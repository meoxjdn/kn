#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/barrier.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <asm/debug-monitors.h>
#include "wuwa_ctrl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DaNiu");
MODULE_DESCRIPTION("GKI 6.6 Ultimate Stealth Engine (Final Pragmatic Edition)");

// ====== 动态符号偷取 ======
typedef void (*fn_register_user_step_hook)(struct step_hook *hook);
typedef void (*fn_unregister_user_step_hook)(struct step_hook *hook);
typedef void (*fn_user_enable_single_step)(struct task_struct *task);
typedef void (*fn_user_disable_single_step)(struct task_struct *task);

static fn_register_user_step_hook _register_user_step_hook;
static fn_unregister_user_step_hook _unregister_user_step_hook;
static fn_user_enable_single_step _user_enable_single_step;
static fn_user_disable_single_step _user_disable_single_step;

static void *find_hidden_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    void *addr;
    if (register_kprobe(&kp) < 0) return NULL;
    addr = (void *)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static int resolve_all_symbols(void) {
    _register_user_step_hook = (fn_register_user_step_hook)find_hidden_symbol("register_user_step_hook");
    _unregister_user_step_hook = (fn_unregister_user_step_hook)find_hidden_symbol("unregister_user_step_hook");
    _user_enable_single_step = (fn_user_enable_single_step)find_hidden_symbol("user_enable_single_step");
    _user_disable_single_step = (fn_user_disable_single_step)find_hidden_symbol("user_disable_single_step");

    if (!_register_user_step_hook || !_user_enable_single_step || !_user_disable_single_step || !_unregister_user_step_hook) {
        return -ENOENT;
    }
    return 0;
}

// ====== 高并发状态机与安全信标 ======
static struct patch_req active_req = {0};
static atomic_t engine_active = ATOMIC_INIT(0);
static atomic_t in_flight_handlers = ATOMIC_INIT(0); // 绝对退场信标
DEFINE_SEQLOCK(req_seqlock); 

// ====== Lockless PTE 原子修改 (带安全断路器) ======
static void toggle_page_uxn_lockless(struct mm_struct *mm, unsigned long addr, bool enable_uxn) {
    pgd_t *pgdp; p4d_t *p4dp; pud_t *pudp; pmd_t *pmdp; pte_t *ptep;
    pmd_t pmd_val;
    pte_t old_pte, new_pte;
    unsigned long ttbr0, asid, tlbi_val;

    if (!mm) return;

    pgdp = pgd_offset(mm, addr);
    if (pgd_none(READ_ONCE(*pgdp)) || pgd_bad(READ_ONCE(*pgdp))) return;

    p4dp = p4d_offset(pgdp, addr);
    if (p4d_none(READ_ONCE(*p4dp)) || p4d_bad(READ_ONCE(*p4dp))) return;

    pudp = pud_offset(p4dp, addr);
    if (pud_none(READ_ONCE(*pudp)) || pud_bad(READ_ONCE(*pudp))) return;

    pmdp = pmd_offset(pudp, addr);
    pmd_val = READ_ONCE(*pmdp);
    
    // 拒绝操作 Huge PMD 或 Bad PMD
    if (pmd_none(pmd_val) || pmd_bad(pmd_val) || pmd_trans_huge(pmd_val)) return;

    ptep = (pte_t *)(pmd_page_vaddr(pmd_val)) + pte_index(addr);

    // 原子 CMPXCHG 循环更新 PTE
    do {
        old_pte = READ_ONCE(*ptep);
        
        // 【最终保命防线】：如果页不存在，或者它是连续页表项(CONT)，直接放弃！绝不制造未定义行为。
        if (!pte_present(old_pte) || pte_cont(old_pte)) return; 

        if (enable_uxn) {
            new_pte = set_pte_bit(old_pte, __pgprot(PTE_UXN));
        } else {
            new_pte = clear_pte_bit(old_pte, __pgprot(PTE_UXN));
        }

    } while (cmpxchg((u64 *)ptep, pte_val(old_pte), pte_val(new_pte)) != pte_val(old_pte));

    // 精准汇编 TLBI
    ttbr0 = read_sysreg(ttbr0_el1);
    asid = (ttbr0 & GENMASK_ULL(63, 48)) >> 48;
    tlbi_val = (asid << 48) | (addr >> 12);
    
    dsb(ishst);
    __asm__ volatile("tlbi vale1is, %0" : : "r" (tlbi_val));
    dsb(ish);
    isb();
}

// ====== 寄存器虚拟动作 ======
static bool apply_virtual_action(struct pt_regs *regs, struct patch_req *req) {
    uint32_t val = 0;
    switch (req->action) {
        case 1: 
            regs->pc = regs->regs[30]; return true;
        case 2: 
            regs->pc = req->target_va; return true;
        case 3:
            pagefault_disable();
            if (__get_user(val, (uint32_t __user *)(regs->regs[1] + 0x1C)) == 0) {
                if (val == 0) {
                    regs->regs[0] = 1; 
                    regs->pc = regs->regs[30]; 
                    pagefault_enable(); return true;
                }
            }
            pagefault_enable(); return false;
        case 5: 
            regs->regs[0] = 1; regs->pc = regs->regs[30]; return true;
        case 6: 
            // 妥协为最稳妥的方式：修改内核保存的结构体，随上下文切换自然恢复，杜绝污染
            current->thread.uw.fpsimd_state.vregs[0] = (u64)req->patch_val;
            regs->pc = regs->regs[30]; 
            return true;
        default: 
            return false;
    }
}

// ====== 异常接管钩子 (Kprobe) ======
static int hook_do_mem_abort_pre(struct kprobe *p, struct pt_regs *regs) {
    unsigned long addr = regs->regs[0];
    unsigned long esr = regs->regs[1];
    struct pt_regs *uregs = (struct pt_regs *)regs->regs[2];
    unsigned int ec = esr >> 26;
    unsigned int seq;
    int retries = 0;
    struct patch_req local_req;

    if (atomic_read(&engine_active) == 0 || ec != 0x20) return 0;

    atomic_inc(&in_flight_handlers);

    do {
        if (retries++ > 3) goto out_pass;
        seq = read_seqbegin(&req_seqlock);
        local_req = active_req;
    } while (read_seqretry(&req_seqlock, seq));

    if (current->pid == local_req.pid) {
        unsigned long page_base = local_req.va & PAGE_MASK;
        
        if ((addr & PAGE_MASK) == page_base) {
            if (uregs->pc == local_req.va) {
                if (apply_virtual_action(uregs, &local_req)) {
                    regs->pc = regs->regs[30]; 
                    atomic_dec(&in_flight_handlers);
                    return 1; 
                }
            }
            
            rcu_read_lock();
            toggle_page_uxn_lockless(current->mm, page_base, false);
            _user_enable_single_step(current);
            rcu_read_unlock();
            
            regs->pc = regs->regs[30]; 
            atomic_dec(&in_flight_handlers);
            return 1; 
        }
    }

out_pass:
    atomic_dec(&in_flight_handlers);
    return 0;
}

static struct kprobe mem_abort_kp = {
    .symbol_name = "do_mem_abort",
    .pre_handler = hook_do_mem_abort_pre,
};

// ====== 硬件单步回调 ======
static int wuwa_step_handler(struct pt_regs *regs, unsigned long esr) {
    unsigned int seq;
    int retries = 0;
    struct patch_req local_req;

    if (atomic_read(&engine_active) == 0) return DBG_HOOK_ERROR;
    
    atomic_inc(&in_flight_handlers);

    do {
        if (retries++ > 3) goto out_err;
        seq = read_seqbegin(&req_seqlock);
        local_req = active_req;
    } while (read_seqretry(&req_seqlock, seq));

    if (current->pid == local_req.pid) {
        unsigned long page_base = local_req.va & PAGE_MASK;
        
        rcu_read_lock();
        _user_disable_single_step(current); 
        toggle_page_uxn_lockless(current->mm, page_base, true);
        rcu_read_unlock();
        
        atomic_dec(&in_flight_handlers);
        return 0; 
    }

out_err:
    atomic_dec(&in_flight_handlers);
    return DBG_HOOK_ERROR;
}

static struct step_hook my_step_hook = {
    .fn = wuwa_step_handler
};

// ====== 安全通信入口 ======
static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct patch_req req;
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;

    if (cmd == WUWA_IOCTL_SET_HOOK) {
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

        if (req.enabled == 0) {
            atomic_set(&engine_active, 0); 
            smp_mb();

            rcu_read_lock();
            task = pid_task(find_vpid(active_req.pid), PIDTYPE_PID);
            if (task) get_task_struct(task);
            rcu_read_unlock();

            if (task) {
                mm = get_task_mm(task);
                if (mm) {
                    rcu_read_lock();
                    toggle_page_uxn_lockless(mm, active_req.va & PAGE_MASK, false);
                    rcu_read_unlock();
                    mmput(mm);
                }
                put_task_struct(task);
            }
            pr_info("[wuwa] 引擎已休眠，清理完成。\n");
            return 0;
        }

        rcu_read_lock();
        task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
        if (task) get_task_struct(task);
        rcu_read_unlock();

        if (!task) return -ESRCH;

        mm = get_task_mm(task);
        put_task_struct(task); 

        if (!mm) return -ESRCH;

        write_seqlock(&req_seqlock);
        active_req = req;
        write_sequnlock(&req_seqlock);

        rcu_read_lock();
        toggle_page_uxn_lockless(mm, active_req.va & PAGE_MASK, true);
        rcu_read_unlock();
        atomic_set(&engine_active, 1);
        
        mmput(mm); 

        pr_info("[wuwa] 引擎激活，极客实用保护已开启！目标 PC: 0x%llx\n", active_req.va);
        return 0;
    }
    return -ENOTTY;
}

static const struct file_operations wuwa_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = wuwa_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = wuwa_ioctl,
#endif
};

static struct miscdevice wuwa_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "wuwa_stepper",
    .fops = &wuwa_fops,
};

// ====== 模块生命周期 ======
static int __init wuwa_engine_init(void) {
    int err;
    if (resolve_all_symbols() < 0) {
        pr_err("[wuwa] 符号解析失败。\n");
        return -ENOSYS;
    }
    if ((err = misc_register(&wuwa_misc_device))) return err;
    _register_user_step_hook(&my_step_hook);
    if ((err = register_kprobe(&mem_abort_kp)) < 0) {
        _unregister_user_step_hook(&my_step_hook);
        misc_deregister(&wuwa_misc_device);
        return err;
    }
    pr_info("[wuwa] GKI 6.6 终极形态引擎加载成功！\n");
    return 0;
}

static void __exit wuwa_engine_exit(void) {
    int timeout = 50; // 最大等待 500ms，防卸载死锁

    // 1. 关闭总闸
    atomic_set(&engine_active, 0);
    smp_mb();

    // 2. 切断源头：优先注销入口，防止新的异常进入
    unregister_kprobe(&mem_abort_kp);
    _unregister_user_step_hook(&my_step_hook);

    // 3. 安全退场：带超时的等待机制
    while (atomic_read(&in_flight_handlers) > 0 && timeout-- > 0) {
        cpu_relax();
        msleep(10);
    }

    if (atomic_read(&in_flight_handlers) > 0) {
        pr_warn("[wuwa] 警告: 卸载超时，仍有回调未退出，强制卸载可能引发异常！\n");
    }

    // 4. 清理设备
    misc_deregister(&wuwa_misc_device);
    
    pr_info("[wuwa] 引擎已卸载。\n");
}

module_init(wuwa_engine_init);
module_exit(wuwa_engine_exit);
