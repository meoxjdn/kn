#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
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
#include <asm/ptrace.h> 
#include "wuwa_ctrl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DaNiu");
MODULE_DESCRIPTION("GKI 6.6 Adaptive Arch-Fault Stealth Engine");

// ====== 动态符号表 (外部参数注入) ======
typedef void (*fn_register_user_step_hook)(struct step_hook *hook);
typedef void (*fn_unregister_user_step_hook)(struct step_hook *hook);
typedef void (*fn_user_enable_single_step)(struct task_struct *task);
typedef void (*fn_user_disable_single_step)(struct task_struct *task);

static fn_register_user_step_hook _register_user_step_hook;
static fn_unregister_user_step_hook _unregister_user_step_hook;
static fn_user_enable_single_step _user_enable_single_step;
static fn_user_disable_single_step _user_disable_single_step;

static char *addr_reg_step = NULL;
static char *addr_unreg_step = NULL;
static char *addr_en_step = NULL;
static char *addr_dis_step = NULL;

module_param(addr_reg_step, charp, 0444);
module_param(addr_unreg_step, charp, 0444);
module_param(addr_en_step, charp, 0444);
module_param(addr_dis_step, charp, 0444);

static int resolve_all_symbols(void) {
    unsigned long reg = 0, unreg = 0, en = 0, dis = 0;

    if (!addr_reg_step || !addr_unreg_step || !addr_en_step || !addr_dis_step) {
        pr_err("[wuwa] 缺少外部传入的符号地址字符串！\n");
        return -EINVAL;
    }

    if (kstrtoul(addr_reg_step, 0, &reg) ||
        kstrtoul(addr_unreg_step, 0, &unreg) ||
        kstrtoul(addr_en_step, 0, &en) ||
        kstrtoul(addr_dis_step, 0, &dis)) {
        pr_err("[wuwa] 符号地址字符串解析失败！\n");
        return -EINVAL;
    }

    _register_user_step_hook = (fn_register_user_step_hook)reg;
    _unregister_user_step_hook = (fn_unregister_user_step_hook)unreg;
    _user_enable_single_step = (fn_user_enable_single_step)en;
    _user_disable_single_step = (fn_user_disable_single_step)dis;

    return 0;
}

// ====== 高并发状态机与安全信标 ======
static struct patch_req active_req = {0};
static atomic_t engine_active = ATOMIC_INIT(0);
static atomic_t in_flight_handlers = ATOMIC_INIT(0);
DEFINE_SEQLOCK(req_seqlock); 

// ====== Lockless PTE 原子修改 ======
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
    
    if (pmd_none(pmd_val) || pmd_bad(pmd_val) || pmd_trans_huge(pmd_val)) return;

    ptep = (pte_t *)(pmd_page_vaddr(pmd_val)) + pte_index(addr);

    do {
        old_pte = READ_ONCE(*ptep);
        if (!pte_present(old_pte) || pte_cont(old_pte)) return; 

        if (enable_uxn) {
            new_pte = set_pte_bit(old_pte, __pgprot(PTE_UXN));
        } else {
            new_pte = clear_pte_bit(old_pte, __pgprot(PTE_UXN));
        }

    } while (cmpxchg((u64 *)ptep, pte_val(old_pte), pte_val(new_pte)) != pte_val(old_pte));

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
            current->thread.uw.fpsimd_state.vregs[0] = (u64)req->patch_val;
            regs->pc = regs->regs[30]; 
            return true;
        default: 
            return false;
    }
}

// ====== 核心魔法：自适应 Arch-Fault 拦截 ======
static int current_hook_type = 0; // 0: do_page_fault类, 1: handle_mm_fault类

static int hook_fault_pre(struct kprobe *p, struct pt_regs *kregs) {
    unsigned long addr;
    unsigned int esr;
    struct pt_regs *uregs;
    unsigned int ec;
    unsigned int seq;
    int retries = 0;
    struct patch_req local_req;

    // 自适应参数解析 (完美兼容不同函数的入参)
    if (current_hook_type == 0) {
        // do_page_fault(unsigned long far, unsigned int esr, struct pt_regs *regs)
        addr = kregs->regs[0];
        esr = kregs->regs[1];
        uregs = (struct pt_regs *)kregs->regs[2];
        ec = esr >> 26;
    } else {
        // handle_mm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags, struct pt_regs *regs)
        addr = kregs->regs[1];
        esr = 0; 
        uregs = (struct pt_regs *)kregs->regs[3];
        ec = 0x20; // 强行假定为指令异常，靠地址比对来拦截
    }

    if (!uregs || !user_mode(uregs)) return 0;
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
                    // 核心拦截：向 caller 伪造 0 (成功) 并直接跳转回 LR 返回！
                    kregs->regs[0] = 0; 
                    kregs->pc = kregs->regs[30];
                    atomic_dec(&in_flight_handlers);
                    return 1; // 跳过原函数执行
                }
            }
            
            rcu_read_lock();
            toggle_page_uxn_lockless(current->mm, page_base, false);
            _user_enable_single_step(current);
            rcu_read_unlock();
            
            // 同样拦截原始逻辑，放行 CPU 执行指令
            kregs->regs[0] = 0;
            kregs->pc = kregs->regs[30];
            atomic_dec(&in_flight_handlers);
            return 1; 
        }
    }

out_pass:
    atomic_dec(&in_flight_handlers);
    return 0;
}

static struct kprobe adaptive_fault_kp = {
    .pre_handler = hook_fault_pre,
};

// ====== 硬件单步回调 ======
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
static int wuwa_step_handler(struct pt_regs *regs, unsigned int esr)
#else
static int wuwa_step_handler(struct pt_regs *regs, unsigned long esr)
#endif
{
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

        pr_info("[wuwa] 引擎激活，目标 PC: 0x%llx\n", active_req.va);
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
    int err = -EINVAL;
    int i;
    // 按优先级尝试 Hook，绝不在一棵树上吊死
    const char *targets[] = {
        "do_page_fault", 
        "do_translation_fault", 
        "handle_mm_fault", 
        NULL
    };

    if (resolve_all_symbols() < 0) {
        return -EINVAL;
    }
    if ((err = misc_register(&wuwa_misc_device))) return err;
    
    _register_user_step_hook(&my_step_hook);
    
    // 自适应 Kprobe 挂载
    for (i = 0; targets[i] != NULL; i++) {
        adaptive_fault_kp.symbol_name = targets[i];
        err = register_kprobe(&adaptive_fault_kp);
        if (err == 0) {
            if (strcmp(targets[i], "handle_mm_fault") == 0) {
                current_hook_type = 1;
            }
            pr_info("[wuwa] 成功挂钩到目标函数: %s\n", targets[i]);
            break;
        }
    }

    if (err < 0) {
        pr_err("[wuwa] 所有的 Fault Kprobe 尝试均被内核拒绝！err=%d\n", err);
        _unregister_user_step_hook(&my_step_hook);
        misc_deregister(&wuwa_misc_device);
        return err;
    }

    pr_info("[wuwa] GKI 6.6 自适应形态引擎加载成功！\n");
    return 0;
}

static void __exit wuwa_engine_exit(void) {
    int timeout = 50;

    atomic_set(&engine_active, 0);
    smp_mb();

    unregister_kprobe(&adaptive_fault_kp);
    _unregister_user_step_hook(&my_step_hook);

    while (atomic_read(&in_flight_handlers) > 0 && timeout-- > 0) {
        cpu_relax();
        msleep(10);
    }

    misc_deregister(&wuwa_misc_device);
    pr_info("[wuwa] 引擎已安全卸载。\n");
}

module_init(wuwa_engine_init);
module_exit(wuwa_engine_exit);
