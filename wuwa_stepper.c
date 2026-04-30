#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
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
MODULE_DESCRIPTION("GKI Traceiter Multi-Slot Engine (Safe X3 & 6.6 Compile Fix)");

#define MAX_HOOKS 16

// ====== 动态符号解析 ======
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
    if (!addr_reg_step || !addr_unreg_step || !addr_en_step || !addr_dis_step) return -EINVAL;
    if (kstrtoul(addr_reg_step, 0, &reg) || kstrtoul(addr_unreg_step, 0, &unreg) ||
        kstrtoul(addr_en_step, 0, &en) || kstrtoul(addr_dis_step, 0, &dis)) return -EINVAL;
    _register_user_step_hook = (fn_register_user_step_hook)reg;
    _unregister_user_step_hook = (fn_unregister_user_step_hook)unreg;
    _user_enable_single_step = (fn_user_enable_single_step)en;
    _user_disable_single_step = (fn_user_disable_single_step)dis;
    return 0;
}

// ====== 多槽位状态机与安全锁 ======
static struct patch_req active_reqs[MAX_HOOKS];
static atomic_t engine_active = ATOMIC_INIT(0);
static atomic_t in_flight_handlers = ATOMIC_INIT(0);
DEFINE_SEQLOCK(req_seqlock);

// ====== 跨版本强制物理页驻留 (修复 6.5+ 编译错误) ======
static int force_page_resident(struct task_struct *task, unsigned long addr) {
    struct mm_struct *mm = get_task_mm(task);
    struct page *page = NULL;
    int ret = -EFAULT;

    if (!mm) return -ESRCH;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    // 6.5 之后移除了 vmas 参数
    mmap_read_lock(mm);
    ret = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, &page, NULL);
    mmap_read_unlock(mm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
    ret = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, &page, NULL, NULL);
    mmap_read_unlock(mm);
#else
    down_read(&mm->mmap_sem);
    ret = get_user_pages_remote(task, mm, addr, 1, FOLL_FORCE, &page, NULL, NULL);
    up_read(&mm->mmap_sem);
#endif

    if (ret > 0 && page) {
        put_page(page);
        ret = 0;
    } else {
        ret = -EFAULT;
    }
    mmput(mm);
    return ret;
}

// ====== Lockless PTE 原子修改 (修复 CONT 避让) ======
static void toggle_page_uxn_lockless(struct mm_struct *mm, unsigned long addr, bool enable_uxn) {
    pgd_t *pgdp; p4d_t *p4dp; pud_t *pudp; pmd_t *pmdp; pte_t *ptep;
    pmd_t pmd_val; pte_t old_pte, new_pte;
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
        
        if (!pte_present(old_pte)) return; 
        
        // 遇到连续页表项直接跑路，绝不强行 clear_pte_bit 造成系统崩溃
        if (pte_cont(old_pte)) {
            pr_warn("[wuwa] CONT_PTE detected at 0x%lx, safely skipped.\n", addr);
            return; 
        }
        
        if (enable_uxn && (pte_val(old_pte) & PTE_UXN)) return;
        if (!enable_uxn && !(pte_val(old_pte) & PTE_UXN)) return;

        new_pte = enable_uxn ? set_pte_bit(old_pte, __pgprot(PTE_UXN)) : clear_pte_bit(old_pte, __pgprot(PTE_UXN));
    } while (cmpxchg((u64 *)ptep, pte_val(old_pte), pte_val(new_pte)) != pte_val(old_pte));

    // 精准 ASID TLB 刷新
    ttbr0 = read_sysreg(ttbr0_el1);
    asid = (ttbr0 & GENMASK_ULL(63, 48)) >> 48;
    tlbi_val = (asid << 48) | (addr >> 12);
    
    dsb(ishst);
    __asm__ volatile("tlbi vale1is, %0" : : "r" (tlbi_val));
    dsb(ish); isb();
}

// ====== 虚拟动作引擎 ======
static bool apply_virtual_action(struct pt_regs *regs, struct patch_req *req) {
    uint32_t val = 0;
    switch (req->action) {
        case 0: 
            if (req->patch_val == 0xD65F03C0) regs->pc = regs->regs[30];
            else regs->pc += 4;
            return true;
        case 1: 
            regs->pc = regs->regs[30]; 
            return true;
        case 2: 
            regs->pc = req->target_va; 
            return true;
        case 3:
            if (regs->regs[1] == 0) return false;
            pagefault_disable();
            if (__get_user(val, (uint32_t __user *)(regs->regs[1] + 0x1C)) == 0) {
                if (val == 0) { regs->regs[0] = 1; regs->pc = regs->regs[30]; pagefault_enable(); return true; }
            }
            pagefault_enable(); 
            return false;
        case 4: 
            regs->pc += 8;
            return true;
        case 5: 
            regs->regs[0] = 1; regs->pc = regs->regs[30]; 
            return true;
        case 6: 
            current->thread.uw.fpsimd_state.vregs[0] = (u64)req->patch_val;
            regs->pc = regs->regs[30]; 
            return true;
        default: 
            return false;
    }
}

// ====== 核心拦截点：Traceiter 安全识别 ======
static int hook_trace_pre(struct kprobe *p, struct pt_regs *kregs) {
    struct pt_regs *uregs = NULL;
    unsigned int seq;
    int retries = 0, i;
    bool page_matched = false;
    struct patch_req local_reqs[MAX_HOOKS];

    if (atomic_read(&engine_active) == 0) return 0;

    // 直接取 x3，绝不瞎猜，绝不强行解引用 user_mode
    uregs = (struct pt_regs *)kregs->regs[3];
    if (!uregs) return 0;
    if ((unsigned long)uregs < 0xffffff0000000000ULL) return 0;

    atomic_inc(&in_flight_handlers);
    
    // 多槽位快照
    do {
        if (retries++ > 3) goto out_pass;
        seq = read_seqbegin(&req_seqlock);
        memcpy(local_reqs, active_reqs, sizeof(active_reqs));
    } while (read_seqretry(&req_seqlock, seq));

    // 多槽位匹配逻辑
    for (i = 0; i < MAX_HOOKS; i++) {
        if (local_reqs[i].enabled && current->pid == local_reqs[i].pid) {
            unsigned long page_base = local_reqs[i].va & PAGE_MASK;
            if ((uregs->pc & PAGE_MASK) == page_base) {
                page_matched = true;
                if (uregs->pc == local_reqs[i].va) {
                    apply_virtual_action(uregs, &local_reqs[i]);
                    break; 
                }
            }
        }
    }

    if (page_matched) {
        rcu_read_lock();
        toggle_page_uxn_lockless(current->mm, uregs->pc & PAGE_MASK, false);
        _user_enable_single_step(current);
        rcu_read_unlock();
    }

out_pass:
    atomic_dec(&in_flight_handlers);
    return 0; 
}

// 挂载两个被证明可用的侧门
static struct kprobe kp_sp_pc = {
    .symbol_name = "__traceiter_android_rvh_do_sp_pc_abort",
    .pre_handler = hook_trace_pre,
};

static struct kprobe kp_read_fault = {
    .symbol_name = "__traceiter_android_vh_do_read_fault",
    .pre_handler = hook_trace_pre,
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
    int i;
    struct patch_req local_reqs[MAX_HOOKS];

    if (atomic_read(&engine_active) == 0) return DBG_HOOK_ERROR;

    atomic_inc(&in_flight_handlers);

    do {
        if (retries++ > 3) goto out_err;
        seq = read_seqbegin(&req_seqlock);
        memcpy(local_reqs, active_reqs, sizeof(active_reqs));
    } while (read_seqretry(&req_seqlock, seq));

    rcu_read_lock();
    _user_disable_single_step(current); 
    
    // 把该 PID 下所有激活的页全部重新打上 UXN
    for (i = 0; i < MAX_HOOKS; i++) {
        if (local_reqs[i].enabled && current->pid == local_reqs[i].pid) {
            toggle_page_uxn_lockless(current->mm, local_reqs[i].va & PAGE_MASK, true);
        }
    }
    rcu_read_unlock();
    
    atomic_dec(&in_flight_handlers);
    return 0; 

out_err:
    atomic_dec(&in_flight_handlers);
    return DBG_HOOK_ERROR;
}

static struct step_hook my_step_hook = { .fn = wuwa_step_handler };

// ====== 多槽位 IOCTL 通信 ======
static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct patch_req req;
    struct task_struct *task;
    struct mm_struct *mm;
    int i, slot = -1;
    
    if (cmd != WUWA_IOCTL_SET_HOOK) return -ENOTTY;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

    rcu_read_lock();
    task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return -ESRCH;

    write_seqlock(&req_seqlock);
    
    if (req.enabled) {
        for (i = 0; i < MAX_HOOKS; i++) {
            if (active_reqs[i].enabled && active_reqs[i].va == req.va && active_reqs[i].pid == req.pid) {
                slot = i; break;
            }
        }
        if (slot == -1) {
            for (i = 0; i < MAX_HOOKS; i++) {
                if (!active_reqs[i].enabled) { slot = i; break; }
            }
        }
        if (slot != -1) active_reqs[slot] = req;
    } else {
        for (i = 0; i < MAX_HOOKS; i++) {
            if (active_reqs[i].enabled && active_reqs[i].pid == req.pid) {
                if (req.va == 0 || active_reqs[i].va == req.va) {
                    active_reqs[i].enabled = 0;
                }
            }
        }
    }
    write_sequnlock(&req_seqlock);

    if (req.enabled && slot != -1) {
        if (force_page_resident(task, req.va & PAGE_MASK) == 0) {
            mm = get_task_mm(task);
            if (mm) {
                toggle_page_uxn_lockless(mm, req.va & PAGE_MASK, true);
                mmput(mm);
            }
            pr_info("[wuwa] Hook Set [Slot %d] -> VA: 0x%llx\n", slot, req.va);
        }
    }

    put_task_struct(task);
    
    for (i = 0; i < MAX_HOOKS; i++) {
        if (active_reqs[i].enabled) {
            atomic_set(&engine_active, 1);
            return 0;
        }
    }
    atomic_set(&engine_active, 0); 
    
    return 0;
}

static const struct file_operations wuwa_fops = { 
    .owner=THIS_MODULE, .unlocked_ioctl=wuwa_ioctl, .compat_ioctl=wuwa_ioctl 
};
static struct miscdevice wuwa_misc_device = { 
    .minor=MISC_DYNAMIC_MINOR, .name="wuwa_stepper", .fops=&wuwa_fops 
};

// ====== 初始化与卸载 ======
static int __init wuwa_init(void) {
    int kp_count = 0;
    if (resolve_all_symbols() < 0) return -EINVAL;
    if (misc_register(&wuwa_misc_device) < 0) return -1;
    
    _register_user_step_hook(&my_step_hook);
    
    if (register_kprobe(&kp_sp_pc) == 0) kp_count++;
    if (register_kprobe(&kp_read_fault) == 0) kp_count++;

    if (kp_count == 0) {
        pr_err("[wuwa] All Kprobes failed!\n");
        _unregister_user_step_hook(&my_step_hook);
        misc_deregister(&wuwa_misc_device);
        return -1;
    }
    
    pr_info("[wuwa] Engine Loaded. Hooks: %d\n", kp_count);
    return 0;
}

static void __exit wuwa_exit(void) {
    int timeout = 50;
    atomic_set(&engine_active, 0);
    smp_mb();
    
    if (kp_sp_pc.nmissed >= 0) unregister_kprobe(&kp_sp_pc);
    if (kp_read_fault.nmissed >= 0) unregister_kprobe(&kp_read_fault);
    
    _unregister_user_step_hook(&my_step_hook);

    while (atomic_read(&in_flight_handlers) > 0 && timeout-- > 0) {
        cpu_relax(); msleep(10);
    }
    misc_deregister(&wuwa_misc_device);
    pr_info("[wuwa] Engine Unloaded.\n");
}

module_init(wuwa_init);
module_exit(wuwa_exit);
