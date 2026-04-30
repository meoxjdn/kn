#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <asm/debug-monitors.h>
#include "wuwa_ctrl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DaNiu");
MODULE_DESCRIPTION("GKI 6.6 Stealth Symbol Hijack Engine");

// ====== 动态符号表（函数指针化） ======
typedef void (*fn_register_user_step_hook)(struct step_hook *hook);
typedef void (*fn_unregister_user_step_hook)(struct step_hook *hook);
typedef void (*fn_user_enable_single_step)(struct task_struct *task);
typedef void (*fn_user_disable_single_step)(struct task_struct *task);

static fn_register_user_step_hook _register_user_step_hook;
static fn_unregister_user_step_hook _unregister_user_step_hook;
static fn_user_enable_single_step _user_enable_single_step;
static fn_user_disable_single_step _user_disable_single_step;

// ====== 强制符号解析逻辑 (Kprobe盗取法) ======
static void *find_hidden_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    void *addr;
    if (register_kprobe(&kp) < 0) {
        pr_err("[wuwa] 无法找回隐藏符号: %s\n", name);
        return NULL;
    }
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

// ====== 引擎全局配置 ======
static struct patch_req active_req = {0};
static bool engine_active = false;

// ====== 底层 PTE 操控 ======
static void toggle_page_uxn(struct mm_struct *mm, unsigned long addr, bool enable_uxn) {
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *ptep, pte;
    
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return;
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return;
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) return;
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return;
    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep) return;

    pte = *ptep;
    if (enable_uxn) {
        pte = set_pte_bit(pte, __pgprot(PTE_UXN));
    } else {
        pte = clear_pte_bit(pte, __pgprot(PTE_UXN));
    }
    
    // 使用 set_pte 规避 __mmu_notifier 导出问题
    set_pte(ptep, pte);
    flush_tlb_mm(mm);
}

// ====== 虚拟动作执行器 ======
static bool apply_virtual_action(struct pt_regs *regs, struct patch_req *req) {
    uint32_t val = 0;

    switch (req->action) {
        case 1: /* Virtual RET Only */
            regs->pc = regs->regs[30]; 
            return true;

        case 2: /* Virtual JUMP B */
            regs->pc = req->target_va;
            return true;

        case 3: /* Virtual God Mode */
            pagefault_disable();
            if (__get_user(val, (uint32_t __user *)(regs->regs[1] + 0x1C)) == 0) {
                if (val == 0) { // 判断为玩家
                    regs->regs[0] = 1;         // 修改伤害
                    regs->pc = regs->regs[30]; // RET
                    pagefault_enable();
                    return true;
                }
            }
            pagefault_enable();
            return false;

        case 5: /* Safe HP Stub */
            regs->regs[0] = 1;
            regs->pc = regs->regs[30];
            return true;

        case 6: /* Float Ret */
            current->thread.uw.fpsimd_state.vregs[0] = (u64)req->patch_val;
            regs->pc = regs->regs[30];
            return true;

        default:
            return false;
    }
}

// ====== Kprobe 接管 do_mem_abort ======
static int hook_do_mem_abort_pre(struct kprobe *p, struct pt_regs *regs) {
    unsigned long addr = regs->regs[0];
    unsigned long esr = regs->regs[1];
    struct pt_regs *uregs = (struct pt_regs *)regs->regs[2];
    unsigned int ec = esr >> 26;

    if (engine_active && current->pid == active_req.pid && ec == 0x20) {
        unsigned long page_base = active_req.va & PAGE_MASK;
        
        if ((addr & PAGE_MASK) == page_base) {
            if (uregs->pc == active_req.va) {
                if (apply_virtual_action(uregs, &active_req)) {
                    regs->pc = regs->regs[30]; 
                    return 1; // Bypass 原始 do_mem_abort
                }
            }

            toggle_page_uxn(current->mm, page_base, false);
            _user_enable_single_step(current); // 动态指针调用
            
            regs->pc = regs->regs[30]; 
            return 1; // Bypass 原始 do_mem_abort
        }
    }
    return 0; // 不是目标异常，放行
}

static struct kprobe mem_abort_kp = {
    .symbol_name = "do_mem_abort",
    .pre_handler = hook_do_mem_abort_pre,
};

// ====== 单步回收机制 ======
static int wuwa_step_handler(struct pt_regs *regs, unsigned long esr) {
    if (engine_active && current->pid == active_req.pid) {
        unsigned long page_base = active_req.va & PAGE_MASK;
        
        _user_disable_single_step(current); // 动态指针调用
        toggle_page_uxn(current->mm, page_base, true);
        
        return 0; // 成功消化异常
    }
    return DBG_HOOK_ERROR;
}

static struct step_hook my_step_hook = {
    .fn = wuwa_step_handler
};

// ====== 用户态 IOCTL 接口 ======
static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct patch_req req;
    struct task_struct *task;

    if (cmd == WUWA_IOCTL_SET_HOOK) {
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

        if (req.enabled == 0) {
            engine_active = false;
            task = pid_task(find_vpid(active_req.pid), PIDTYPE_PID);
            if (task && task->mm) {
                toggle_page_uxn(task->mm, active_req.va & PAGE_MASK, false);
            }
            pr_info("[wuwa] 引擎已休眠，清理收尾完成。\n");
            return 0;
        }

        task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
        if (!task || !task->mm) return -ESRCH;

        active_req = req;
        engine_active = true;

        toggle_page_uxn(task->mm, active_req.va & PAGE_MASK, true);
        pr_info("[wuwa] 引擎激活！精准截击设定完毕: 0x%llx\n", active_req.va);
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
    
    // 1. 偷取隐藏的内核符号
    if (resolve_all_symbols() < 0) {
        pr_err("[wuwa] 核心符号解析失败，无法在 GKI 环境下运行！\n");
        return -ENOSYS;
    }

    // 2. 注册设备节点
    if ((err = misc_register(&wuwa_misc_device))) return err;

    // 3. 注册单步回调
    _register_user_step_hook(&my_step_hook);

    // 4. 劫持异常分发
    if ((err = register_kprobe(&mem_abort_kp)) < 0) {
        pr_err("[wuwa] Kprobe 注册失败: %d\n", err);
        _unregister_user_step_hook(&my_step_hook);
        misc_deregister(&wuwa_misc_device);
        return err;
    }

    pr_info("[wuwa] 幽灵引擎 (GKI 符号盗取版) 初始化成功！\n");
    return 0;
}

static void __exit wuwa_engine_exit(void) {
    engine_active = false;
    unregister_kprobe(&mem_abort_kp);
    _unregister_user_step_hook(&my_step_hook);
    misc_deregister(&wuwa_misc_device);
    pr_info("[wuwa] 幽灵引擎已卸载。\n");
}

module_init(wuwa_engine_init);
module_exit(wuwa_engine_exit);
