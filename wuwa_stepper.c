#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/kprobes.h>        // 核心改动：抛弃 Ftrace，改用 Kprobes
#include <linux/miscdevice.h>
#include <asm/debug-monitors.h>   // 包含 register_user_step_hook

#include "wuwa_ctrl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DaNiu");
MODULE_DESCRIPTION("Universal UXN + Single Step Stealth Hook Engine (GKI 6.6 Edition)");

static struct patch_req active_req = {0};
static bool engine_active = false;

// ==========================================
// 1. 底层工具：操控物理页的 UXN 权限
// ==========================================
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
    set_pte(ptep, pte);
    flush_tlb_mm(mm);
}

// ==========================================
// 2. 虚拟动作执行器 (寄存器魔法)
// ==========================================
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
                if (val == 0) {
                    regs->regs[0] = 1;
                    regs->pc = regs->regs[30];
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

        case 6: /* Float Ret (修复 6.6 不导出 fpsimd_save 的问题) */
            // 异常上下文中，用户态寄存器已由硬件/底层汇编妥善托管。
            // 只要修改当前线程绑定的 state 结构体，返回用户态时内核会自动按此恢复。
            current->thread.uw.fpsimd_state.vregs[0] = (u64)req->patch_val;
            regs->pc = regs->regs[30];
            return true;

        default:
            return false;
    }
}

// ==========================================
// 3. 核心大招：Kprobes 接管 do_mem_abort 并 Bypass
// ==========================================
static int hook_do_mem_abort_pre(struct kprobe *p, struct pt_regs *regs) {
    // ARM64 do_mem_abort(addr, esr, uregs) 对应寄存器 x0, x1, x2
    unsigned long addr = regs->regs[0];
    unsigned long esr = regs->regs[1];
    struct pt_regs *uregs = (struct pt_regs *)regs->regs[2];

    unsigned int ec = esr >> 26;

    if (engine_active && current->pid == active_req.pid && ec == 0x20) {
        unsigned long page_base = active_req.va & PAGE_MASK;
        
        if ((addr & PAGE_MASK) == page_base) {
            
            // 踩中精准 Hook 点，执行 Action
            if (uregs->pc == active_req.va) {
                if (apply_virtual_action(uregs, &active_req)) {
                    // Action 成功，需要吃掉这个异常。
                    // 魔法：修改 PC 指向 LR（返回地址），返回 1 通知 Kprobe 取消原函数单步！
                    regs->pc = regs->regs[30]; 
                    return 1; 
                }
            }

            // 未踩中，开启硬件单步
            toggle_page_uxn(current->mm, page_base, false);
            user_enable_single_step(current);
            
            // 同样需要吃掉异常，防止原版 do_mem_abort 杀掉游戏进程
            regs->pc = regs->regs[30];
            return 1; 
        }
    }
    
    // 如果不是我们的目标进程或异常类型，返回 0 乖乖让 Kprobe 放行原函数
    return 0; 
}

static struct kprobe mem_abort_kp = {
    .symbol_name = "do_mem_abort",
    .pre_handler = hook_do_mem_abort_pre,
};

// ==========================================
// 4. 单步回收：适配 Android 15 新版 API
// 注意修复了 esr 参数类型为 unsigned long
// ==========================================
static int wuwa_step_handler(struct pt_regs *regs, unsigned long esr) {
    if (engine_active && current->pid == active_req.pid) {
        unsigned long page_base = active_req.va & PAGE_MASK;
        
        user_disable_single_step(current);
        toggle_page_uxn(current->mm, page_base, true);
        
        return 0; // DBG_HOOK_HANDLED
    }
    return DBG_HOOK_ERROR;
}

static struct step_hook my_step_hook = {
    .fn = wuwa_step_handler
};

// ==========================================
// 控制接口与注册
// ==========================================
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

static int __init wuwa_engine_init(void) {
    int err;
    
    if ((err = misc_register(&wuwa_misc_device))) return err;

    // 核心修复：使用 register_user_step_hook
    register_user_step_hook(&my_step_hook);

    // 核心修复：注册 Kprobe
    if ((err = register_kprobe(&mem_abort_kp)) < 0) {
        pr_err("[wuwa] Kprobe 注册失败: %d\n", err);
        unregister_user_step_hook(&my_step_hook);
        misc_deregister(&wuwa_misc_device);
        return err;
    }

    pr_info("[wuwa_stepper] 终极无痕硬件劫持引擎初始化成功 (Android 15 Kprobe 版)！\n");
    return 0;
}

static void __exit wuwa_engine_exit(void) {
    engine_active = false;
    
    // 清理资源
    unregister_kprobe(&mem_abort_kp);
    unregister_user_step_hook(&my_step_hook);
    misc_deregister(&wuwa_misc_device);
    
    pr_info("[wuwa_stepper] 引擎已彻底卸载。\n");
}

module_init(wuwa_engine_init);
module_exit(wuwa_engine_exit);
