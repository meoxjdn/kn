#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/ftrace.h>
#include <linux/miscdevice.h>
#include <asm/debug-monitors.h>
#include <asm/fpsimd.h> // 用于 Action 6 的浮点刷新

#include "wuwa_ctrl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DaNiu");
MODULE_DESCRIPTION("Universal UXN + Single Step Stealth Hook Engine");

// 引擎全局配置 (支持单点劫持演示)
static struct patch_req active_req = {0};
static bool engine_active = false;

// ==========================================
// 底层工具：操控物理页的 UXN 权限
// ==========================================
static void toggle_page_uxn(struct mm_struct *mm, unsigned long addr, bool enable_uxn) {
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *ptep, pte;

    // 无锁页表遍历 (要求在当前进程上下文中，或者确保 mm 未被销毁)
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
    
    // 强制刷新 TLB 保证立即生效
    flush_tlb_mm(mm);
}

// ==========================================
// 业务逻辑核心：无痕操作寄存器上下文
// 返回 true 表示成功修改了流向，不需要执行原指令；返回 false 表示需放行原指令
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
            // 安全读取目标进程内存 (必须关缺页异常，防止在中断上下文中睡眠)
            pagefault_disable();
            if (__get_user(val, (uint32_t __user *)(regs->regs[1] + 0x1C)) == 0) {
                if (val == 0) { // 发现是玩家 (TeamID == 0)
                    regs->regs[0] = 1;         // 伤害锁为 1
                    regs->pc = regs->regs[30]; // 强行返回
                    pagefault_enable();
                    return true;
                }
            }
            pagefault_enable();
            return false; // 非玩家，或者读取失败，返回 false 放行原指令

        case 5: /* Safe HP Stub */
            regs->regs[0] = 1;
            regs->pc = regs->regs[30];
            return true;

        case 6: /* Float Ret */
            // 写入浮点寄存器并强刷上下文
            fpsimd_save(); 
            current->thread.uw.fpsimd_state.vregs[0] = (u64)req->patch_val;
            fpsimd_flush_task_state(current); 
            regs->pc = regs->regs[30];
            return true;

        default:
            return false;
    }
}

// ==========================================
// 异常接管钩子：do_mem_abort (拦截 UXN)
// ==========================================
typedef int (*do_mem_abort_t)(unsigned long addr, unsigned int esr, struct pt_regs *regs);
static do_mem_abort_t orig_do_mem_abort;

static int notrace hook_do_mem_abort(unsigned long addr, unsigned int esr, struct pt_regs *regs) {
    unsigned int ec = esr >> 26;

    // 识别目标进程的 Instruction Abort (EL0)
    if (engine_active && current->pid == active_req.pid && ec == 0x20) {
        unsigned long page_base = active_req.va & PAGE_MASK;
        
        if ((addr & PAGE_MASK) == page_base) {
            // 1. 精准踩中 Hook 点！
            if (regs->pc == active_req.va) {
                if (apply_virtual_action(regs, &active_req)) {
                    // Action 成功接管控制流，吃掉异常，直接按照新 PC 飞走
                    return 0; 
                }
            }

            // 2. 未踩中，或 Action(如GodMode判断为怪物)要求放行执行原始逻辑
            // 开启硬件单步死循环
            toggle_page_uxn(current->mm, page_base, false); // 开门
            user_enable_single_step(current);               // 挂绳子
            return 0; // ERET: CPU 将原生执行那一条原始指令
        }
    }
    return orig_do_mem_abort(addr, esr, regs);
}

// Ftrace 注册脚手架
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

static int resolve_hook_address(struct ftrace_hook *hook) {
    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) return -ENOENT;
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
    return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                 struct ftrace_ops *ops, struct ftrace_regs *fregs) {
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (regs) regs->pc = (unsigned long)hook->function;
}

static struct ftrace_hook mem_abort_hook = {
    .name = "do_mem_abort",
    .function = hook_do_mem_abort,
    .original = &orig_do_mem_abort,
};

// ==========================================
// 硬件单步回调钩子：回收权限
// ==========================================
static int wuwa_step_handler(struct pt_regs *regs, unsigned int esr) {
    if (engine_active && current->pid == active_req.pid) {
        unsigned long page_base = active_req.va & PAGE_MASK;
        
        // 执行完一条指令了，立刻关门
        user_disable_single_step(current);            // 解开绳子
        toggle_page_uxn(current->mm, page_base, true); // 锁门，重新打上 UXN
        
        return 0; // 成功消化单步异常，游戏将继续跑，马上又会触发 UXN
    }
    return DBG_HOOK_ERROR;
}

static struct step_hook my_step_hook = {
    .fn = wuwa_step_handler
};

// ==========================================
// 控制接口与设备注册
// ==========================================
static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct patch_req req;
    struct task_struct *task;

    if (cmd == WUWA_IOCTL_SET_HOOK) {
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

        if (req.enabled == 0) {
            engine_active = false;
            // 清理遗留的 UXN
            task = pid_task(find_vpid(active_req.pid), PIDTYPE_PID);
            if (task && task->mm) {
                toggle_page_uxn(task->mm, active_req.va & PAGE_MASK, false);
            }
            pr_info("[wuwa] 引擎已休眠，清理收尾完成。\n");
            return 0;
        }

        task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
        if (!task || !task->mm) return -ESRCH;

        // 保存全局状态
        active_req = req;
        engine_active = true;

        // 首次激活：给目标页挂上 UXN
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

// ==========================================
// 模块出入口
// ==========================================
static int __init wuwa_engine_init(void) {
    int err;
    
    // 1. 注册设备节点
    if ((err = misc_register(&wuwa_misc_device))) return err;

    // 2. 注册硬件单步调试器回调
    register_step_hook(&my_step_hook);

    // 3. 拦截内核指令异常总入口
    if (resolve_hook_address(&mem_abort_hook) == 0) {
        mem_abort_hook.ops.func = ftrace_thunk;
        mem_abort_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
        ftrace_set_filter_ip(&mem_abort_hook.ops, mem_abort_hook.address, 0, 0);
        register_ftrace_function(&mem_abort_hook.ops);
    }

    pr_info("[wuwa_stepper] 终极无痕硬件劫持引擎初始化成功！\n");
    return 0;
}

static void __exit wuwa_engine_exit(void) {
    engine_active = false;
    unregister_ftrace_function(&mem_abort_hook.ops);
    ftrace_set_filter_ip(&mem_abort_hook.ops, mem_abort_hook.address, 1, 0);
    unregister_step_hook(&my_step_hook);
    misc_deregister(&wuwa_misc_device);
    pr_info("[wuwa_stepper] 引擎已彻底卸载。\n");
}

module_init(wuwa_engine_init);
module_exit(wuwa_engine_exit);
