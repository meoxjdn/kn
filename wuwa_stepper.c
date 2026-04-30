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
MODULE_DESCRIPTION("GKI 6.6 Ultimate Traceiter Engine (Full Armor + Debug Edition)");

// ====== 动态符号表 (外部参数注入版) ======
typedef void (*fn_register_user_step_hook)(struct step_hook *hook);
typedef void (*fn_unregister_user_step_hook)(struct step_hook *hook);
typedef void (*fn_user_enable_single_step)(struct task_struct *task);
typedef void (*fn_user_disable_single_step)(struct task_struct *task);

static fn_register_user_step_hook _register_user_step_hook;
static fn_unregister_user_step_hook _unregister_user_step_hook;
static fn_user_enable_single_step _user_enable_single_step;
static fn_user_disable_single_step _user_disable_single_step;

// 接收外部传入的地址参数
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
static atomic_t in_flight_handlers = ATOMIC_INIT(0); // 绝对退场信标
DEFINE_SEQLOCK(req_seqlock); 

// ====== Lockless PTE 原子修改 (带安全断路器与日志) ======
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
        
        // 【最终保命防线】：如果页不存在，或者它是连续页表项(CONT)，直接放弃！
        if (!pte_present(old_pte) || pte_cont(old_pte)) {
            pr_err("[wuwa] 放弃修改 PTE: 页不存在或为 CONT_PTE。VA: 0x%lx\n", addr);
            return; 
        }

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

    pr_info("[wuwa] PTE 已修改: %s -> VA: 0x%lx (ASID: %lu)\n", enable_uxn ? "UXN 打桩" : "UXN 解除", addr, asid);
}

// ====== 寄存器虚拟动作核心分发器 ======
static bool apply_virtual_action(struct pt_regs *regs, struct patch_req *req) {
    uint32_t val = 0;
    switch (req->action) {
        case 0: /* SHADOW_DATA_PATCH (虚拟 NOP 化) */
            if (req->patch_val == 0xD65F03C0) {
                regs->pc = regs->regs[30];
            } else {
                regs->pc += 4;
            }
            return true;

        case 1: /* SHADOW_RET_ONLY */
            regs->pc = regs->regs[30]; 
            return true;

        case 2: /* SHADOW_JUMP_B (秒过) */
            regs->pc = req->target_va; 
            return true;

        case 3: /* 无敌模式 God Mode (X1+0x1C 判定) */
            if (regs->regs[1] == 0) return false;
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

        case 4: /* SHADOW_DOUBLE_PATCH (去黑边双指令) */
            regs->pc += 8;
            return true;

        case 5: /* SHADOW_SAFE_HP_STUB (锁血蹦床) */
            regs->regs[0] = 1; 
            regs->pc = regs->regs[30]; 
            return true;

        case 6: /* SHADOW_FLOAT_RET (全屏浮点) */
            current->thread.uw.fpsimd_state.vregs[0] = (u64)req->patch_val;
            regs->pc = regs->regs[30]; 
            return true;

        default: 
            return false;
    }
}

// ====== 异常接管钩子 (Traceiter 侧门盲狙版) ======
static int hook_trace_pre(struct kprobe *p, struct pt_regs *kregs) {
    struct pt_regs *uregs = NULL;
    unsigned int seq;
    int retries = 0, i;
    struct patch_req local_req;

    if (atomic_read(&engine_active) == 0) return 0;

    // 扫描 X1 到 X4，自动定位并提取 User pt_regs 指针
    for (i = 1; i <= 4; i++) {
        struct pt_regs *tmp = (struct pt_regs *)kregs->regs[i];
        if ((unsigned long)tmp > 0xffffff0000000000ULL && user_mode(tmp)) {
            uregs = tmp;
            break;
        }
    }

    if (!uregs) return 0; // 没找到说明这不是异常调用的上下文

    atomic_inc(&in_flight_handlers);

    // Seqlock 安全重试机制
    do {
        if (retries++ > 3) goto out_pass;
        seq = read_seqbegin(&req_seqlock);
        local_req = active_req;
    } while (read_seqretry(&req_seqlock, seq));

    if (current->pid == local_req.pid) {
        unsigned long page_base = local_req.va & PAGE_MASK;
        
        // 记录命中信息 (排障核心)
        if ((uregs->pc & PAGE_MASK) == page_base) {
            pr_info("[wuwa] 命中监控页! 触发点 PC: 0x%llx (期望 PC: 0x%llx)\n", uregs->pc, local_req.va);
            
            if (uregs->pc == local_req.va) {
                if (apply_virtual_action(uregs, &local_req)) {
                    pr_info("[wuwa] 动作 %d 执行成功！虚拟 PC 已重定向。\n", local_req.action);
                } else {
                    pr_info("[wuwa] 动作 %d 判定未通过 (如 GodMode X1 检查不满足)，放行。\n", local_req.action);
                }
            }
            
            // 安全防御：准备单步恢复 UXN
            rcu_read_lock();
            toggle_page_uxn_lockless(current->mm, page_base, false);
            _user_enable_single_step(current);
            rcu_read_unlock();
        }
    }

out_pass:
    atomic_dec(&in_flight_handlers);
    return 0;
}

// 广撒网：同时监听两个可能触发 UXN 异常的 Tracepoint
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
                    toggle_page_uxn_lockless(mm, active_req.va & PAGE_MASK, false);
                    mmput(mm);
                }
                put_task_struct(task);
            }
            pr_info("[wuwa] 引擎已休眠，清理完成。\n");
            return 0;
        }

        // 严格的生命周期保护
        rcu_read_lock();
        task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
        if (task) get_task_struct(task);
        rcu_read_unlock();

        if (!task) return -ESRCH;

        mm = get_task_mm(task);
        put_task_struct(task); 

        if (!mm) return -ESRCH;

        // Seqlock 写锁更新请求
        write_seqlock(&req_seqlock);
        active_req = req;
        write_sequnlock(&req_seqlock);

        // 打上 UXN 异常断点
        toggle_page_uxn_lockless(mm, active_req.va & PAGE_MASK, true);
        atomic_set(&engine_active, 1);
        
        mmput(mm); 

        pr_info("[wuwa] 引擎激活，目标 PC: 0x%llx, Action: %d\n", active_req.va, active_req.action);
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
    int err = 0;
    int kp_count = 0;

    if (resolve_all_symbols() < 0) {
        return -EINVAL;
    }
    if ((err = misc_register(&wuwa_misc_device))) return err;
    
    _register_user_step_hook(&my_step_hook);
    
    if (register_kprobe(&kp_sp_pc) == 0) {
        pr_info("[wuwa] Kprobe 挂接成功: %s\n", kp_sp_pc.symbol_name);
        kp_count++;
    } else {
        pr_err("[wuwa] Kprobe 挂接失败: %s\n", kp_sp_pc.symbol_name);
    }

    if (register_kprobe(&kp_read_fault) == 0) {
        pr_info("[wuwa] Kprobe 挂接成功: %s\n", kp_read_fault.symbol_name);
        kp_count++;
    } else {
        pr_err("[wuwa] Kprobe 挂接失败: %s\n", kp_read_fault.symbol_name);
    }

    if (kp_count == 0) {
        pr_err("[wuwa] 所有的 Traceiter 挂载均失败！\n");
        _unregister_user_step_hook(&my_step_hook);
        misc_deregister(&wuwa_misc_device);
        return -EINVAL;
    }

    pr_info("[wuwa] GKI 6.6 终极引擎加载成功！(拦截点: %d)\n", kp_count);
    return 0;
}

static void __exit wuwa_engine_exit(void) {
    int timeout = 50;

    atomic_set(&engine_active, 0);
    smp_mb();

    if (kp_sp_pc.nmissed >= 0) unregister_kprobe(&kp_sp_pc);
    if (kp_read_fault.nmissed >= 0) unregister_kprobe(&kp_read_fault);
    
    _unregister_user_step_hook(&my_step_hook);

    // 等待所有异常处理器退出，防止 UAF 死机
    while (atomic_read(&in_flight_handlers) > 0 && timeout-- > 0) {
        cpu_relax();
        msleep(10);
    }

    misc_deregister(&wuwa_misc_device);
    pr_info("[wuwa] 引擎已安全卸载。\n");
}

module_init(wuwa_engine_init);
module_exit(wuwa_engine_exit);
