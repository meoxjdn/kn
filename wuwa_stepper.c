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
MODULE_DESCRIPTION("GKI 6.6 Ultimate Stealth Engine (Full Unomitted Armor Edition)");

// ==============================================================================
// 1. 动态符号表与外部参数注入
// ==============================================================================
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
        pr_err("[wuwa] 错误：缺少外部传入的符号地址字符串！\n");
        return -EINVAL;
    }

    if (kstrtoul(addr_reg_step, 0, &reg) ||
        kstrtoul(addr_unreg_step, 0, &unreg) ||
        kstrtoul(addr_en_step, 0, &en) ||
        kstrtoul(addr_dis_step, 0, &dis)) {
        pr_err("[wuwa] 错误：符号地址字符串解析失败！\n");
        return -EINVAL;
    }

    _register_user_step_hook = (fn_register_user_step_hook)reg;
    _unregister_user_step_hook = (fn_unregister_user_step_hook)unreg;
    _user_enable_single_step = (fn_user_enable_single_step)en;
    _user_disable_single_step = (fn_user_disable_single_step)dis;

    return 0;
}

// ==============================================================================
// 2. 核心状态机与工业级安全锁
// ==============================================================================
static struct patch_req active_req = {0};
static atomic_t engine_active = ATOMIC_INIT(0);
static atomic_t in_flight_handlers = ATOMIC_INIT(0); // 绝对退场信标，防 UAF
DEFINE_SEQLOCK(req_seqlock); // 读写防撕裂顺序锁

// ==============================================================================
// 3. 内存管理：强制页面驻留 (终结“页不存在”的死穴)
// ==============================================================================
static int force_page_resident(struct task_struct *task, unsigned long addr) {
    struct mm_struct *mm;
    struct page *page = NULL;
    int ret = -EFAULT;

    mm = get_task_mm(task);
    if (!mm) {
        pr_err("[wuwa] force_page_resident: 无法获取 task_mm\n");
        return -ESRCH;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    ret = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, &page, NULL);
#else
    ret = get_user_pages_remote(task, mm, addr, 1, FOLL_FORCE, &page, NULL, NULL);
#endif

    if (ret > 0 && page) {
        put_page(page); // 我们不需要锁定 page，只需要它被读入内存即可
        ret = 0;
    } else {
        pr_err("[wuwa] force_page_resident: get_user_pages_remote 失败, ret=%d\n", ret);
        ret = -EFAULT;
    }

    mmput(mm);
    return ret;
}

// ==============================================================================
// 4. 内存管理：Lockless PTE 原子修改 (带严格层级校验与 ASID 刷新)
// ==============================================================================
static void toggle_page_uxn_lockless(struct mm_struct *mm, unsigned long addr, bool enable_uxn) {
    pgd_t *pgdp;
    p4d_t *p4dp;
    pud_t *pudp;
    pmd_t *pmdp;
    pte_t *ptep;
    pmd_t pmd_val;
    pte_t old_pte, new_pte;
    unsigned long ttbr0, asid, tlbi_val;

    if (!mm) return;

    // 严谨的 5 级页表遍历，任何一环缺失直接放弃，绝不触发空指针解引用
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

    // 原子 CMPXCHG 循环更新 PTE，完美解决多线程缺页竞态
    do {
        old_pte = READ_ONCE(*ptep);
        
        // 最终保命防线：如果页不存在，或者它是连续页表项(CONT)，直接放弃
        if (!pte_present(old_pte)) {
            pr_err("[wuwa] toggle_page: 物理页不存在 (Swap/Unmapped), VA: 0x%lx\n", addr);
            return;
        }
        if (pte_cont(old_pte)) {
            pr_err("[wuwa] toggle_page: 遇到 CONT_PTE 连续页，放弃修改防 Panic, VA: 0x%lx\n", addr);
            return;
        }

        if (enable_uxn) {
            new_pte = set_pte_bit(old_pte, __pgprot(PTE_UXN));
        } else {
            new_pte = clear_pte_bit(old_pte, __pgprot(PTE_UXN));
        }

    } while (cmpxchg((u64 *)ptep, pte_val(old_pte), pte_val(new_pte)) != pte_val(old_pte));

    // 获取当前进程真实的 ASID
    ttbr0 = read_sysreg(ttbr0_el1);
    asid = (ttbr0 & GENMASK_ULL(63, 48)) >> 48;
    
    // 拼接 TLBI 格式: [63:48] ASID | [43:12] VA
    tlbi_val = (asid << 48) | (addr >> 12);
    
    // 纯内联汇编规避 __tlbi 宏版本差异，精准核销目标进程的该页缓存
    dsb(ishst);
    __asm__ volatile("tlbi vale1is, %0" : : "r" (tlbi_val));
    dsb(ish);
    isb();

    pr_info("[wuwa] PTE 权限已切换: %s -> VA: 0x%lx (所属 ASID: %lu)\n", 
            enable_uxn ? "开启 UXN 埋伏" : "解除 UXN 放行", addr, asid);
}

// ==============================================================================
// 5. 虚拟动作引擎 (零物理内存修改，纯 CPU 劫持)
// ==============================================================================
static bool apply_virtual_action(struct pt_regs *regs, struct patch_req *req) {
    uint32_t val = 0;

    switch (req->action) {
        case 0: /* 虚拟 NOP (Data Patch 退化方案) */
            if (req->patch_val == 0xD65F03C0) {
                regs->pc = regs->regs[30]; // RET
            } else {
                regs->pc += 4; // 跳过当前指令
            }
            return true;

        case 1: /* RET Only (去黑边等) */
            regs->pc = regs->regs[30]; 
            return true;

        case 2: /* JUMP B (秒过等长跳) */
            regs->pc = req->target_va; 
            return true;

        case 3: /* God Mode (无敌判定) */
            if (regs->regs[1] == 0) return false;
            
            pagefault_disable();
            if (__get_user(val, (uint32_t __user *)(regs->regs[1] + 0x1C)) == 0) {
                if (val == 0) {
                    regs->regs[0] = 1;         // MOV W0, #1
                    regs->pc = regs->regs[30]; // RET
                    pagefault_enable(); 
                    return true;
                }
            }
            pagefault_enable(); 
            return false; // 非目标对象，正常放行

        case 4: /* Double Patch (双指令虚拟 NOP) */
            regs->pc += 8;
            return true;

        case 5: /* Safe HP (锁血蹦床) */
            regs->regs[0] = 1; 
            regs->pc = regs->regs[30]; 
            return true;

        case 6: /* Float Ret (全屏 AOE 浮点参数) */
            current->thread.uw.fpsimd_state.vregs[0] = (u64)req->patch_val;
            regs->pc = regs->regs[30]; 
            return true;

        default: 
            return false;
    }
}

// ==============================================================================
// 6. Kprobe 拦截层 (Hook handle_mm_fault)
// ==============================================================================
static int hook_mm_fault_pre(struct kprobe *p, struct pt_regs *kregs) {
    // ARM64 handle_mm_fault 传参: x0=vma, x1=address, x2=flags, x3=regs (user pt_regs)
    unsigned long addr = kregs->regs[1];
    struct pt_regs *uregs = (struct pt_regs *)kregs->regs[3];
    unsigned int seq;
    int retries = 0;
    struct patch_req local_req;

    if (!uregs || !user_mode(uregs)) return 0;
    if (atomic_read(&engine_active) == 0) return 0;

    atomic_inc(&in_flight_handlers); // 签到，进入临界区
    
    // 完整版的 Seqlock 重试机制，防撕裂并带断路器
    do {
        if (retries++ > 3) {
            pr_warn("[wuwa] Kprobe: Seqlock 重试次数过多，放弃本次拦截。\n");
            goto out_pass;
        }
        seq = read_seqbegin(&req_seqlock);
        local_req = active_req;
    } while (read_seqretry(&req_seqlock, seq));

    if (current->pid == local_req.pid) {
        unsigned long page_base = local_req.va & PAGE_MASK;
        
        if ((addr & PAGE_MASK) == page_base) {
            
            // 精准命中 PC
            if (uregs->pc == local_req.va) {
                if (apply_virtual_action(uregs, &local_req)) {
                    pr_info("[wuwa] 拦截成功！Action %d 已执行，PC 被重定向。\n", local_req.action);
                } else {
                    pr_info("[wuwa] 触发点到达，但逻辑未满足(如 GodMode 检查失败)，正常放行。\n");
                }
            }
            
            // 退出 UXN 态，准备放行 CPU 真实执行，并挂上单步钩子
            rcu_read_lock();
            toggle_page_uxn_lockless(current->mm, page_base, false);
            _user_enable_single_step(current);
            rcu_read_unlock();
        }
    }

out_pass:
    atomic_dec(&in_flight_handlers); // 签退，离开临界区
    return 0; // 绝对不拦截，返回 0 让内核原版 handle_mm_fault 正常处理
}

static struct kprobe kp_mm_fault = {
    .symbol_name = "handle_mm_fault",
    .pre_handler = hook_mm_fault_pre,
};

// ==============================================================================
// 7. 硬件单步回调层
// ==============================================================================
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

    // 单步里的完整 Seqlock 断路器
    do {
        if (retries++ > 3) goto out_err;
        seq = read_seqbegin(&req_seqlock);
        local_req = active_req;
    } while (read_seqretry(&req_seqlock, seq));
    
    if (current->pid == local_req.pid) {
        // 关闭单步，重新挂上 UXN 埋伏
        rcu_read_lock();
        _user_disable_single_step(current); 
        toggle_page_uxn_lockless(current->mm, local_req.va & PAGE_MASK, true);
        rcu_read_unlock();
        
        atomic_dec(&in_flight_handlers);
        return 0; // 处理成功
    }

out_err:
    atomic_dec(&in_flight_handlers);
    return DBG_HOOK_ERROR;
}

static struct step_hook my_step_hook = { 
    .fn = wuwa_step_handler 
};

// ==============================================================================
// 8. 用户态 IOCTL 通信入口
// ==============================================================================
static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct patch_req req;
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    int force_ret = 0;
    
    if (cmd != WUWA_IOCTL_SET_HOOK) return -ENOTTY;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

    // 清理旧钩子逻辑
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
        pr_info("[wuwa] 收到关闭指令，引擎已休眠并清理旧页表。\n");
        return 0;
    }

    // 写入新配置 (完整的 Seqlock 写锁)
    write_seqlock(&req_seqlock);
    active_req = req;
    write_sequnlock(&req_seqlock);

    // 严格的进程/内存生命周期保护
    rcu_read_lock();
    task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) {
        pr_err("[wuwa] IOCTL 失败: 找不到目标 PID %d\n", req.pid);
        return -ESRCH;
    }

    // 核心操作：强制拉取物理页面驻留，根治 "PTE 不存在" 导致无法打桩的顽疾
    force_ret = force_page_resident(task, req.va & PAGE_MASK);
    if (force_ret < 0) {
        pr_warn("[wuwa] 警告: force_page_resident 失败 (ret=%d)，VA: 0x%llx。打桩可能延后生效。\n", force_ret, req.va);
    } else {
        pr_info("[wuwa] 目标内存页已强制拉取驻留完毕。\n");
    }

    // 安全获取 mm 并执行打桩
    mm = get_task_mm(task);
    if (mm) {
        toggle_page_uxn_lockless(mm, req.va & PAGE_MASK, true);
        mmput(mm);
    } else {
        pr_err("[wuwa] IOCTL 失败: 无法获取 task_mm\n");
    }
    
    put_task_struct(task);
    
    // 全面激活引擎
    atomic_set(&engine_active, 1);
    pr_info("[wuwa] 引擎已激活！目标 PC: 0x%llx, Action: %d\n", req.va, req.action);
    
    return 0;
}

static const struct file_operations wuwa_fops = { 
    .owner = THIS_MODULE, 
    .unlocked_ioctl = wuwa_ioctl, 
#ifdef CONFIG_COMPAT
    .compat_ioctl = wuwa_ioctl 
#endif
};

static struct miscdevice wuwa_misc_device = { 
    .minor = MISC_DYNAMIC_MINOR, 
    .name = "wuwa_stepper", 
    .fops = &wuwa_fops 
};

// ==============================================================================
// 9. 模块初始化与安全退场
// ==============================================================================
static int __init wuwa_init(void) {
    if (resolve_all_symbols() < 0) return -EINVAL;
    
    if (misc_register(&wuwa_misc_device) < 0) {
        pr_err("[wuwa] 严重错误：无法注册 misc 设备！\n");
        return -1;
    }
    
    _register_user_step_hook(&my_step_hook);
    
    // 挂钩 handle_mm_fault
    if (register_kprobe(&kp_mm_fault) < 0) {
        pr_err("[wuwa] 严重错误：无法 Hook handle_mm_fault！\n");
        _unregister_user_step_hook(&my_step_hook);
        misc_deregister(&wuwa_misc_device);
        return -1;
    }
    
    pr_info("[wuwa] 终极防线引擎加载成功！万物皆虚，万事皆允。\n");
    return 0;
}

static void __exit wuwa_exit(void) {
    int timeout = 50; // 最多等待 500ms

    // 1. 关闭总闸，切断新的处理请求
    atomic_set(&engine_active, 0);
    smp_mb();

    // 2. 切断源头：注销入口函数
    unregister_kprobe(&kp_mm_fault);
    _unregister_user_step_hook(&my_step_hook);

    // 3. 优雅退场：数学级的安全退场，等待所有在飞的回调彻底落地
    while (atomic_read(&in_flight_handlers) > 0 && timeout-- > 0) {
        cpu_relax();
        msleep(10);
    }
    
    if (atomic_read(&in_flight_handlers) > 0) {
        pr_warn("[wuwa] 警告：卸载超时，仍有回调未退出，系统可能不稳定！\n");
    }

    // 4. 清理通信设备
    misc_deregister(&wuwa_misc_device);
    
    pr_info("[wuwa] 终极引擎已安全卸载。\n");
}

module_init(wuwa_init);
module_exit(wuwa_exit);
