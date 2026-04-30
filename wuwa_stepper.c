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
#include <linux/highmem.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <linux/miscdevice.h>
#include "wuwa_ctrl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DaNiu");
MODULE_DESCRIPTION("Page-Centric Shadow Manager (Strict Engineering Edition)");

#define ARM64_PTE_PFN_MASK GENMASK_ULL(47, 12)
#define MAX_PATCHES_PER_PAGE 8

struct shadow_page {
    struct list_head list;
    pid_t pid;
    unsigned long va_page;
    struct page *orig_page;
    struct page *sh_page;
    unsigned long orig_pfn;
    
    int cave_watermark;
    int patch_count;
    bool corrupted; 
    struct patch_req patches[MAX_PATCHES_PER_PAGE];
};

static LIST_HEAD(shadow_page_list);
static DEFINE_MUTEX(shadow_list_lock);

static int force_page_resident(struct task_struct *task, struct mm_struct *mm, unsigned long addr, struct page **out_page) {
    int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    mmap_read_lock(mm);
    ret = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, out_page, NULL);
    mmap_read_unlock(mm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
    ret = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, out_page, NULL, NULL);
    mmap_read_unlock(mm);
#else
    down_read(&mm->mmap_sem);
    ret = get_user_pages_remote(task, mm, addr, 1, FOLL_FORCE, out_page, NULL, NULL);
    up_read(&mm->mmap_sem);
#endif
    return ret;
}

static int alloc_cave_in_page(void *kaddr, struct shadow_page *sp, int size) {
    int count = 0, i;
    for (i = sp->cave_watermark - 4; i >= 0; i -= 4) {
        uint32_t v = *(uint32_t *)((char *)kaddr + i);
        if (v == 0x00000000 || v == 0xD503201F) {
            count += 4;
            if (count >= size) {
                sp->cave_watermark = i; 
                return i;
            }
        } else {
            count = 0;
        }
    }
    return -ENOSPC; 
}

static int apply_single_patch(struct shadow_page *sp, struct patch_req *req, void *sh_kaddr) {
    unsigned long off = req->va & ~PAGE_MASK;
    uint32_t *dst = (uint32_t *)((char *)sh_kaddr + off);
    
    long j_off = 0, j_back = 0, j_go = 0;
    int cave_off = 0;
    uint32_t *stub = NULL;
    unsigned long cave = 0, god = 0;

    switch (req->action) {
        case 1: 
            *dst = 0xD65F03C0; 
            break;
        case 2: 
            j_off = (long)req->target_va - (long)req->va;
            if ((j_off < -134217728LL) || (j_off > 134217724LL)) return -ERANGE;
            *dst = 0x14000000 | ((j_off >> 2) & 0x03FFFFFF);
            break;
        case 3: 
            cave_off = alloc_cave_in_page(sh_kaddr, sp, 28);
            if (cave_off < 0) return -ENOSPC;

            stub = (uint32_t *)((char *)sh_kaddr + cave_off);
            cave = (sp->va_page) + cave_off; 
            god = req->va;

            stub[0] = 0xB40000A1;     
            stub[1] = 0xB9401C30;     
            stub[2] = 0x35000070;     
            stub[3] = 0x52800020;     
            stub[4] = 0xD65F03C0;     
            stub[5] = *dst;           

            j_back = (god + 4) - (cave + 24);
            stub[6] = 0x14000000 | ((j_back >> 2) & 0x03FFFFFF);

            j_go = cave - god;
            *dst = 0x14000000 | ((j_go >> 2) & 0x03FFFFFF);
            break;
        case 4: 
            *dst = req->patch_val;
            *(dst + 1) = req->patch_val_2;
            break;
        case 5: 
            if (off + 8 > PAGE_SIZE) return -EFAULT;
            *dst = 0x52800020;       
            *(dst + 1) = 0xD65F03C0; 
            break;
        case 6: 
            if (off + 12 > PAGE_SIZE) return -EFAULT;
            *dst = 0x1C000040;       
            *(dst + 1) = 0xD65F03C0; 
            *(dst + 2) = req->patch_val; 
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

// ====== 修复后的事务重构 ======
static int rebuild_shadow_page(struct shadow_page *sp) {
    void *orig_kaddr = kmap(sp->orig_page);
    void *sh_kaddr = kmap(sp->sh_page);
    int i, ret = 0;

    memcpy(sh_kaddr, orig_kaddr, PAGE_SIZE);
    sp->cave_watermark = PAGE_SIZE;

    for (i = 0; i < sp->patch_count; i++) {
        if ((ret = apply_single_patch(sp, &sp->patches[i], sh_kaddr)) < 0) {
            pr_err("[wuwa] 致命: Patch 重放失败 (VA:0x%llx), ret=%d\n", sp->patches[i].va, ret);
            break; 
        }
    }

    // 【修复】：只有当所有 Patch 重放均成功时，才刷新 I-Cache 对外暴露
    if (ret == 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        flush_icache_range((unsigned long)sh_kaddr, (unsigned long)sh_kaddr + PAGE_SIZE);
#else
        __flush_icache_range((unsigned long)sh_kaddr, (unsigned long)sh_kaddr + PAGE_SIZE);
#endif
    }

    kunmap(sp->sh_page);
    kunmap(sp->orig_page);
    return ret;
}

static int swap_pte_with_lock(struct mm_struct *mm, unsigned long addr, unsigned long target_pfn, unsigned long *out_old_pfn) {
    pgd_t *pgdp; p4d_t *p4dp; pud_t *pudp; pmd_t *pmdp; pte_t *ptep;
    pte_t pte, new_pte;
    spinlock_t *ptl;
    struct vm_area_struct *vma;
    unsigned long tlbi_val;
    int ret = -EFAULT;

    mmap_read_lock(mm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    vma = vma_lookup(mm, addr);
#else
    vma = find_vma(mm, addr);
#endif

    if (!vma || vma->vm_start > addr || !(vma->vm_flags & VM_EXEC)) {
        pr_err("[wuwa] 拦截失败: VA 0x%lx 不属于合法的 VM_EXEC 映射\n", addr);
        ret = -EPERM;
        goto err_unlock;
    }

    pgdp = pgd_offset(mm, addr);
    if (pgd_none(READ_ONCE(*pgdp)) || pgd_bad(READ_ONCE(*pgdp))) goto err_unlock;
    p4dp = p4d_offset(pgdp, addr);
    if (p4d_none(READ_ONCE(*p4dp)) || p4d_bad(READ_ONCE(*p4dp))) goto err_unlock;
    pudp = pud_offset(p4dp, addr);
    if (pud_none(READ_ONCE(*pudp)) || pud_bad(READ_ONCE(*pudp))) goto err_unlock;
    pmdp = pmd_offset(pudp, addr);
    if (pmd_none(READ_ONCE(*pmdp)) || pmd_trans_huge(READ_ONCE(*pmdp)) || pmd_bad(READ_ONCE(*pmdp))) goto err_unlock;

    ptep = pte_offset_map_lock(mm, pmdp, addr, &ptl);
    if (!ptep) goto err_unlock;

    pte = *ptep;
    if (!pte_present(pte)) { ret = -EFAULT; goto err_ptl; }
    if (pte_cont(pte)) { ret = -EBUSY; goto err_ptl; }

    if (out_old_pfn) *out_old_pfn = pte_pfn(pte);

    new_pte = __pte((pte_val(pte) & ~ARM64_PTE_PFN_MASK) | (target_pfn << 12));
    
    dsb(ishst);
    WRITE_ONCE(*ptep, new_pte);

    tlbi_val = (addr >> 12);
    __asm__ volatile("tlbi vaae1is, %0" : : "r" (tlbi_val));
    
    dsb(ish);
    isb();

    ret = 0;

err_ptl:
    pte_unmap_unlock(ptep, ptl);
err_unlock:
    mmap_read_unlock(mm);
    return ret;
}

static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct patch_req req;
    struct task_struct *task;
    struct mm_struct *mm;
    struct shadow_page *sp = NULL, *tmp;
    int i, found = 0;
    long ret = 0;
    bool is_new_sp = false;
    int old_count = 0;
    struct patch_req old_patches[MAX_PATCHES_PER_PAGE];

    if (cmd != WUWA_IOCTL_SET_HOOK) return -ENOTTY;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

    rcu_read_lock();
    task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); return -ESRCH; }

    mutex_lock(&shadow_list_lock);

    if (req.enabled) {
        unsigned long va_page = req.va & PAGE_MASK;
        list_for_each_entry(tmp, &shadow_page_list, list) {
            if (tmp->pid == req.pid && tmp->va_page == va_page) { sp = tmp; break; }
        }

        if (sp && sp->corrupted) { ret = -EIO; goto out_unlock; }

        if (!sp) {
            sp = kzalloc(sizeof(struct shadow_page), GFP_KERNEL);
            if (!sp) { ret = -ENOMEM; goto out_unlock; }
            sp->pid = req.pid; 
            sp->va_page = va_page; 
            sp->corrupted = false;
            is_new_sp = true;

            if ((ret = force_page_resident(task, mm, va_page, &sp->orig_page)) < 0) {
                kfree(sp); goto out_unlock;
            }
            sp->sh_page = alloc_page(GFP_HIGHUSER);
            if (!sp->sh_page) { put_page(sp->orig_page); kfree(sp); ret = -ENOMEM; goto out_unlock; }
            
            // 【修复】：不再提前挂载链表，保持结构纯净
        }

        old_count = sp->patch_count;
        memcpy(old_patches, sp->patches, sizeof(old_patches));

        for (i = 0; i < sp->patch_count; i++) {
            if (sp->patches[i].va == req.va) { sp->patches[i] = req; found = 1; break; }
        }

        if (!found) {
            if (sp->patch_count >= MAX_PATCHES_PER_PAGE) { ret = -ENOSPC; goto err_rollback; }
            sp->patches[sp->patch_count++] = req;
        }

        if ((ret = rebuild_shadow_page(sp)) < 0) goto err_rollback;

        if (is_new_sp) {
            if ((ret = swap_pte_with_lock(mm, va_page, page_to_pfn(sp->sh_page), &sp->orig_pfn)) != 0) {
                pr_err("[wuwa] 影子页置换失败(err:%ld), VA: 0x%lx\n", ret, va_page);
                goto err_rollback;
            }
            // 【修复】：所有核心动作完成，成功置换页表后，才挂入全局管理链表
            list_add_tail(&sp->list, &shadow_page_list);
            pr_info("[wuwa] 影子页置换成功! VA: 0x%lx\n", va_page);
        } else {
            pr_info("[wuwa] 影子页增量更新成功! VA: 0x%llx\n", req.va);
        }
        goto out_unlock;

err_rollback:
        if (is_new_sp) {
            // is_new_sp 从未挂载到全局链表，直接清理内存即可
            __free_page(sp->sh_page); put_page(sp->orig_page); kfree(sp);
        } else {
            sp->patch_count = old_count;
            memcpy(sp->patches, old_patches, sizeof(old_patches));
            if (rebuild_shadow_page(sp) < 0) {
                pr_emerg("[wuwa] 致命: 事务回滚失败！影子页已被污染。\n");
                sp->corrupted = true;
            }
        }
    } else {
        list_for_each_entry_safe(sp, tmp, &shadow_page_list, list) {
            if (sp->pid == req.pid) {
                if (req.va == 0) {
                    sp->patch_count = 0; 
                } else if ((req.va & PAGE_MASK) == sp->va_page) {
                    bool patch_deleted = false;
                    for (i = 0; i < sp->patch_count; i++) {
                        if (sp->patches[i].va == req.va) {
                            sp->patch_count--;
                            sp->patches[i] = sp->patches[sp->patch_count];
                            patch_deleted = true;
                            break;
                        }
                    }
                    // 【修复】：未找到对应的 Patch 时明确报错，不执行无意义的重建
                    if (!patch_deleted) {
                        ret = -ENOENT;
                        pr_warn("[wuwa] 删除失败: 未在影子页找到目标 VA 0x%llx\n", req.va);
                        break; 
                    }
                }

                if (sp->patch_count == 0 || sp->corrupted) {
                    if (swap_pte_with_lock(mm, sp->va_page, sp->orig_pfn, NULL) == 0) {
                        pr_info("[wuwa] 影子页已安全还原: 0x%lx\n", sp->va_page);
                    } else {
                        pr_warn("[wuwa] 还原失败 (VMA 可能已销毁), 强制回收物理页\n");
                    }
                    list_del(&sp->list); __free_page(sp->sh_page); put_page(sp->orig_page); kfree(sp);
                } else {
                    if (rebuild_shadow_page(sp) < 0) {
                        pr_emerg("[wuwa] 致命: 局部清理时重构失败，影子页标记为损坏！\n");
                        sp->corrupted = true;
                    } else {
                        pr_info("[wuwa] 影子页局部回滚完成 (残留 %d 个 Patch)\n", sp->patch_count);
                    }
                }
            }
        }
    }

out_unlock:
    mutex_unlock(&shadow_list_lock);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

static const struct file_operations wuwa_fops = { 
    .owner=THIS_MODULE, .unlocked_ioctl=wuwa_ioctl, .compat_ioctl=wuwa_ioctl 
};
static struct miscdevice wuwa_misc_device = { 
    .minor=MISC_DYNAMIC_MINOR, .name="wuwa_stepper", .fops=&wuwa_fops 
};

static int __init wuwa_init(void) {
    int ret = misc_register(&wuwa_misc_device);
    if (ret == 0) {
        pr_info("[wuwa] Page-Centric Shadow Manager Engine Started Successfully.\n");
    }
    return ret;
}

static void __exit wuwa_exit(void) {
    struct shadow_page *sp, *tmp;
    struct task_struct *task;
    struct mm_struct *mm;

    mutex_lock(&shadow_list_lock);
    list_for_each_entry_safe(sp, tmp, &shadow_page_list, list) {
        rcu_read_lock();
        task = pid_task(find_vpid(sp->pid), PIDTYPE_PID);
        if (task) get_task_struct(task);
        rcu_read_unlock();
        if (task) {
            mm = get_task_mm(task);
            if (mm) { swap_pte_with_lock(mm, sp->va_page, sp->orig_pfn, NULL); mmput(mm); }
            put_task_struct(task);
        }
        list_del(&sp->list); __free_page(sp->sh_page); put_page(sp->orig_page); kfree(sp);
    }
    mutex_unlock(&shadow_list_lock);
    misc_deregister(&wuwa_misc_device);
    pr_info("[wuwa] Engine Unloaded Safely.\n");
}

module_init(wuwa_init);
module_exit(wuwa_exit);
