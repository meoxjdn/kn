#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");

static char *name = NULL;
module_param(name, charp, 0444);

static struct kprobe kp;

static int __init t_init(void)
{
    int ret;

    if (!name) {
        pr_err("[kp_test] missing name\n");
        return -EINVAL;
    }

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = name;

    ret = register_kprobe(&kp);
    pr_err("[kp_test] target=%s ret=%d addr=%px\n", name, ret, kp.addr);

    if (ret == 0)
        unregister_kprobe(&kp);

    return -EINVAL;
}

static void __exit t_exit(void) {}
module_init(t_init);
module_exit(t_exit);
