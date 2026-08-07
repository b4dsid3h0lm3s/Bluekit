#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lab");
MODULE_DESCRIPTION("ftrace mkdir debug hook");

#define TARGET_FUNC "__x64_sys_mkdir"

static struct ftrace_ops mkdir_ops;


/*
 * シンボル取得
 */
static unsigned long lookup_symbol(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name,
    };

    if (register_kprobe(&kp))
        return 0;

    unregister_kprobe(&kp);

    return (unsigned long)kp.addr;
}


/*
 * ftrace callback
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

static void notrace mkdir_callback(
        unsigned long ip,
        unsigned long parent_ip,
        struct ftrace_ops *ops,
        struct ftrace_regs *fregs)
{
    struct pt_regs *regs;

    regs = ftrace_get_regs(fregs);

    if (!regs)
        return;


    pr_info(
        "mkdir callback: ip=%lx di=%lx si=%lx dx=%lx\n",
        regs->ip,
        regs->di,
        regs->si,
        regs->dx
    );


    /*
     * ここで syscall ABI の確認をする
     * まだ pathname と決めつけない
     */

}

#else

static void notrace mkdir_callback(
        unsigned long ip,
        unsigned long parent_ip,
        struct ftrace_ops *ops,
        struct pt_regs *regs)
{
    pr_info(
        "mkdir callback: ip=%lx di=%lx si=%lx dx=%lx\n",
        regs->ip,
        regs->di,
        regs->si,
        regs->dx
    );
}

#endif


static int __init mkdir_hook_init(void)
{
    int ret;

    if (!lookup_symbol(TARGET_FUNC)) {
        pr_err("cannot find %s\n", TARGET_FUNC);
        return -ENOENT;
    }


    mkdir_ops.func = mkdir_callback;

    mkdir_ops.flags =
        FTRACE_OPS_FL_SAVE_REGS |
        FTRACE_OPS_FL_RECURSION;


    ret = ftrace_set_filter(
            &mkdir_ops,
            TARGET_FUNC,
            strlen(TARGET_FUNC),
            0);

    if (ret) {
        pr_err("filter failed %d\n", ret);
        return ret;
    }


    ret = register_ftrace_function(&mkdir_ops);

    if (ret) {
        pr_err("register failed %d\n", ret);
        return ret;
    }


    pr_info("mkdir hook loaded\n");

    return 0;
}


static void __exit mkdir_hook_exit(void)
{
    unregister_ftrace_function(&mkdir_ops);

    ftrace_set_filter(
        &mkdir_ops,
        TARGET_FUNC,
        strlen(TARGET_FUNC),
        1
    );

    pr_info("mkdir hook unloaded\n");
}


module_init(mkdir_hook_init);
module_exit(mkdir_hook_exit);
