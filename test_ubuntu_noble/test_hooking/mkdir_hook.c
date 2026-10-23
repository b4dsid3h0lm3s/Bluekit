#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Ftrace mkdir hook module");
MODULE_VERSION("1.0");

/* フック対象の関数名 */
#define TARGET_FUNC "__x64_sys_mkdir"
/* Ftraceの命令サイズ (x86_64における5バイトのNOP/JMP) */
#define MCOUNT_INSN_SIZE 5

static unsigned long orig_mkdir_addr;
static struct ftrace_ops hook_ops;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static void notrace hook_mkdir(unsigned long ip, unsigned long parent_ip,struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    pr_info("mkdir_hook: callback ip=%lx\n", ip);
    // カーネル5.7以降は ftrace_regs から pt_regs を取得
    //
    struct pt_regs *regs = ftrace_get_regs(fregs);
    if (!regs)
        return;
#else
static void notrace hook_mkdir(unsigned long ip, unsigned long parent_ip,
                               struct ftrace_ops *ops, struct pt_regs *regs)
{
#endif
    char user_buf[256] = {0};
   
    struct pt_regs *sys_regs;
    char __user *pathname;

    sys_regs = (struct pt_regs *)regs->di;
    pathname = (char __user *)sys_regs->di;
    pr_info("ip=%lx di=%lx si=%lx\n",
        regs->ip,
        regs->di,
        regs->si);

    if (pathname) {
        // ユーザー空間から安全に文字列をコピー
        if (copy_from_user(user_buf, pathname, sizeof(user_buf) - 1) == 0) {
            user_buf[sizeof(user_buf) - 1] = '\0';
            // フォルダ名に "hacker" が含まれているかチェック
            if (strstr(user_buf, "hacker") != NULL) {
                pr_alert("mkdir_hook: 'hacker' フォルダの作成を検出しました\n");
                // ax レジスタ（戻り値）に「Permission denied (-EACCES)」をセット
                regs->ax = (unsigned long)-EACCES;
                return;
            }
        }
    }

}

/* カーネル内の関数名からアドレスを検索する関数（kprobeを利用） */
static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;

    if (register_kprobe(&kp) < 0) return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}


static int __init fh_init(void)
{
    int err;

    // 1. __x64_sys_mkdir のアドレスを探す
    orig_mkdir_addr = lookup_name(TARGET_FUNC);
    if (!orig_mkdir_addr) {
        pr_err("mkdir_hook: アドレスの取得に失敗しました\n");
        return -ENOENT;
    }

    // 2. Ftraceの設定を行う
    hook_ops.func = (ftrace_func_t)hook_mkdir;
    hook_ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION;

    // 3. 対象の関数を指定してFtraceに登録
    err = ftrace_set_filter(&hook_ops, TARGET_FUNC, strlen(TARGET_FUNC), 0);
    if (err) {
        pr_err("mkdir_hook: フィルター設定エラー: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook_ops);
    if (err) {
        pr_err("mkdir_hook: Ftrace登録エラー: %d\n", err);
        return err;
    }

    pr_info("mkdir_hook: モジュールをロードしました。ターゲット: %s\n", TARGET_FUNC);
    return 0;
}

/* モジュールがアンロードされたときの処理（元に戻す） */
static void __exit fh_exit(void)
{
    unregister_ftrace_function(&hook_ops);
    ftrace_set_filter(&hook_ops, TARGET_FUNC, strlen(TARGET_FUNC), 1);
    pr_info("mkdir_hook: モジュールをアンロードしました。\n");
}

module_init(fh_init);
module_exit(fh_exit);

