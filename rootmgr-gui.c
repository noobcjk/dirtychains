/*
 * rootmgr-gui.c —— root 管理器的图形界面
 *
 * 版式参照 KernelSU（Material 3）：浅灰底、大标题、白色圆角卡片。
 * 窗口默认 960x600 横屏，卡片在宽屏下分左右两列，底部是四格切换栏：
 *   主页 / 超级用户 / 终端 / 设置
 *
 * 终端页直接调 /bin/sh -c 执行命令：
 *   - 程序本身以 root 运行时，命令就是 root 权限；
 *   - 否则先试 sudo -n（免密），再退到 pkexec（弹密码框）。
 *
 * 构建：
 *   make rootmgr-gui
 */

#include <gtk/gtk.h>
#include <cairo.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define APP_TITLE   "RootMgr"
#define MGR_VERSION "1.1"

/* 图标种类：全部用 cairo 画，不依赖图标字体 / 主题 */
typedef enum {
    IC_ERROR = 0,   /* 圆圈感叹号 */
    IC_CHECK,       /* 圆圈对勾 */
    IC_HASH,        /* # 号 */
    IC_CHIP,        /* 芯片 */
    IC_SHIELD,      /* 盾牌 */
    IC_FILTER,      /* 三条横线 */
    IC_T_HOME,      /* 底部栏：房子 */
    IC_T_SHIELD,    /* 底部栏：盾牌（超级用户） */
    IC_T_TERM,      /* 底部栏：终端 */
    IC_T_GEAR       /* 底部栏：齿轮（设置） */
} IconKind;

#define TAB_COUNT 4

/* 进程列表的三列 */
enum { COL_PID, COL_USER, COL_CMD, COL_N };

typedef struct {
    GtkWidget *win;
    GtkWidget *stack;

    /* 首页 */
    GtkWidget *ico_status;
    GtkWidget *lbl_status;
    GtkWidget *lbl_status_sub;
    GtkWidget *val_mgr;
    GtkWidget *val_kernel;
    GtkWidget *val_selinux;
    GtkWidget *val_seccomp;

    /* 超级用户页 */
    GtkWidget *tree;
    GtkListStore *store;

    /* 终端页 */
    GtkWidget *termview;
    GtkTextBuffer *termbuf;
    GtkWidget *entry;
    GtkWidget *prompt;
    GPid run_pid;

    /* 底部切换栏 */
    GtkWidget *tab_ico[TAB_COUNT];
    GtkWidget *tab_lbl[TAB_COUNT];
    int        cur;
} App;

/* --------------------------------------------------------------------------
 * 小工具
 * ----------------------------------------------------------------------- */

static const char *user_name(uid_t uid)
{
    static char buf[32];
    struct passwd *pw = getpwuid(uid);

    if (pw)
        return pw->pw_name;
    g_snprintf(buf, sizeof(buf), "%u", (unsigned)uid);
    return buf;
}

static gboolean is_root(void)
{
    return geteuid() == 0;
}

static const char *selinux_text(void)
{
    FILE *f = fopen("/sys/fs/selinux/enforce", "r");
    int c;

    if (!f)
        return "被禁用";

    c = fgetc(f);
    fclose(f);
    if (c == '1')
        return "强制执行";
    if (c == '0')
        return "宽容模式";
    return "未知";
}

static const char *seccomp_text(void)
{
    static char buf[32] = "未知";
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];

    if (!f)
        return "内核未开启";

    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "Seccomp:", 8)) {
            int v = atoi(line + 8);

            if (v == 0)
                g_strlcpy(buf, "未启用", sizeof(buf));
            else if (v == 1)
                g_strlcpy(buf, "严格模式", sizeof(buf));
            else if (v == 2)
                g_strlcpy(buf, "过滤模式", sizeof(buf));
            else
                g_strlcpy(buf, "未知", sizeof(buf));
            break;
        }
    }
    fclose(f);
    return buf;
}

static const char *kernel_release(void)
{
    static struct utsname u;
    static gboolean done = FALSE;

    if (!done) {
        if (uname(&u) != 0)
            g_strlcpy(u.release, "未知", sizeof(u.release));
        done = TRUE;
    }
    return u.release;
}

/* 在常见 sbin 目录里找可执行文件，PATH 里通常不含 /usr/sbin */
static char *find_tool(const char *name)
{
    static const char *dirs[] = {
        "/usr/sbin", "/sbin", "/usr/bin", "/bin",
        "/usr/local/sbin", "/usr/local/bin"
    };
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(dirs); i++) {
        char *p = g_build_filename(dirs[i], name, NULL);

        if (g_file_test(p, G_FILE_TEST_IS_EXECUTABLE))
            return p;
        g_free(p);
    }
    return g_strdup(name);
}

static gboolean have_tool(const char *name)
{
    char *p = find_tool(name);
    gboolean ok = g_file_test(p, G_FILE_TEST_IS_EXECUTABLE);

    g_free(p);
    return ok;
}

/* 免密 sudo 是否可用（root 身份下恒为真） */
static gboolean sudo_ready(void)
{
    static int cached = -1;
    char *sudo;
    char *av[4];
    gint st = -1;
    gboolean ok = FALSE;

    if (cached >= 0)
        return cached != 0;

    if (is_root()) {
        cached = 1;
        return TRUE;
    }

    sudo = find_tool("sudo");
    av[0] = sudo;
    av[1] = "-n";
    av[2] = "true";
    av[3] = NULL;

    if (g_file_test(sudo, G_FILE_TEST_IS_EXECUTABLE) &&
        g_spawn_sync(NULL, av, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
                     NULL, NULL, &st, NULL) &&
        WIFEXITED(st) && WEXITSTATUS(st) == 0)
        ok = TRUE;

    g_free(sudo);
    cached = ok ? 1 : 0;
    return ok;
}

/* --------------------------------------------------------------------------
 * 图标：24x24 网格，线宽 1.9，圆头
 * ----------------------------------------------------------------------- */

static void rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    cairo_new_path(cr);
    cairo_arc(cr, x + r, y + r, r, G_PI, 1.5 * G_PI);
    cairo_arc(cr, x + w - r, y + r, r, 1.5 * G_PI, 2 * G_PI);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, 0.5 * G_PI);
    cairo_arc(cr, x + r, y + h - r, r, 0.5 * G_PI, G_PI);
    cairo_close_path(cr);
}

static gboolean on_icon_draw(GtkWidget *w, cairo_t *cr, gpointer data)
{
    int kind = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "kind"));
    gboolean dim = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "dim"));
    double size = MIN(gtk_widget_get_allocated_width(w),
                      gtk_widget_get_allocated_height(w));
    double s;

    (void)data;
    if (size <= 0)
        return TRUE;

    s = size / 24.0;
    cairo_save(cr);
    cairo_scale(cr, s, s);
    cairo_set_line_width(cr, 1.9);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    if (dim)
        cairo_set_source_rgb(cr, 0.560, 0.560, 0.585);
    else
        cairo_set_source_rgb(cr, 0.106, 0.106, 0.106);

    switch (kind) {
    case IC_CHECK:
        cairo_arc(cr, 12, 12, 9, 0, 2 * G_PI);
        cairo_stroke(cr);
        cairo_move_to(cr, 7.9, 12.3);
        cairo_line_to(cr, 10.7, 15.1);
        cairo_line_to(cr, 16.3, 9.1);
        cairo_stroke(cr);
        break;

    case IC_HASH:
        cairo_move_to(cr, 4.6, 9.2);
        cairo_line_to(cr, 19.4, 9.2);
        cairo_move_to(cr, 4.6, 14.8);
        cairo_line_to(cr, 19.4, 14.8);
        cairo_move_to(cr, 10.0, 4.2);
        cairo_line_to(cr, 8.0, 19.8);
        cairo_move_to(cr, 16.0, 4.2);
        cairo_line_to(cr, 14.0, 19.8);
        cairo_stroke(cr);
        break;

    case IC_CHIP:
        cairo_move_to(cr, 7.5, 2.2);  cairo_line_to(cr, 7.5, 4.6);
        cairo_move_to(cr, 12.0, 2.2); cairo_line_to(cr, 12.0, 4.6);
        cairo_move_to(cr, 16.5, 2.2); cairo_line_to(cr, 16.5, 4.6);
        cairo_move_to(cr, 7.5, 19.4); cairo_line_to(cr, 7.5, 21.8);
        cairo_move_to(cr, 12.0, 19.4); cairo_line_to(cr, 12.0, 21.8);
        cairo_move_to(cr, 16.5, 19.4); cairo_line_to(cr, 16.5, 21.8);
        cairo_stroke(cr);
        rounded_rect(cr, 4.4, 4.4, 15.2, 15.2, 2.4);
        cairo_stroke(cr);
        rounded_rect(cr, 8.2, 8.2, 3.0, 3.0, 0.7);
        cairo_fill(cr);
        rounded_rect(cr, 12.8, 8.2, 3.0, 3.0, 0.7);
        cairo_fill(cr);
        rounded_rect(cr, 8.2, 12.8, 3.0, 3.0, 0.7);
        cairo_fill(cr);
        rounded_rect(cr, 12.8, 12.8, 3.0, 3.0, 0.7);
        cairo_fill(cr);
        break;

    case IC_SHIELD:
        cairo_move_to(cr, 12, 2.4);
        cairo_line_to(cr, 19.9, 5.7);
        cairo_line_to(cr, 19.9, 11.0);
        cairo_curve_to(cr, 19.9, 16.1, 16.6, 20.1, 12, 21.7);
        cairo_curve_to(cr, 7.4, 20.1, 4.1, 16.1, 4.1, 11.0);
        cairo_line_to(cr, 4.1, 5.7);
        cairo_close_path(cr);
        cairo_stroke(cr);
        cairo_move_to(cr, 8.7, 11.9);
        cairo_line_to(cr, 11.0, 14.2);
        cairo_line_to(cr, 15.5, 9.5);
        cairo_stroke(cr);
        break;

    case IC_FILTER:
        cairo_move_to(cr, 3.6, 6.6);
        cairo_line_to(cr, 20.4, 6.6);
        cairo_move_to(cr, 6.6, 12.0);
        cairo_line_to(cr, 17.4, 12.0);
        cairo_move_to(cr, 9.6, 17.4);
        cairo_line_to(cr, 14.4, 17.4);
        cairo_stroke(cr);
        break;

    case IC_ERROR:
    default:
        cairo_arc(cr, 12, 12, 9, 0, 2 * G_PI);
        cairo_stroke(cr);
        cairo_move_to(cr, 12, 7.3);
        cairo_line_to(cr, 12, 12.9);
        cairo_stroke(cr);
        cairo_arc(cr, 12, 16.6, 1.05, 0, 2 * G_PI);
        cairo_fill(cr);
        break;

    /* ---- 底部切换栏 ---- */
    case IC_T_HOME:
        cairo_move_to(cr, 2.9, 11.3);
        cairo_line_to(cr, 12.0, 3.6);
        cairo_line_to(cr, 21.1, 11.3);
        cairo_stroke(cr);
        cairo_move_to(cr, 5.5, 10.3);
        cairo_line_to(cr, 5.5, 20.4);
        cairo_line_to(cr, 18.5, 20.4);
        cairo_line_to(cr, 18.5, 10.3);
        cairo_stroke(cr);
        cairo_move_to(cr, 9.9, 20.4);
        cairo_line_to(cr, 9.9, 15.6);
        cairo_line_to(cr, 14.1, 15.6);
        cairo_line_to(cr, 14.1, 20.4);
        cairo_stroke(cr);
        break;

    case IC_T_SHIELD:
        cairo_move_to(cr, 12, 2.6);
        cairo_line_to(cr, 19.9, 5.9);
        cairo_line_to(cr, 19.9, 11.1);
        cairo_curve_to(cr, 19.9, 16.2, 16.6, 20.2, 12, 21.9);
        cairo_curve_to(cr, 7.4, 20.2, 4.1, 16.2, 4.1, 11.1);
        cairo_line_to(cr, 4.1, 5.9);
        cairo_close_path(cr);
        cairo_stroke(cr);
        cairo_move_to(cr, 12, 2.6);
        cairo_line_to(cr, 12, 21.9);
        cairo_stroke(cr);
        break;

    case IC_T_TERM:
        rounded_rect(cr, 2.6, 4.3, 18.8, 15.4, 3.2);
        cairo_stroke(cr);
        cairo_move_to(cr, 7.0, 9.7);
        cairo_line_to(cr, 10.3, 12.3);
        cairo_line_to(cr, 7.0, 14.9);
        cairo_stroke(cr);
        cairo_move_to(cr, 12.6, 15.2);
        cairo_line_to(cr, 17.2, 15.2);
        cairo_stroke(cr);
        break;

    case IC_T_GEAR: {
        int i;

        cairo_save(cr);
        cairo_set_line_width(cr, 3.4);
        for (i = 0; i < 8; i++) {
            cairo_save(cr);
            cairo_translate(cr, 12, 12);
            cairo_rotate(cr, i * G_PI / 4.0);
            cairo_move_to(cr, 0, -6.1);
            cairo_line_to(cr, 0, -9.1);
            cairo_stroke(cr);
            cairo_restore(cr);
        }
        cairo_restore(cr);
        cairo_set_line_width(cr, 1.9);
        cairo_arc(cr, 12, 12, 6.1, 0, 2 * G_PI);
        cairo_stroke(cr);
        cairo_arc(cr, 12, 12, 2.5, 0, 2 * G_PI);
        cairo_stroke(cr);
        break;
    }
    }

    cairo_restore(cr);
    return TRUE;
}

static GtkWidget *make_icon(IconKind kind, int px)
{
    GtkWidget *w = gtk_drawing_area_new();

    gtk_widget_set_size_request(w, px, px);
    gtk_widget_set_halign(w, GTK_ALIGN_START);
    gtk_widget_set_valign(w, GTK_ALIGN_START);
    g_object_set_data(G_OBJECT(w), "kind", GINT_TO_POINTER(kind));
    g_signal_connect(w, "draw", G_CALLBACK(on_icon_draw), NULL);
    return w;
}

static void icon_set_kind(GtkWidget *w, IconKind kind)
{
    g_object_set_data(G_OBJECT(w), "kind", GINT_TO_POINTER(kind));
    gtk_widget_queue_draw(w);
}

/* --------------------------------------------------------------------------
 * 首页状态
 * ----------------------------------------------------------------------- */

static void refresh_home(App *a)
{
    gboolean root = is_root();
    char buf[128];

    icon_set_kind(a->ico_status, root ? IC_CHECK : IC_ERROR);
    gtk_label_set_text(GTK_LABEL(a->lbl_status), root ? "root 已就绪" : "非 root 身份");
    gtk_label_set_text(GTK_LABEL(a->lbl_status_sub),
                       root ? "当前以 root 运行，「终端」页里的命令都是 root 权限。"
                            : "「终端」页会通过 sudo -n / pkexec 提权执行；"
                              "也可以直接用 root 启动本程序。");

    g_snprintf(buf, sizeof(buf), "%s (%s)", MGR_VERSION,
               root ? "root" : user_name(getuid()));
    gtk_label_set_text(GTK_LABEL(a->val_mgr), buf);
    gtk_label_set_text(GTK_LABEL(a->val_kernel), kernel_release());
    gtk_label_set_text(GTK_LABEL(a->val_selinux), selinux_text());
    gtk_label_set_text(GTK_LABEL(a->val_seccomp), seccomp_text());
}

/* --------------------------------------------------------------------------
 * 超级用户页：当前用户自己的 shell 进程
 * ----------------------------------------------------------------------- */

static gboolean is_shell_name(const char *name)
{
    static const char *ok[] = {
        "sh", "bash", "dash", "zsh", "ksh", "ash", "fish",
        "tmux", "screen", "su", "sudo", "rootmgr-gui"
    };
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(ok); i++)
        if (!strcmp(name, ok[i]))
            return TRUE;
    return FALSE;
}

static void refresh_procs(App *a)
{
    DIR *d;
    struct dirent *de;
    uid_t me = getuid();

    if (!a->store)
        return;

    gtk_list_store_clear(a->store);

    d = opendir("/proc");
    if (!d)
        return;

    while ((de = readdir(d))) {
        char path[300], buf[1024], name[64] = "", cmd[256] = "";
        FILE *f;
        unsigned uid = 0;
        char *p;

        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;

        g_snprintf(path, sizeof(path), "/proc/%s/status", de->d_name);
        f = fopen(path, "r");
        if (!f)
            continue;

        while (fgets(buf, sizeof(buf), f)) {
            if (!strncmp(buf, "Name:", 5))
                g_strlcpy(name, g_strstrip(buf + 5), sizeof(name));
            else if (!strncmp(buf, "Uid:", 4))
                uid = (unsigned)strtoul(buf + 4, NULL, 10);
        }
        fclose(f);

        if (uid != (unsigned)me || !is_shell_name(name))
            continue;

        g_snprintf(path, sizeof(path), "/proc/%s/cmdline", de->d_name);
        f = fopen(path, "r");
        if (f) {
            size_t n = fread(cmd, 1, sizeof(cmd) - 1, f);

            fclose(f);
            cmd[n] = '\0';
            for (p = cmd; p < cmd + n; p++)
                if (*p == '\0')
                    *p = ' ';
        }
        if (!cmd[0])
            g_strlcpy(cmd, name, sizeof(cmd));

        {
            GtkTreeIter it;

            gtk_list_store_append(a->store, &it);
            gtk_list_store_set(a->store, &it,
                               COL_PID, atoi(de->d_name),
                               COL_USER, user_name(me),
                               COL_CMD, cmd, -1);
        }
    }
    closedir(d);
}

/* --------------------------------------------------------------------------
 * 终端
 * ----------------------------------------------------------------------- */

static void term_append(App *a, const char *text, const char *tag)
{
    GtkTextIter end;
    GtkTextMark *mark;

    if (!a->termbuf)
        return;

    gtk_text_buffer_get_end_iter(a->termbuf, &end);
    if (tag)
        gtk_text_buffer_insert_with_tags_by_name(a->termbuf, &end, text, -1, tag, NULL);
    else
        gtk_text_buffer_insert(a->termbuf, &end, text, -1);

    gtk_text_buffer_get_end_iter(a->termbuf, &end);
    gtk_text_buffer_place_cursor(a->termbuf, &end);
    mark = gtk_text_buffer_get_insert(a->termbuf);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(a->termview), mark);
}

/* 输出没以换行结尾时补一个，避免提示符粘在结果后面 */
static void term_ensure_nl(App *a)
{
    GtkTextIter end;
    gunichar ch;

    if (!a->termbuf)
        return;
    gtk_text_buffer_get_end_iter(a->termbuf, &end);
    if (gtk_text_iter_get_offset(&end) == 0)
        return;
    gtk_text_buffer_get_iter_at_offset(a->termbuf, &end, gtk_text_buffer_get_char_count(a->termbuf) - 1);
    ch = gtk_text_iter_get_char(&end);
    if (ch != '\n')
        term_append(a, "\n", NULL);
}

static void term_clear(App *a)
{
    if (a->termbuf)
        gtk_text_buffer_set_text(a->termbuf, "", -1);
}

static const char *term_prompt_str(void)
{
    return is_root() ? "root@rootmgr # " : "user@rootmgr $ ";
}

static gboolean pipe_read(GIOChannel *ch, GIOCondition cond, gpointer data,
                          const char *tag)
{
    App *a = data;
    gchar buf[1024];
    gsize n = 0;
    GError *err = NULL;
    GIOStatus st;

    st = g_io_channel_read_chars(ch, buf, sizeof(buf) - 1, &n, &err);
    if (n > 0) {
        buf[n] = '\0';
        term_append(a, buf, tag);
    }
    if (err)
        g_error_free(err);

    if (st == G_IO_STATUS_EOF || st == G_IO_STATUS_ERROR ||
        ((cond & (G_IO_HUP | G_IO_ERR)) && n == 0)) {
        g_io_channel_unref(ch);
        return FALSE;
    }
    return TRUE;
}

static gboolean on_stdout(GIOChannel *ch, GIOCondition cond, gpointer data)
{
    return pipe_read(ch, cond, data, NULL);
}

static gboolean on_stderr(GIOChannel *ch, GIOCondition cond, gpointer data)
{
    return pipe_read(ch, cond, data, "err");
}

static void on_child_exit(GPid pid, gint status, gpointer data)
{
    App *a = data;
    char buf[64];

    g_spawn_close_pid(pid);
    a->run_pid = 0;

    term_ensure_nl(a);
    if (!WIFEXITED(status))
        term_append(a, "[异常终止]\n", "err");
    else if (WEXITSTATUS(status) != 0) {
        g_snprintf(buf, sizeof(buf), "[退出码 %d]\n", WEXITSTATUS(status));
        term_append(a, buf, "err");
    }

    if (a->entry) {
        gtk_widget_set_sensitive(a->entry, TRUE);
        gtk_widget_grab_focus(a->entry);
    }
}

/* 把命令包成一次 spawn：root 直跑，否则 sudo -n → pkexec */
static gboolean build_argv(const char *cmd, char *argv[], int *argc)
{
    static char *sudo_path, *pkexec_path;

    if (is_root()) {
        argv[0] = (char *)"/bin/sh";
        argv[1] = (char *)"-c";
        argv[2] = (char *)cmd;
        argv[3] = NULL;
        *argc = 3;
        return TRUE;
    }

    if (sudo_ready()) {
        if (!sudo_path)
            sudo_path = find_tool("sudo");
        argv[0] = sudo_path;
        argv[1] = (char *)"-n";
        argv[2] = (char *)"/bin/sh";
        argv[3] = (char *)"-c";
        argv[4] = (char *)cmd;
        argv[5] = NULL;
        *argc = 5;
        return TRUE;
    }

    if (have_tool("pkexec")) {
        if (!pkexec_path)
            pkexec_path = find_tool("pkexec");
        argv[0] = pkexec_path;
        argv[1] = (char *)"/bin/sh";
        argv[2] = (char *)"-c";
        argv[3] = (char *)cmd;
        argv[4] = NULL;
        *argc = 4;
        return TRUE;
    }

    return FALSE;
}

static void term_run(App *a, const char *cmd)
{
    char *argv[8];
    int argc = 0;
    GPid pid = 0;
    gint out_fd = -1, err_fd = -1;
    GError *ge = NULL;

    if (a->run_pid) {
        term_append(a, "上一条命令还在跑，等它结束\n", "err");
        return;
    }

    if (!build_argv(cmd, argv, &argc)) {
        term_append(a, "没有 root 也不见 sudo / pkexec，"
                       "请直接以 root 启动本程序\n", "err");
        return;
    }

    if (!g_spawn_async_with_pipes(NULL, argv, NULL,
                                  G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD,
                                  NULL, NULL, &pid,
                                  NULL, &out_fd, &err_fd, &ge)) {
        term_append(a, ge ? ge->message : "启动失败", "err");
        term_append(a, "\n", NULL);
        if (ge)
            g_error_free(ge);
        return;
    }

    a->run_pid = pid;
    g_child_watch_add(pid, on_child_exit, a);

    if (out_fd >= 0) {
        GIOChannel *ch = g_io_channel_unix_new(out_fd);

        g_io_channel_set_encoding(ch, NULL, NULL);
        g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR, on_stdout, a);
    }
    if (err_fd >= 0) {
        GIOChannel *ch = g_io_channel_unix_new(err_fd);

        g_io_channel_set_encoding(ch, NULL, NULL);
        g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR, on_stderr, a);
    }

}

static void on_entry_activate(GtkWidget *w, gpointer data)
{
    App *a = data;
    const char *text = gtk_entry_get_text(GTK_ENTRY(w));

    if (!text || !*text) {
        term_append(a, term_prompt_str(), "cmd");
        return;
    }

    if (!strcmp(text, "clear")) {
        term_clear(a);
        gtk_entry_set_text(GTK_ENTRY(w), "");
        return;
    }

    /* 回显：提示符 + 命令 */
    term_append(a, term_prompt_str(), "cmd");
    term_append(a, text, "cmd");
    term_append(a, "\n", NULL);

    /* text 指向 GtkEntry 内部缓冲，必须等 spawn 完成后再清空 */
    term_run(a, text);
    gtk_entry_set_text(GTK_ENTRY(w), "");
}

static void on_run_clicked(GtkWidget *w, gpointer data)
{
    (void)w;
    on_entry_activate(((App *)data)->entry, data);
}

static void on_term_clear(GtkWidget *w, gpointer data)
{
    (void)w;
    term_clear(data);
}

/* --------------------------------------------------------------------------
 * 页面切换
 * ----------------------------------------------------------------------- */

static const char *PAGE_NAMES[TAB_COUNT] = { "home", "super", "term", "set" };

static void switch_page(App *a, int idx)
{
    int i;

    if (idx < 0 || idx >= TAB_COUNT)
        return;

    gtk_stack_set_visible_child_name(GTK_STACK(a->stack), PAGE_NAMES[idx]);
    a->cur = idx;

    for (i = 0; i < TAB_COUNT; i++) {
        gboolean on = (i == idx);
        GtkStyleContext *sc;

        g_object_set_data(G_OBJECT(a->tab_ico[i]), "dim",
                          GINT_TO_POINTER(on ? 0 : 1));
        gtk_widget_queue_draw(a->tab_ico[i]);

        sc = gtk_widget_get_style_context(a->tab_lbl[i]);
        if (on)
            gtk_style_context_add_class(sc, "on");
        else
            gtk_style_context_remove_class(sc, "on");
    }

    if (idx == 0)
        refresh_home(a);
    if (idx == 1)
        refresh_procs(a);
    if (idx == 2 && a->entry)
        gtk_widget_grab_focus(a->entry);
}

static void on_tab(GtkWidget *w, GdkEventButton *ev, gpointer data)
{
    App *a = data;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "idx"));

    (void)ev;
    switch_page(a, idx);
}

/* 点状态卡直接去终端 */
static gboolean on_status_click(GtkWidget *w, GdkEventButton *ev, gpointer data)
{
    (void)w;
    (void)ev;
    switch_page(data, 2);
    return TRUE;
}

/* --------------------------------------------------------------------------
 * 界面
 * ----------------------------------------------------------------------- */

static const char *CSS =
    "window, #shell { background-color: #ededf1; }\n"
    "#bigtitle { color: #1b1b1b; font-size: 30px; font-weight: 500; }\n"
    "#pagetitle { color: #1b1b1b; font-size: 24px; font-weight: 600; }\n"
    "#card { background-color: #ffffff; border-radius: 24px;        border: 1px solid rgba(20,30,50,0.045); }\n"
    "#cardtitle { color: #1b1b1b; font-size: 15px; font-weight: 500; }\n"
    "#cardvalue { color: #6f6f6f; font-size: 13px; }\n"
    "#status_title { color: #1b1b1b; font-size: 17px; font-weight: 500; }\n"
    "#status_sub { color: #6f6f6f; font-size: 13.5px; }\n"
    "#rowlabel { color: #1b1b1b; font-size: 15px; }\n"
    "button { background-image: none; background-color: #e7e7ec;\n"
    "         border: none; border-radius: 20px; padding: 7px 18px;\n"
    "         color: #1b1b1b; font-size: 13px; box-shadow: none;\n"
    "         text-shadow: none; }\n"
    "button:hover { background-color: #dcdce3; }\n"
    "button:active { background-color: #d2d2da; }\n"
    "button:disabled { color: rgba(27,27,27,0.35); background-color: #f0f0f3; }\n"
    "#textbtn { background-color: transparent; padding: 6px 12px;           color: #6f6f6f; font-size: 13px; }\n"
    "#textbtn:hover { background-color: rgba(0,0,0,0.06); }\n"
    "#logview, #logview text { background-color: #fafafc; color: #3a3a3c; }\n"
    "#logscroll, #logscroll viewport { background-color: #fafafc; }\n"
    "#proctree { background-color: #ffffff; -GtkTreeView-vertical-separator: 9; }\n"
    "#proctree:selected, #proctree:selected:focus { background-color: #e7e7ec; color: #1b1b1b; }\n"
    "#tabbar { background-color: #ededf1; border-top: 1px solid rgba(0,0,0,0.075); }\n"
    "#tablbl { color: #8e8e93; font-size: 11.5px; }\n"
    "#tablbl.on { color: #1b1b1b; font-weight: 600; }\n"
    "#term, #term text { background-color: #fafafc; color: #1f1f22;\n"
    "         font-family: \"DejaVu Sans Mono\", \"Noto Sans Mono\", monospace;\n"
    "         font-size: 12.5px; }\n"
    "#termscroll, #termscroll viewport { background-color: #fafafc; }\n"
    "#prompt { color: #1b1b1b; font-family: \"DejaVu Sans Mono\", monospace;\n"
    "          font-size: 12.5px; font-weight: 600; }\n"
    "#cmdline { font-family: \"DejaVu Sans Mono\", monospace; font-size: 12.5px;\n"
    "           background-color: #f4f4f7; border-radius: 12px; padding: 6px 10px; }\n"
    "button.primary { background-color: #1b1b1b; color: #ffffff; }\n"
    "button.primary:hover { background-color: #33333a; }\n";

/* 一张白卡：内盒自己往里塞 */
static GtkWidget *card_new(void)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    gtk_widget_set_name(box, "card");
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);
    return box;
}

/* 状态卡：左图标 + 右两行字 */
static GtkWidget *status_card(App *a)
{
    GtkWidget *c = card_new();
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 18);
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *eb;

    gtk_widget_set_margin_start(row, 22);
    gtk_widget_set_margin_end(row, 22);
    gtk_widget_set_margin_top(row, 22);
    gtk_widget_set_margin_bottom(row, 22);

    a->ico_status = make_icon(IC_ERROR, 30);
    gtk_widget_set_valign(a->ico_status, GTK_ALIGN_START);
    gtk_widget_set_margin_top(a->ico_status, 2);

    a->lbl_status = gtk_label_new("");
    gtk_widget_set_name(a->lbl_status, "status_title");
    gtk_widget_set_halign(a->lbl_status, GTK_ALIGN_START);

    a->lbl_status_sub = gtk_label_new("");
    gtk_widget_set_name(a->lbl_status_sub, "status_sub");
    gtk_widget_set_halign(a->lbl_status_sub, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(a->lbl_status_sub), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(a->lbl_status_sub), 60);

    gtk_box_pack_start(GTK_BOX(col), a->lbl_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(col), a->lbl_status_sub, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), a->ico_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), col, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(c), row, FALSE, FALSE, 0);

    eb = gtk_event_box_new();
    gtk_event_box_set_visible_window(GTK_EVENT_BOX(eb), FALSE);
    gtk_container_add(GTK_CONTAINER(eb), c);
    g_signal_connect(eb, "button-press-event", G_CALLBACK(on_status_click), a);
    return eb;
}

/* 信息行：左图标 + 标题 + 值 */
static GtkWidget *info_row(IconKind kind, const char *label, GtkWidget **val_out)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
    GtkWidget *ico = make_icon(kind, 24);
    GtkWidget *lbl = gtk_label_new(label);
    GtkWidget *val = gtk_label_new("");

    gtk_widget_set_margin_start(row, 22);
    gtk_widget_set_margin_end(row, 22);
    gtk_widget_set_margin_top(row, 14);
    gtk_widget_set_margin_bottom(row, 14);

    gtk_widget_set_valign(ico, GTK_ALIGN_START);
    gtk_widget_set_margin_top(ico, 1);

    gtk_widget_set_name(lbl, "rowlabel");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_widget_set_name(val, "cardvalue");
    gtk_widget_set_halign(val, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(val), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(val), 34);

    gtk_box_pack_start(GTK_BOX(col), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(col), val, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), ico, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), col, TRUE, TRUE, 0);

    *val_out = val;
    return row;
}

/* 卡片里两项之间的淡分隔线 */
static void add_divider(GtkWidget *card)
{
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);

    gtk_widget_set_margin_start(sep, 62);
    gtk_widget_set_margin_end(sep, 22);
    gtk_widget_set_opacity(sep, 0.55);
    gtk_box_pack_start(GTK_BOX(card), sep, FALSE, FALSE, 0);
}

/* 页面大标题 */
static GtkWidget *page_title(const char *text, const char *name)
{
    GtkWidget *lbl = gtk_label_new(text);

    gtk_widget_set_name(lbl, name ? name : "pagetitle");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_widget_set_margin_start(lbl, 14);
    gtk_widget_set_margin_end(lbl, 14);
    gtk_widget_set_margin_bottom(lbl, 10);
    return lbl;
}

static GtkWidget *build_home(App *a)
{
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    GtkWidget *card_info, *card_sys;

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_name(scroll, "shell");

    gtk_widget_set_margin_start(body, 8);
    gtk_widget_set_margin_end(body, 8);
    gtk_widget_set_margin_top(body, 8);
    gtk_widget_set_margin_bottom(body, 20);

    gtk_box_pack_start(GTK_BOX(body), page_title(APP_TITLE, "bigtitle"),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(body), status_card(a), FALSE, FALSE, 0);

    card_info = card_new();
    gtk_box_pack_start(GTK_BOX(card_info),
                       info_row(IC_HASH, "管理器版本", &a->val_mgr), FALSE, FALSE, 0);
    add_divider(card_info);
    gtk_box_pack_start(GTK_BOX(card_info),
                       info_row(IC_CHIP, "内核版本", &a->val_kernel), FALSE, FALSE, 0);
    gtk_widget_set_margin_top(card_info, 4);
    gtk_widget_set_margin_bottom(card_info, 4);

    card_sys = card_new();
    gtk_box_pack_start(GTK_BOX(card_sys),
                       info_row(IC_SHIELD, "SELinux 状态", &a->val_selinux), FALSE, FALSE, 0);
    add_divider(card_sys);
    gtk_box_pack_start(GTK_BOX(card_sys),
                       info_row(IC_FILTER, "Seccomp 状态", &a->val_seccomp), FALSE, FALSE, 0);

    /* 横屏：版本卡和系统卡并排两列 */
    {
        GtkWidget *cols = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

        gtk_box_pack_start(GTK_BOX(cols), left, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(cols), right, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(left), card_info, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(right), card_sys, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(body), cols, FALSE, FALSE, 0);
    }

    gtk_container_add(GTK_CONTAINER(scroll), body);
    return scroll;
}

/* 超级用户页：当前用户的 shell 进程（只读） */
static GtkWidget *build_super(App *a)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *card, *cbody, *h, *lbl, *sub, *btn, *scroll;
    GtkWidget *tree;

    gtk_widget_set_margin_start(box, 8);
    gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 12);

    gtk_box_pack_start(GTK_BOX(box), page_title("超级用户", NULL), FALSE, FALSE, 0);

    card = card_new();
    gtk_widget_set_vexpand(card, TRUE);
    cbody = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(cbody, 10);
    gtk_widget_set_margin_end(cbody, 10);
    gtk_widget_set_margin_top(cbody, 14);
    gtk_widget_set_margin_bottom(cbody, 14);

    h = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    lbl = gtk_label_new("当前用户的进程");
    sub = gtk_label_new(user_name(getuid()));
    btn = gtk_button_new_with_label("刷新");
    gtk_widget_set_name(lbl, "cardtitle");
    gtk_widget_set_name(sub, "cardvalue");
    gtk_widget_set_name(btn, "textbtn");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_widget_set_valign(sub, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(btn, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(h), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), sub, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(h), btn, FALSE, FALSE, 0);
    gtk_widget_set_margin_start(h, 10);
    gtk_box_pack_start(GTK_BOX(cbody), h, FALSE, FALSE, 0);

    scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);

    a->store = gtk_list_store_new(COL_N, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING);
    tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(a->store));
    a->tree = tree;
    gtk_widget_set_name(tree, "proctree");
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(tree), FALSE);
    gtk_tree_view_set_enable_search(GTK_TREE_VIEW(tree), FALSE);

    {
        GtkCellRenderer *r;
        GtkTreeViewColumn *c;

        r = gtk_cell_renderer_text_new();
        g_object_set(r, "weight", PANGO_WEIGHT_BOLD, "xpad", 10, NULL);
        c = gtk_tree_view_column_new_with_attributes("pid", r, "text", COL_PID, NULL);
        gtk_tree_view_column_set_min_width(c, 78);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), c);

        r = gtk_cell_renderer_text_new();
        g_object_set(r, "xpad", 10, NULL);
        c = gtk_tree_view_column_new_with_attributes("user", r, "text", COL_USER, NULL);
        gtk_tree_view_column_set_min_width(c, 84);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), c);

        r = gtk_cell_renderer_text_new();
        g_object_set(r, "ellipsize", PANGO_ELLIPSIZE_END, "xpad", 10, NULL);
        c = gtk_tree_view_column_new_with_attributes("cmd", r, "text", COL_CMD, NULL);
        gtk_tree_view_column_set_expand(c, TRUE);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), c);
    }

    gtk_container_add(GTK_CONTAINER(scroll), tree);
    gtk_box_pack_start(GTK_BOX(cbody), scroll, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(card), cbody, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), card, TRUE, TRUE, 0);

    {
        GtkWidget *hint = gtk_label_new("这里是 /proc 里属于当前用户的 shell 进程，仅供查看。");
        gtk_widget_set_name(hint, "cardvalue");
        gtk_widget_set_halign(hint, GTK_ALIGN_START);
        gtk_widget_set_margin_start(hint, 14);
        gtk_box_pack_start(GTK_BOX(box), hint, FALSE, FALSE, 0);
    }

    g_signal_connect_swapped(btn, "clicked", G_CALLBACK(refresh_procs), a);
    return box;
}

/* 终端页：一行输入 + 输出区 */
static GtkWidget *build_term(App *a)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *card, *cbody, *h, *lbl, *btn_clear;
    GtkWidget *scroll, *line, *btn_run;

    gtk_widget_set_margin_start(box, 8);
    gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 12);

    gtk_box_pack_start(GTK_BOX(box), page_title("终端", NULL), FALSE, FALSE, 0);

    card = card_new();
    gtk_widget_set_vexpand(card, TRUE);
    cbody = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(cbody, 14);
    gtk_widget_set_margin_end(cbody, 14);
    gtk_widget_set_margin_top(cbody, 14);
    gtk_widget_set_margin_bottom(cbody, 14);

    h = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    lbl = gtk_label_new("输出");
    gtk_widget_set_name(lbl, "cardtitle");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_widget_set_valign(lbl, GTK_ALIGN_CENTER);

    btn_clear = gtk_button_new_with_label("清屏");
    gtk_widget_set_name(btn_clear, "textbtn");
    gtk_widget_set_valign(btn_clear, GTK_ALIGN_CENTER);

    gtk_box_pack_start(GTK_BOX(h), lbl, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(h), btn_clear, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(cbody), h, FALSE, FALSE, 0);

    scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_name(scroll, "termscroll");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);

    a->termbuf = gtk_text_buffer_new(NULL);
    gtk_text_buffer_create_tag(a->termbuf, "cmd",
                               "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(a->termbuf, "err",
                               "foreground", "#c0392b", NULL);
    gtk_text_buffer_create_tag(a->termbuf, "dim",
                               "foreground", "#8e8e93", NULL);

    a->termview = gtk_text_view_new_with_buffer(a->termbuf);
    gtk_widget_set_name(a->termview, "term");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(a->termview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(a->termview), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(a->termview), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(a->termview), 10);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(a->termview), 10);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(a->termview), 8);
    gtk_container_add(GTK_CONTAINER(scroll), a->termview);
    gtk_box_pack_start(GTK_BOX(cbody), scroll, TRUE, TRUE, 0);

    /* 输入行：提示符 + 输入框 + 运行 */
    line = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    a->prompt = gtk_label_new(term_prompt_str());
    gtk_widget_set_name(a->prompt, "prompt");
    gtk_widget_set_valign(a->prompt, GTK_ALIGN_CENTER);

    a->entry = gtk_entry_new();
    gtk_widget_set_name(a->entry, "cmdline");
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry), "输入命令后回车，例如 id / ls -l / whoami");
    gtk_widget_set_hexpand(a->entry, TRUE);
    gtk_widget_set_valign(a->entry, GTK_ALIGN_CENTER);

    btn_run = gtk_button_new_with_label("运行");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_run), "primary");
    gtk_widget_set_valign(btn_run, GTK_ALIGN_CENTER);

    gtk_box_pack_start(GTK_BOX(line), a->prompt, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(line), a->entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(line), btn_run, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(cbody), line, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(card), cbody, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), card, TRUE, TRUE, 0);

    g_signal_connect(a->entry, "activate", G_CALLBACK(on_entry_activate), a);
    g_signal_connect(btn_run, "clicked", G_CALLBACK(on_run_clicked), a);
    g_signal_connect(btn_clear, "clicked", G_CALLBACK(on_term_clear), a);
    return box;
}

/* 设置页：运行身份 + 说明 */
static GtkWidget *build_settings(App *a)
{
    GtkWidget *box;

    (void)a;
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *card_id, *card_about, *cbody, *lbl, *hint;
    GtkWidget *v_uid, *v_euid, *v_sudo, *v_pk;

    gtk_widget_set_margin_start(box, 8);
    gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 12);

    gtk_box_pack_start(GTK_BOX(box), page_title("设置", NULL), FALSE, FALSE, 0);

    card_id = card_new();
    gtk_box_pack_start(GTK_BOX(card_id),
                       info_row(IC_SHIELD, "当前用户", &v_uid), FALSE, FALSE, 0);
    add_divider(card_id);
    gtk_box_pack_start(GTK_BOX(card_id),
                       info_row(IC_CHECK, "有效用户（euid）", &v_euid), FALSE, FALSE, 0);
    add_divider(card_id);
    gtk_box_pack_start(GTK_BOX(card_id),
                       info_row(IC_HASH, "sudo -n", &v_sudo), FALSE, FALSE, 0);
    add_divider(card_id);
    gtk_box_pack_start(GTK_BOX(card_id),
                       info_row(IC_CHIP, "pkexec", &v_pk), FALSE, FALSE, 0);

    gtk_label_set_text(GTK_LABEL(v_uid), user_name(getuid()));
    gtk_label_set_text(GTK_LABEL(v_euid),
                       is_root() ? "root（命令直接以 root 执行）"
                                 : user_name(geteuid()));
    gtk_label_set_text(GTK_LABEL(v_sudo),
                       sudo_ready() ? "可用（免密）" : "不可用（需要密码或未安装）");
    gtk_label_set_text(GTK_LABEL(v_pk),
                       have_tool("pkexec") ? "可用（执行时弹密码框）" : "未安装");

    card_about = card_new();
    cbody = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(cbody, 22);
    gtk_widget_set_margin_end(cbody, 22);
    gtk_widget_set_margin_top(cbody, 18);
    gtk_widget_set_margin_bottom(cbody, 18);

    lbl = gtk_label_new("关于");
    gtk_widget_set_name(lbl, "cardtitle");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);

    hint = gtk_label_new("RootMgr " MGR_VERSION "　\n"
                         "「终端」页直接调 /bin/sh -c 执行命令：以 root 运行时就是 "
                         "root 权限，否则先试 sudo -n，再退到 pkexec。\n"
                         "想要每次都免密，可以给 sudo 配 NOPASSWD，"
                         "或者直接用 root 启动本程序。");
    gtk_widget_set_name(hint, "cardvalue");
    gtk_widget_set_halign(hint, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(hint), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(hint), 36);

    gtk_box_pack_start(GTK_BOX(cbody), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(cbody), hint, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(card_about), cbody, FALSE, FALSE, 0);

    /* 横屏：两张卡并排 */
    {
        GtkWidget *cols = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

        gtk_box_pack_start(GTK_BOX(cols), card_id, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(cols), right, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(right), card_about, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), cols, FALSE, FALSE, 0);
    }

    return box;
}

/* 底部栏一格：图标 + 文字 */
static GtkWidget *tab_item(App *a, int idx, IconKind kind, const char *text)
{
    GtkWidget *eb = gtk_event_box_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *ico = make_icon(kind, 24);
    GtkWidget *lbl = gtk_label_new(text);

    gtk_event_box_set_visible_window(GTK_EVENT_BOX(eb), FALSE);
    gtk_widget_set_hexpand(eb, TRUE);

    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 8);

    gtk_widget_set_halign(ico, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(ico, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(lbl, GTK_ALIGN_CENTER);
    gtk_widget_set_name(lbl, "tablbl");

    gtk_box_pack_start(GTK_BOX(box), ico, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(eb), box);

    a->tab_ico[idx] = ico;
    a->tab_lbl[idx] = lbl;
    g_object_set_data(G_OBJECT(eb), "idx", GINT_TO_POINTER(idx));
    g_signal_connect(eb, "button-press-event", G_CALLBACK(on_tab), a);
    return eb;
}

static GtkWidget *build_tabbar(App *a)
{
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    gtk_widget_set_name(bar, "tabbar");
    gtk_box_pack_start(GTK_BOX(bar), tab_item(a, 0, IC_T_HOME, "主页"), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(bar), tab_item(a, 1, IC_T_SHIELD, "超级用户"), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(bar), tab_item(a, 2, IC_T_TERM, "终端"), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(bar), tab_item(a, 3, IC_T_GEAR, "设置"), TRUE, TRUE, 0);
    return bar;
}

static void build_ui(App *a)
{
    GtkCssProvider *css;
    GtkWidget *shell;

    a->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(a->win), "RootMgr");
    gtk_window_set_default_size(GTK_WINDOW(a->win), 960, 600);
    gtk_window_set_position(GTK_WINDOW(a->win), GTK_WIN_POS_CENTER);
    g_signal_connect(a->win, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);

    shell = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(a->win), shell);

    a->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(a->stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_set_transition_duration(GTK_STACK(a->stack), 120);
    gtk_widget_set_vexpand(a->stack, TRUE);
    gtk_box_pack_start(GTK_BOX(shell), a->stack, TRUE, TRUE, 0);

    gtk_stack_add_named(GTK_STACK(a->stack), build_home(a), "home");
    gtk_stack_add_named(GTK_STACK(a->stack), build_super(a), "super");
    gtk_stack_add_named(GTK_STACK(a->stack), build_term(a), "term");
    gtk_stack_add_named(GTK_STACK(a->stack), build_settings(a), "set");

    gtk_box_pack_end(GTK_BOX(shell), build_tabbar(a), FALSE, FALSE, 0);

    gtk_widget_show_all(a->win);
    switch_page(a, 0);
}

int main(int argc, char **argv)
{
    App a;

    memset(&a, 0, sizeof(a));
    gtk_init(&argc, &argv);

    build_ui(&a);

    refresh_home(&a);
    refresh_procs(&a);

    term_append(&a, "RootMgr " MGR_VERSION " 终端\n", "dim");
    if (is_root())
        term_append(&a, "当前是 root，命令直接以 root 执行。\n\n", "dim");
    else
        term_append(&a, "当前不是 root，命令会走 sudo -n / pkexec。\n\n", "dim");

    gtk_main();
    return 0;
}
