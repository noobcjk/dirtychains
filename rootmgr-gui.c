/*
 * rootmgr-gui.c —— 常驻 root 管理器的图形界面
 *
 * 版式参照 KernelSU 首页（Material 3）：浅灰底、大标题、白色圆角卡片、
 * 左侧线性图标 + 标题/副标题两行。首页只放状态信息，功能收进「管理」页。
 *
 * 配合 tools/kmod/rootmgr.c 使用：
 *   1) 把 rootmgr.ko 放到本程序同目录（或 tools/kmod/ 下）；
 *   2) 点「加载模块」，root 身份直跑 insmod，否则走 pkexec / sudo -n；
 *   3) 管理页列出当前用户自己的 shell 进程；
 *   4) 选中一个点「提权选中进程」，该进程的 uid 立刻变成 0。
 *
 * 构建：
 *   make rootmgr-gui
 */

#include <gtk/gtk.h>
#include <cairo.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#define PROC_PATH   "/proc/rootmgr"
#define APP_TITLE   "RootMgr"
#define MGR_VERSION "1.0"

/* 图标种类：全部用 cairo 画，不依赖图标字体 / 主题 */
typedef enum {
    IC_ERROR = 0,   /* 圆圈感叹号 */
    IC_CHECK,       /* 圆圈对勾 */
    IC_HASH,        /* # 号 */
    IC_CHIP,        /* 芯片 */
    IC_SHIELD,      /* 盾牌 */
    IC_FILTER       /* 三条横线 */
} IconKind;

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

    /* 管理页 */
    GtkWidget *ko_label;
    GtkWidget *list;        /* 进程列表 */
    GtkWidget *logview;
    GtkWidget *btn_give;

    char *ko_path;
    int   sel_pid;
} App;

/* --------------------------------------------------------------------------
 * 小工具
 * ----------------------------------------------------------------------- */

static char *exe_dir(void)
{
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);

    if (n <= 0)
        return g_strdup(".");
    buf[n] = '\0';
    return g_path_get_dirname(buf);
}

static gboolean module_loaded(void)
{
    return g_file_test(PROC_PATH, G_FILE_TEST_EXISTS);
}

static const char *user_name(uid_t uid)
{
    static char buf[32];
    struct passwd *pw = getpwuid(uid);

    if (pw)
        return pw->pw_name;
    g_snprintf(buf, sizeof(buf), "%u", (unsigned)uid);
    return buf;
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
 * 日志
 * ----------------------------------------------------------------------- */

static void log_line(App *a, const char *fmt, ...)
{
    GtkTextBuffer *tb;
    GtkTextIter end;
    va_list ap;
    char *msg;

    if (!a->logview)
        return;

    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->logview));
    gtk_text_buffer_get_end_iter(tb, &end);
    gtk_text_buffer_insert(tb, &end, msg, -1);
    g_free(msg);

    gtk_text_buffer_get_end_iter(tb, &end);
    gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(a->logview), &end, 0, FALSE, 0, 0);
}

static void log_reset(App *a)
{
    GtkTextBuffer *tb;

    if (!a->logview)
        return;
    tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->logview));
    gtk_text_buffer_set_text(tb, "", -1);
}

/* --------------------------------------------------------------------------
 * 状态
 * ----------------------------------------------------------------------- */

static void refresh_home(App *a)
{
    gboolean on = module_loaded();
    char buf[128];

    icon_set_kind(a->ico_status, on ? IC_CHECK : IC_ERROR);
    gtk_label_set_text(GTK_LABEL(a->lbl_status), on ? "运行中" : "尚未启动");
    gtk_label_set_text(GTK_LABEL(a->lbl_status_sub),
                       on ? "rootmgr 模块已加载，可以直接给进程提权。"
                          : "rootmgr 模块还没加载。点右上角「管理」加载模块后即可使用。");

    g_snprintf(buf, sizeof(buf), "%s (%s)", MGR_VERSION,
               on ? "rootmgr" : "未加载");
    gtk_label_set_text(GTK_LABEL(a->val_mgr), buf);
    gtk_label_set_text(GTK_LABEL(a->val_kernel), kernel_release());
    gtk_label_set_text(GTK_LABEL(a->val_selinux), selinux_text());
    gtk_label_set_text(GTK_LABEL(a->val_seccomp), seccomp_text());
}

static void refresh_state(App *a)
{
    refresh_home(a);
    gtk_widget_set_sensitive(a->btn_give, module_loaded());
}

/* 只列出当前用户自己的、常见的 shell 进程 */
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

static void add_row(App *a, int pid, const char *user, const char *cmd)
{
    GtkWidget *row, *box, *l1, *l2, *l3;

    row = gtk_list_box_row_new();
    box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_start(box, 14);
    gtk_widget_set_margin_end(box, 14);
    gtk_widget_set_margin_top(box, 9);
    gtk_widget_set_margin_bottom(box, 9);

    l1 = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(l1), g_strdup_printf("<b>%d</b>", pid));
    gtk_widget_set_size_request(l1, 62, -1);
    gtk_widget_set_halign(l1, GTK_ALIGN_START);

    l2 = gtk_label_new(user);
    gtk_widget_set_size_request(l2, 76, -1);
    gtk_widget_set_halign(l2, GTK_ALIGN_START);

    l3 = gtk_label_new(cmd);
    gtk_widget_set_halign(l3, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(l3), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(l3, TRUE);

    gtk_box_pack_start(GTK_BOX(box), l1, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), l2, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), l3, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(row), box);

    g_object_set_data(G_OBJECT(row), "pid", GINT_TO_POINTER(pid));
    gtk_container_add(GTK_CONTAINER(a->list), row);
}

static void refresh_procs(App *a)
{
    GtkListBoxRow *row;
    DIR *d;
    struct dirent *de;
    uid_t me = getuid();

    if (!a->list)
        return;

    while ((row = gtk_list_box_get_row_at_index(GTK_LIST_BOX(a->list), 0)))
        gtk_widget_destroy(GTK_WIDGET(row));
    a->sel_pid = 0;

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

        add_row(a, atoi(de->d_name), user_name(me), cmd);
    }
    closedir(d);

    gtk_widget_show_all(a->list);
}

/* --------------------------------------------------------------------------
 * 动作
 * ----------------------------------------------------------------------- */

static void on_refresh(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    log_reset(a);
    refresh_state(a);
    refresh_procs(a);
    log_line(a, "刷新：模块%s\n", module_loaded() ? "已加载" : "未加载");
}

static void run_priv(App *a, const char *const *argv, const char *what)
{
    char *out = NULL, *err = NULL;
    GError *ge = NULL;
    gint st = -1;
    gboolean ok;

    log_line(a, "> %s\n", what);
    ok = g_spawn_sync(NULL, (char **)argv, NULL, G_SPAWN_SEARCH_PATH,
                      NULL, NULL, &out, &err, &st, &ge);
    if (!ok) {
        log_line(a, "  启动失败: %s\n", ge ? ge->message : "未知");
        if (ge)
            g_error_free(ge);
        g_free(out);
        g_free(err);
        return;
    }

    if (out && *out)
        log_line(a, "%s", out);
    if (err && *err)
        log_line(a, "%s", err);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        log_line(a, "  退出码 %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    else
        log_line(a, "  完成\n");

    g_free(out);
    g_free(err);
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

/*
 * 统一执行 insmod / rmmod。
 *
 * 身份为 root 时直接跑，不再套 pkexec —— 否则在没有 polkit 的机器上
 * 会先报 "Failed to execute child process"，明明已经有权限却跑不动。
 */
static void do_module_op(App *a, const char *op, const char *arg)
{
    const char *av[6];
    char *tool = find_tool(op);
    char *pkexec = find_tool("pkexec");
    char *sudo = find_tool("sudo");
    char *what = NULL;
    int n = 0;

    if (geteuid() == 0) {
        av[n++] = tool;
        av[n++] = arg;
        what = g_strdup_printf("%s %s  (root 直接执行)", op, arg);
    } else if (g_file_test(pkexec, G_FILE_TEST_IS_EXECUTABLE)) {
        av[n++] = pkexec;
        av[n++] = tool;
        av[n++] = arg;
        what = g_strdup_printf("%s %s  (pkexec)", op, arg);
    } else if (g_file_test(sudo, G_FILE_TEST_IS_EXECUTABLE)) {
        av[n++] = sudo;
        av[n++] = "-n";
        av[n++] = tool;
        av[n++] = arg;
        what = g_strdup_printf("%s %s  (sudo -n)", op, arg);
    } else {
        log_line(a, "当前不是 root，也找不到 pkexec / sudo\n"
                    "  可以先切到 root 再运行本程序，或在终端执行：\n"
                    "    sudo %s %s\n", tool, arg);
        goto out;
    }
    av[n] = NULL;

    run_priv(a, av, what);

out:
    g_free(what);
    g_free(tool);
    g_free(pkexec);
    g_free(sudo);
}

static void on_load(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    log_reset(a);

    if (!a->ko_path || !g_file_test(a->ko_path, G_FILE_TEST_EXISTS)) {
        log_line(a, "找不到 rootmgr.ko\n"
                    "  把它放到本程序同目录，或先执行 make rootmgr\n");
        return;
    }

    do_module_op(a, "insmod", a->ko_path);

    refresh_state(a);
    refresh_procs(a);
}

static void on_unload(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    log_reset(a);

    if (!module_loaded()) {
        log_line(a, "模块未加载，无需卸载\n");
        return;
    }

    do_module_op(a, "rmmod", "rootmgr");

    refresh_state(a);
    refresh_procs(a);
}

static void on_row_selected(GtkListBox *lb, GtkListBoxRow *row, gpointer data)
{
    App *a = data;

    (void)lb;
    a->sel_pid = row ? GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "pid")) : 0;
    gtk_widget_set_sensitive(a->btn_give, a->sel_pid > 0 && module_loaded());
}

static void on_give(GtkWidget *w, gpointer data)
{
    App *a = data;
    char cmd[64];
    int fd;
    ssize_t wr;

    (void)w;
    log_reset(a);

    if (a->sel_pid <= 0) {
        log_line(a, "先在上面选一个进程\n");
        return;
    }
    if (!module_loaded()) {
        log_line(a, "模块未加载，先点「加载模块」\n");
        return;
    }

    g_snprintf(cmd, sizeof(cmd), "give %d", a->sel_pid);

    /* proc 文件不能用 g_file_set_contents: 它带 O_CREAT|O_TRUNC，procfs 会拒绝 */
    fd = open(PROC_PATH, O_WRONLY);
    if (fd < 0) {
        log_line(a, "打开 %s 失败: %s\n", PROC_PATH, g_strerror(errno));
        return;
    }

    wr = write(fd, cmd, strlen(cmd));
    if (wr < 0 || (size_t)wr != strlen(cmd)) {
        int e = errno;

        close(fd);
        log_line(a, "写 %s 失败: %s\n", PROC_PATH, g_strerror(e));
        return;
    }
    close(fd);

    log_line(a, "已提交: %s\n"
                "  到那个进程的终端里执行 id，应看到 uid=0(root)\n", cmd);

    refresh_state(a);
}

/* 页面切换 */
static void on_manage(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    gtk_stack_set_visible_child_name(GTK_STACK(a->stack), "manage");
    refresh_state(a);
    refresh_procs(a);
}

static void on_back(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    refresh_state(a);
    gtk_stack_set_visible_child_name(GTK_STACK(a->stack), "home");
}

/* --------------------------------------------------------------------------
 * 界面
 * ----------------------------------------------------------------------- */

static const char *CSS =
    "window, #shell { background-color: #ededf1; }\n"
    "#bigtitle { color: #1b1b1b; font-size: 30px; font-weight: 500; }\n"
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
    "#listbox { background-color: #ffffff; padding: 0; }\n"
    "#listbox row { border-radius: 12px; padding: 0; }\n"
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

static void on_manage(GtkWidget *w, gpointer data);

/* 点状态卡等同点「管理」，和 KernelSU 首页一致 */
static gboolean on_status_click(GtkWidget *w, GdkEventButton *ev, gpointer data)
{
    (void)w;
    (void)ev;
    on_manage(NULL, data);
    return TRUE;
}

/* 状态卡：左图标 + 右两行字 */
static GtkWidget *status_card(App *a)
{
    GtkWidget *c = card_new();
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 18);
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    gtk_widget_set_margin_start(row, 22);
    gtk_widget_set_margin_end(row, 22);
    gtk_widget_set_margin_top(row, 22);
    gtk_widget_set_margin_bottom(row, 22);

    a->ico_status = make_icon(IC_ERROR, 30);
    gtk_widget_set_valign(a->ico_status, GTK_ALIGN_START);
    gtk_widget_set_margin_top(a->ico_status, 2);

    a->lbl_status = gtk_label_new("尚未启动");
    gtk_widget_set_name(a->lbl_status, "status_title");
    gtk_widget_set_halign(a->lbl_status, GTK_ALIGN_START);

    a->lbl_status_sub = gtk_label_new("");
    gtk_widget_set_name(a->lbl_status_sub, "status_sub");
    gtk_widget_set_halign(a->lbl_status_sub, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(a->lbl_status_sub), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(a->lbl_status_sub), 34);

    gtk_box_pack_start(GTK_BOX(col), a->lbl_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(col), a->lbl_status_sub, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), a->ico_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), col, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(c), row, FALSE, FALSE, 0);

    {
        GtkWidget *eb = gtk_event_box_new();

        gtk_event_box_set_visible_window(GTK_EVENT_BOX(eb), FALSE);
        gtk_container_add(GTK_CONTAINER(eb), c);
        g_signal_connect(eb, "button-press-event", G_CALLBACK(on_status_click), a);
        return eb;
    }
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
    gtk_label_set_max_width_chars(GTK_LABEL(val), 40);

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

static GtkWidget *build_home(App *a)
{
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    GtkWidget *card_info, *card_sys;
    GtkWidget *title_row, *title, *btn_manage;

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_name(scroll, "shell");

    gtk_widget_set_margin_start(body, 8);
    gtk_widget_set_margin_end(body, 8);
    gtk_widget_set_margin_top(body, 8);
    gtk_widget_set_margin_bottom(body, 20);

    /* 大标题 + 右上角「管理」 */
    title_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_start(title_row, 14);
    gtk_widget_set_margin_end(title_row, 8);
    gtk_widget_set_margin_bottom(title_row, 10);

    title = gtk_label_new(APP_TITLE);
    gtk_widget_set_name(title, "bigtitle");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_set_valign(title, GTK_ALIGN_CENTER);

    btn_manage = gtk_button_new_with_label("管理");
    gtk_widget_set_name(btn_manage, "textbtn");
    gtk_widget_set_valign(btn_manage, GTK_ALIGN_CENTER);
    g_signal_connect(btn_manage, "clicked", G_CALLBACK(on_manage), a);

    gtk_box_pack_start(GTK_BOX(title_row), title, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(title_row), btn_manage, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(body), title_row, FALSE, FALSE, 0);

    /* 状态卡 */
    gtk_box_pack_start(GTK_BOX(body), status_card(a), FALSE, FALSE, 0);

    /* 版本信息卡 */
    card_info = card_new();
    gtk_box_pack_start(GTK_BOX(card_info),
                       info_row(IC_HASH, "管理器版本", &a->val_mgr), FALSE, FALSE, 0);
    add_divider(card_info);
    gtk_box_pack_start(GTK_BOX(card_info),
                       info_row(IC_CHIP, "内核版本", &a->val_kernel), FALSE, FALSE, 0);
    gtk_widget_set_margin_top(card_info, 4);
    gtk_widget_set_margin_bottom(card_info, 4);
    gtk_box_pack_start(GTK_BOX(body), card_info, FALSE, FALSE, 0);

    /* 系统状态卡 */
    card_sys = card_new();
    gtk_box_pack_start(GTK_BOX(card_sys),
                       info_row(IC_SHIELD, "SELinux 状态", &a->val_selinux), FALSE, FALSE, 0);
    add_divider(card_sys);
    gtk_box_pack_start(GTK_BOX(card_sys),
                       info_row(IC_FILTER, "Seccomp 状态", &a->val_seccomp), FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(body), card_sys, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(scroll), body);
    return scroll;
}

static GtkWidget *build_manage(App *a)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *head, *title, *btn_back;
    GtkWidget *card_mod, *card_proc, *card_log;
    GtkWidget *btn_row, *btn_refresh, *btn_load, *btn_unload;
    GtkWidget *cbody, *scroll, *logscroll;

    gtk_widget_set_margin_start(box, 8);
    gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 12);

    head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_margin_start(head, 6);
    gtk_widget_set_margin_bottom(head, 2);

    btn_back = gtk_button_new_with_label("‹ 返回");
    gtk_widget_set_name(btn_back, "textbtn");
    g_signal_connect(btn_back, "clicked", G_CALLBACK(on_back), a);

    title = gtk_label_new("管理");
    gtk_widget_set_name(title, "cardtitle");
    gtk_widget_set_valign(title, GTK_ALIGN_CENTER);

    gtk_box_pack_start(GTK_BOX(head), btn_back, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(head), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), head, FALSE, FALSE, 0);

    /* 模块卡 */
    card_mod = card_new();
    cbody = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(cbody, 22);
    gtk_widget_set_margin_end(cbody, 22);
    gtk_widget_set_margin_top(cbody, 18);
    gtk_widget_set_margin_bottom(cbody, 18);

    a->ko_label = gtk_label_new("");
    gtk_widget_set_name(a->ko_label, "cardvalue");
    gtk_widget_set_halign(a->ko_label, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(a->ko_label), PANGO_ELLIPSIZE_MIDDLE);

    btn_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    btn_refresh = gtk_button_new_with_label("刷新");
    btn_load = gtk_button_new_with_label("加载模块");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_load), "primary");
    btn_unload = gtk_button_new_with_label("卸载模块");
    gtk_box_pack_start(GTK_BOX(btn_row), btn_load, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_row), btn_unload, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_row), btn_refresh, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(cbody), a->ko_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(cbody), btn_row, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(card_mod), cbody, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), card_mod, FALSE, FALSE, 0);

    /* 进程卡 */
    card_proc = card_new();
    gtk_widget_set_vexpand(card_proc, TRUE);
    cbody = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(cbody, 12);
    gtk_widget_set_margin_end(cbody, 12);
    gtk_widget_set_margin_top(cbody, 14);
    gtk_widget_set_margin_bottom(cbody, 14);

    {
        GtkWidget *h = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *lbl = gtk_label_new("可提权进程");
        GtkWidget *sub = gtk_label_new("当前用户");
        gtk_widget_set_name(lbl, "cardtitle");
        gtk_widget_set_name(sub, "cardvalue");
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);
        gtk_widget_set_valign(sub, GTK_ALIGN_CENTER);
        gtk_box_pack_start(GTK_BOX(h), lbl, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(h), sub, FALSE, FALSE, 0);
        gtk_widget_set_margin_start(h, 10);
        gtk_box_pack_start(GTK_BOX(cbody), h, FALSE, FALSE, 0);
    }

    scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    a->list = gtk_list_box_new();
    gtk_widget_set_name(a->list, "listbox");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(a->list), GTK_SELECTION_SINGLE);
    g_signal_connect(a->list, "row-selected", G_CALLBACK(on_row_selected), a);
    gtk_container_add(GTK_CONTAINER(scroll), a->list);
    gtk_box_pack_start(GTK_BOX(cbody), scroll, TRUE, TRUE, 0);

    a->btn_give = gtk_button_new_with_label("提权选中进程");
    gtk_widget_set_halign(a->btn_give, GTK_ALIGN_END);
    gtk_widget_set_sensitive(a->btn_give, FALSE);
    gtk_box_pack_start(GTK_BOX(cbody), a->btn_give, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(card_proc), cbody, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), card_proc, TRUE, TRUE, 0);

    /* 日志卡 */
    card_log = card_new();
    cbody = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(cbody, 14);
    gtk_widget_set_margin_end(cbody, 14);
    gtk_widget_set_margin_top(cbody, 14);
    gtk_widget_set_margin_bottom(cbody, 14);

    {
        GtkWidget *lbl = gtk_label_new("输出");
        gtk_widget_set_name(lbl, "cardtitle");
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);
        gtk_box_pack_start(GTK_BOX(cbody), lbl, FALSE, FALSE, 0);
    }

    logscroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_name(logscroll, "logscroll");
    gtk_widget_set_size_request(logscroll, -1, 96);
    a->logview = gtk_text_view_new();
    gtk_widget_set_name(a->logview, "logview");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(a->logview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(a->logview), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(a->logview), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(logscroll), a->logview);
    gtk_box_pack_start(GTK_BOX(cbody), logscroll, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(card_log), cbody, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), card_log, FALSE, FALSE, 0);

    g_signal_connect(btn_refresh, "clicked", G_CALLBACK(on_refresh), a);
    g_signal_connect(btn_load, "clicked", G_CALLBACK(on_load), a);
    g_signal_connect(btn_unload, "clicked", G_CALLBACK(on_unload), a);
    g_signal_connect(a->btn_give, "clicked", G_CALLBACK(on_give), a);

    return box;
}

static void build_ui(App *a)
{
    GtkCssProvider *css;

    a->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(a->win), "RootMgr");
    gtk_window_set_default_size(GTK_WINDOW(a->win), 440, 720);
    gtk_window_set_position(GTK_WINDOW(a->win), GTK_WIN_POS_CENTER);
    g_signal_connect(a->win, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);

    a->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(a->stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_set_transition_duration(GTK_STACK(a->stack), 120);
    gtk_container_add(GTK_CONTAINER(a->win), a->stack);

    gtk_stack_add_named(GTK_STACK(a->stack), build_home(a), "home");
    gtk_stack_add_named(GTK_STACK(a->stack), build_manage(a), "manage");
    gtk_stack_set_visible_child_name(GTK_STACK(a->stack), "home");

    gtk_widget_show_all(a->win);
}

int main(int argc, char **argv)
{
    App a;
    char *dir, *p1, *p2;

    memset(&a, 0, sizeof(a));
    gtk_init(&argc, &argv);

    dir = exe_dir();
    p1 = g_build_filename(dir, "rootmgr.ko", NULL);
    p2 = g_build_filename(dir, "tools", "kmod", "rootmgr.ko", NULL);
    if (g_file_test(p1, G_FILE_TEST_EXISTS))
        a.ko_path = p1;
    else if (g_file_test(p2, G_FILE_TEST_EXISTS))
        a.ko_path = p2;
    else
        a.ko_path = p1;

    build_ui(&a);
    gtk_label_set_text(GTK_LABEL(a.ko_label), a.ko_path);

    refresh_state(&a);
    refresh_procs(&a);

    gtk_main();

    g_free(p1);
    g_free(p2);
    g_free(dir);
    return 0;
}
