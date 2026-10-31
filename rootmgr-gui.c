/*
 * rootmgr-gui.c —— 常驻 root 管理器的图形界面
 *
 * 配合 tools/kmod/rootmgr.c 使用：
 *   1) 把 rootmgr.ko 放到本程序同目录（或 tools/kmod/ 下）；
 *   2) 点「加载模块」，走 pkexec/sudo 执行 insmod；
 *   3) 下面的列表会列出当前用户自己的 shell 进程；
 *   4) 选中一个，点「提权选中进程」，该进程的 uid 立刻变成 0
 *      （在它自己的终端里跑 id 就能看到）。
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
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#define PROC_PATH   "/proc/rootmgr"
#define APP_TITLE   "ROOT 管理器"
#define APP_SUB     "late-load · /proc/rootmgr"

typedef struct {
    GtkWidget *win;
    GtkWidget *bg_area;
    GdkPixbuf *bg_pix;

    GtkWidget *badge;       /* 已加载 / 未加载 */
    GtkWidget *ko_label;    /* 模块路径 */
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

/* --------------------------------------------------------------------------
 * 背景
 * ----------------------------------------------------------------------- */

static gboolean on_bg_draw(GtkWidget *w, cairo_t *cr, gpointer data)
{
    App *a = data;
    int ww = gtk_widget_get_allocated_width(w);
    int wh = gtk_widget_get_allocated_height(w);

    cairo_set_source_rgb(cr, 0.937, 0.957, 0.980);
    cairo_paint(cr);
    if (!a->bg_pix)
        return FALSE;

    {
        int iw = gdk_pixbuf_get_width(a->bg_pix);
        int ih = gdk_pixbuf_get_height(a->bg_pix);
        double s = MAX((double)ww / iw, (double)wh / ih);
        double dw = iw * s, dh = ih * s;

        cairo_save(cr);
        cairo_rectangle(cr, 0, 0, ww, wh);
        cairo_clip(cr);
        cairo_translate(cr, (ww - dw) / 2.0, (wh - dh) / 2.0);
        cairo_scale(cr, s, s);
        gdk_cairo_set_source_pixbuf(cr, a->bg_pix, 0, 0);
        cairo_pattern_set_filter(cairo_get_source(cr), CAIRO_FILTER_BILINEAR);
        cairo_paint(cr);
        cairo_restore(cr);

        cairo_set_source_rgba(cr, 0.98, 0.99, 1.0, 0.26);
        cairo_paint(cr);
    }
    return FALSE;
}

static gboolean on_configure(GtkWidget *w, GdkEventConfigure *ev, gpointer data)
{
    App *a = data;

    (void)w;
    (void)ev;
    gtk_widget_queue_draw(a->bg_area);
    return FALSE;
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

    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->logview));
    gtk_text_buffer_get_end_iter(tb, &end);
    gtk_text_buffer_insert(tb, &end, msg, -1);

    {
        GtkTextIter s, e;
        gtk_text_buffer_get_end_iter(tb, &e);
        s = e;
        gtk_text_iter_backward_chars(&s, (int)g_utf8_strlen(msg, -1));
        gtk_text_buffer_apply_tag_by_name(tb, "dim", &s, &e);
    }
    g_free(msg);

    gtk_text_buffer_get_end_iter(tb, &end);
    gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(a->logview), &end, 0, FALSE, 0, 0);
}

static void log_reset(App *a)
{
    GtkTextBuffer *tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->logview));

    gtk_text_buffer_set_text(tb, "", -1);
}

/* --------------------------------------------------------------------------
 * 状态
 * ----------------------------------------------------------------------- */

static void refresh_state(App *a)
{
    gboolean on = module_loaded();
    GtkStyleContext *ctx;

    gtk_label_set_text(GTK_LABEL(a->badge), on ? "已加载" : "未加载");
    ctx = gtk_widget_get_style_context(a->badge);
    gtk_style_context_remove_class(ctx, "badge-on");
    gtk_style_context_remove_class(ctx, "badge-off");
    gtk_style_context_add_class(ctx, on ? "badge-on" : "badge-off");

    gtk_widget_set_sensitive(a->btn_give, on);
}

/* 只列出当前用户自己的、常见的 shell 进程 */
static gboolean is_shell_name(const char *name)
{
    static const char *ok[] = {
        "sh", "bash", "dash", "zsh", "ksh", "ash", "fish",
        "bash", "tmux", "screen", "su", "sudo", "rootmgr-gui"
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
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 8);

    l1 = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(l1),
                         g_strdup_printf("<b>%d</b>", pid));
    gtk_widget_set_size_request(l1, 70, -1);
    gtk_widget_set_halign(l1, GTK_ALIGN_START);

    l2 = gtk_label_new(user);
    gtk_widget_set_size_request(l2, 90, -1);
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

    while ((row = gtk_list_box_get_row_at_index(GTK_LIST_BOX(a->list), 0))) {
        gtk_widget_destroy(GTK_WIDGET(row));
    }
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
            if (!strncmp(buf, "Name:", 5)) {
                g_strlcpy(name, g_strstrip(buf + 5), sizeof(name));
            } else if (!strncmp(buf, "Uid:", 4)) {
                uid = (unsigned)strtoul(buf + 4, NULL, 10);
            }
        }
        fclose(f);

        if (uid != (unsigned)me)
            continue;
        if (!is_shell_name(name))
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

/* --------------------------------------------------------------------------
 * 界面
 * ----------------------------------------------------------------------- */

static const char *CSS =
    "#card { background-color: #ffffff; border-radius: 12px;"
    "        border: 1px solid rgba(160,190,220,0.55); }\n"
    "#cardtitle { color: #3a5a78; font-weight: 600; font-size: 10pt; }\n"
    "#sub { color: #6b8299; font-size: 9pt; }\n"
    "#badge { border-radius: 9px; padding: 2px 10px; font-size: 9pt; }\n"
    ".badge-on { background-color: #d9f2e2; color: #1d7a46; }\n"
    ".badge-off { background-color: #e8edf3; color: #6b7a89; }\n"
    "#procname { color: #22384a; }\n"
    "#logview, #logview text { background-color: #fbfdff; color: #2b3a48; }\n"
    "#logscroll, #logscroll viewport { background-color: #fbfdff; }\n"
    "#listbox { background-color: #ffffff; }\n";

static GtkWidget *card(const char *title, GtkWidget **body_out)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *lbl = gtk_label_new(title);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    gtk_widget_set_name(box, "card");
    gtk_widget_set_name(lbl, "cardtitle");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);
    gtk_widget_set_margin_top(box, 14);
    gtk_widget_set_margin_bottom(box, 14);

    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), body, TRUE, TRUE, 0);
    *body_out = body;
    return box;
}

static void build_ui(App *a)
{
    GtkWidget *overlay, *root, *head, *hbox, *title, *sub;
    GtkWidget *card_mod, *body_mod, *card_proc, *body_proc, *card_log, *body_log;
    GtkWidget *btn_row, *btn_refresh, *btn_load, *btn_unload, *scroll, *logscroll;
    GtkCssProvider *css;

    a->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(a->win), "ROOT 管理器");
    gtk_window_set_default_size(GTK_WINDOW(a->win), 860, 640);
    gtk_window_set_position(GTK_WINDOW(a->win), GTK_WIN_POS_CENTER);
    g_signal_connect(a->win, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);

    overlay = gtk_overlay_new();
    a->bg_area = gtk_drawing_area_new();
    g_signal_connect(a->bg_area, "draw", G_CALLBACK(on_bg_draw), a);
    g_signal_connect(a->win, "configure-event", G_CALLBACK(on_configure), a);
    gtk_container_add(GTK_CONTAINER(overlay), a->bg_area);
    gtk_container_add(GTK_CONTAINER(a->win), overlay);

    root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(root, 16);
    gtk_widget_set_margin_end(root, 16);
    gtk_widget_set_margin_top(root, 14);
    gtk_widget_set_margin_bottom(root, 14);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), root);

    /* 顶部标题 */
    head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
                         "<span size='large' weight='bold'>ROOT 管理器</span>");
    sub = gtk_label_new(APP_SUB);
    gtk_widget_set_name(sub, "sub");
    gtk_widget_set_valign(sub, GTK_ALIGN_CENTER);
    a->badge = gtk_label_new("未加载");
    gtk_widget_set_name(a->badge, "badge");
    gtk_widget_set_valign(a->badge, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(head), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(head), sub, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(head), a->badge, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), head, FALSE, FALSE, 0);

    /* 模块卡片 */
    card_mod = card("内核模块", &body_mod);
    a->ko_label = gtk_label_new("");
    gtk_widget_set_name(a->ko_label, "sub");
    gtk_widget_set_halign(a->ko_label, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(a->ko_label), PANGO_ELLIPSIZE_MIDDLE);
    gtk_box_pack_start(GTK_BOX(body_mod), a->ko_label, FALSE, FALSE, 0);

    btn_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    btn_refresh = gtk_button_new_with_label("刷新");
    btn_load = gtk_button_new_with_label("加载模块");
    btn_unload = gtk_button_new_with_label("卸载模块");
    gtk_box_pack_start(GTK_BOX(btn_row), btn_refresh, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_row), btn_load, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_row), btn_unload, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(body_mod), btn_row, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), card_mod, FALSE, FALSE, 0);

    /* 进程卡片 */
    card_proc = card("可提权进程（当前用户）", &body_proc);
    gtk_widget_set_vexpand(card_proc, TRUE);
    hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_pack_start(GTK_BOX(body_proc), hbox, TRUE, TRUE, 0);

    scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    a->list = gtk_list_box_new();
    gtk_widget_set_name(a->list, "listbox");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(a->list), GTK_SELECTION_SINGLE);
    g_signal_connect(a->list, "row-selected", G_CALLBACK(on_row_selected), a);
    gtk_container_add(GTK_CONTAINER(scroll), a->list);
    gtk_box_pack_start(GTK_BOX(hbox), scroll, TRUE, TRUE, 0);

    a->btn_give = gtk_button_new_with_label("提权选中进程");
    gtk_widget_set_valign(a->btn_give, GTK_ALIGN_START);
    gtk_widget_set_sensitive(a->btn_give, FALSE);
    gtk_box_pack_start(GTK_BOX(hbox), a->btn_give, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), card_proc, TRUE, TRUE, 0);

    /* 日志卡片 */
    card_log = card("输出", &body_log);
    gtk_widget_set_size_request(card_log, -1, 150);
    logscroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_name(logscroll, "logscroll");
    a->logview = gtk_text_view_new();
    gtk_widget_set_name(a->logview, "logview");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(a->logview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(a->logview), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(a->logview), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(logscroll), a->logview);
    gtk_box_pack_start(GTK_BOX(body_log), logscroll, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(root), card_log, FALSE, FALSE, 0);

    {
        GtkTextBuffer *tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->logview));
        gtk_text_buffer_create_tag(tb, "dim", "foreground", "#5a7086", NULL);
    }

    g_signal_connect(btn_refresh, "clicked", G_CALLBACK(on_refresh), a);
    g_signal_connect(btn_load, "clicked", G_CALLBACK(on_load), a);
    g_signal_connect(btn_unload, "clicked", G_CALLBACK(on_unload), a);
    g_signal_connect(a->btn_give, "clicked", G_CALLBACK(on_give), a);

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

    a.bg_pix = gdk_pixbuf_new_from_file(
        g_build_filename(dir, "bg.png", NULL), NULL);

    build_ui(&a);
    gtk_label_set_text(GTK_LABEL(a.ko_label), a.ko_path);

    refresh_state(&a);
    refresh_procs(&a);
    log_line(&a, "模块状态: %s\n", module_loaded() ? "已加载" : "未加载");
    if (!module_loaded())
        log_line(&a, "先点「加载模块」；ko 路径见上方。\n");

    gtk_main();

    if (a.bg_pix)
        g_object_unref(a.bg_pix);
    g_free(p1);
    g_free(p2);
    g_free(dir);
    return 0;
}
