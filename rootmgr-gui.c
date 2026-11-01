/*
 * rootmgr-gui.c —— root 管理器的图形界面
 *
 * 版式参照 KernelSU（Material 3）：浅灰底、大标题、白色圆角卡片。
 * 窗口默认 960x600 横屏，卡片在宽屏下分左右两列，底部是五格切换栏：
 *   主页 / 超级用户 / 终端 / 漏洞 / 设置
 *
 * 超级用户页是一张授权表（仿 KernelSU）：
 *   - 默认是空的，程序在终端里执行时会被登记成「待授权」；
 *   - 点一行展开，里面是 root / 禁止 两个选项；
 *   - 选 root 后内核 exec 钩子生效：该程序每次被 exec 时，新进程的
 *     cred 直接就是 root（等效给文件加了个 setuid 位），不需要程序自己
 *     再要一次权限；
 *   - 记录存在 /var/lib/rootmgr/policy.tsv（非 root 时放用户配置目录），
 *     重启后状态还在；右键可以移除一条记录。
 *
 * 终端页直接调 /bin/sh -c 执行命令：
 *   - 程序本身以 root 运行时，命令就是 root 权限；
 *   - 否则先试 sudo -n（免密），再退到 pkexec（弹密码框）。
 *
 * 漏洞页跑 CVE-2026-46300（Fragnesia）的 PoC（tools/lpe/fragnesia.c）：
 *   - 「编译」现场 cc 一份，产物在 tools/lpe/fragnesia；
 *   - 「运行验证」把目标文件 / 偏移传进去，输出（剥掉 ANSI）落在下面的
 *     日志里，按 PoC 的退出码给结论：1 有漏洞 / 0 已修复 / 4 前置条件不满足；
 *   - 子进程带 FRAGNESIA_NO_SHELL=1，否则 PoC 最后会 exec 目标，把整个
 *     GUI 换成 /bin/sh。
 *
 * 构建：
 *   make rootmgr-gui
 */

#include <gtk/gtk.h>
#include <cairo.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tools/kmod/rootmgr_fd.h"

#define APP_TITLE   "RootMgr"
#define MGR_VERSION "1.6"

/* 图标种类：全部用 cairo 画，不依赖图标字体 / 主题 */
typedef enum {
    IC_ERROR = 0,   /* 圆圈感叹号 */
    IC_CHECK,       /* 圆圈对勾 */
    IC_HASH,        /* # 号 */
    IC_CHIP,        /* 芯片 */
    IC_SHIELD,      /* 盾牌 */
    IC_FILTER,      /* 三条横线 */
    IC_BUG,         /* 虫子（漏洞） */
    IC_T_HOME,      /* 底部栏：房子 */
    IC_T_SHIELD,    /* 底部栏：盾牌（超级用户） */
    IC_T_TERM,      /* 底部栏：终端 */
    IC_T_BUG,       /* 底部栏：虫子（漏洞） */
    IC_T_GEAR       /* 底部栏：齿轮（设置） */
} IconKind;

#define TAB_COUNT 5

/* 超级用户列表：图标 / 程序位置 / 权限设置 / 层级 / 悬浮提示 */
enum { COL_ICON, COL_PATH, COL_STATE, COL_LEVEL, COL_TIP, COL_N };

/* 授权状态 */
enum { ST_ASK = 0, ST_ROOT, ST_DENY };

#define STATE_TEXT(st) ((st) == ST_ROOT ? "root" : \
                        (st) == ST_DENY ? "禁止" : "待授权")

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
    GtkWidget *lbl_count;
    GtkWidget *tree;
    GtkTreeStore *store;
    GtkWidget *empty_hint;      /* 列表为空时的提示 */
    GHashTable *policy;         /* 程序位置 -> 授权状态 */

    /* 终端页 */
    GtkWidget *termview;
    GtkTextBuffer *termbuf;
    GtkWidget *entry;
    GtkWidget *prompt;
    GPid run_pid;

    /* 设置页：内核通道 */
    GtkWidget *val_knl;
    GtkWidget *val_kmgr;
    GtkWidget *val_kcnt;
    GtkWidget *val_kexec;
    GtkWidget *btn_escalate;

    /* 漏洞页：CVE-2026-46300 Fragnesia */
    GtkWidget *lpe_target;      /* 目标文件输入框 */
    GtkWidget *lpe_off;         /* 偏移输入框 */
    GtkWidget *lpe_status;      /* 结果一行 */
    GtkWidget *lpe_view;
    GtkWidget *lpe_btn_run;
    GtkWidget *lpe_btn_build;
    GtkTextBuffer *lpe_buf;
    GString  *lpe_pending;      /* 还没凑齐一整行的输出（用来剥 ANSI） */
    GPid      lpe_pid;
    int       lpe_mode;         /* 0 空闲 / 1 编译 / 2 运行 */

    /* 内核通道状态 */
    gboolean knl_ok;            /* 模块在、版本对得上 */
    gboolean knl_autoexec;      /* exec 钩子挂上了（授权程序执行即 root） */
    gboolean knl_manager;       /* 有权限写授权表 */
    guint32  knl_ver;
    guint    knl_synced;        /* 上次成功灌进内核的条数 */
    guint    knl_miss;          /* 路径已失效、没能灌进去的条数 */

    char *policy_path;          /* 启动时定死，提权后也不换文件 */

    /* 底部切换栏 */
    GtkWidget *tab_ico[TAB_COUNT];
    GtkWidget *tab_lbl[TAB_COUNT];
    int        cur;
} App;

/* 定义在后面，先声明 */
static void term_append(App *a, const char *text, const char *tag);
static void refresh_settings(App *a);
static void refresh_lpe(App *a);
static void knl_sync(App *a);

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

    case IC_T_BUG:
    case IC_BUG:
        /* 身体 + 头 + 两根触角 + 三对腿 */
        cairo_arc(cr, 12, 13.8, 4.7, 0, 2 * G_PI);
        cairo_stroke(cr);
        cairo_arc(cr, 12, 7.4, 2.4, 0, 2 * G_PI);
        cairo_stroke(cr);
        cairo_move_to(cr, 10.5, 5.6);
        cairo_line_to(cr, 9.1, 3.1);
        cairo_move_to(cr, 13.5, 5.6);
        cairo_line_to(cr, 14.9, 3.1);
        cairo_stroke(cr);
        cairo_move_to(cr, 7.5, 11.2);
        cairo_line_to(cr, 3.4, 9.3);
        cairo_move_to(cr, 7.3, 13.8);
        cairo_line_to(cr, 3.0, 13.8);
        cairo_move_to(cr, 7.5, 16.4);
        cairo_line_to(cr, 3.4, 18.3);
        cairo_move_to(cr, 16.5, 11.2);
        cairo_line_to(cr, 20.6, 9.3);
        cairo_move_to(cr, 16.7, 13.8);
        cairo_line_to(cr, 21.0, 13.8);
        cairo_move_to(cr, 16.5, 16.4);
        cairo_line_to(cr, 20.6, 18.3);
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
 * 超级用户页：当前用户进程对应的「程序位置」
 * ----------------------------------------------------------------------- */

/* 程序图标：浅色圆角方块 + 程序名首字母，纯 cairo 绘制，不依赖图标主题 */
static GdkPixbuf *prog_icon(const char *path, const char *name)
{
    enum { S = 32 };
    static const double pal[][3] = {
        { 0.906, 0.918, 0.941 },   /* 冷灰 */
        { 0.929, 0.910, 0.902 },   /* 暖灰 */
        { 0.902, 0.933, 0.914 },   /* 青灰 */
        { 0.933, 0.918, 0.949 },   /* 紫灰 */
        { 0.945, 0.929, 0.898 }    /* 米灰 */
    };
    cairo_surface_t *surf;
    cairo_t *cr;
    PangoLayout *pl;
    PangoFontDescription *fd;
    const double *bg;
    unsigned h;
    char letter[8] = "?";
    const char *base;
    gunichar u;
    GdkPixbuf *pb;

    /* 取 basename 的首字符做大写字母 */
    base = path ? strrchr(path, '/') : NULL;
    base = (base && base[1]) ? base + 1 : (name ? name : (path ? path : "?"));
    u = g_utf8_get_char(base);
    if (u && u != G_DIR_SEPARATOR) {
        int k;

        u = g_unichar_toupper(u);
        k = g_unichar_to_utf8(u, letter);
        letter[k] = '\0';
    }

    h = g_str_hash(path && *path ? path : base);
    bg = pal[h % G_N_ELEMENTS(pal)];

    surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, S, S);
    cr = cairo_create(surf);
    cairo_set_antialias(cr, CAIRO_ANTIALIAS_BEST);

    {
        const double r = 8.6;

        cairo_new_sub_path(cr);
        cairo_arc(cr, S - r, r, r, -G_PI / 2, 0);
        cairo_arc(cr, S - r, S - r, r, 0, G_PI / 2);
        cairo_arc(cr, r, S - r, r, G_PI / 2, G_PI);
        cairo_arc(cr, r, r, r, G_PI, 1.5 * G_PI);
        cairo_close_path(cr);
    }
    cairo_set_source_rgb(cr, bg[0], bg[1], bg[2]);
    cairo_fill(cr);

    pl = pango_cairo_create_layout(cr);
    fd = pango_font_description_new();
    pango_font_description_set_family(fd, "Sans");
    pango_font_description_set_weight(fd, PANGO_WEIGHT_BOLD);
    pango_font_description_set_absolute_size(fd, 19 * PANGO_SCALE);
    pango_layout_set_font_description(pl, fd);
    pango_layout_set_text(pl, letter, -1);

    {
        int w = 0, hh = 0;

        pango_layout_get_pixel_size(pl, &w, &hh);
        cairo_set_source_rgb(cr, 0.22, 0.22, 0.25);
        cairo_move_to(cr, (S - w) / 2.0, (S - hh) / 2.0);
        pango_cairo_show_layout(cr, pl);
    }

    pango_font_description_free(fd);
    g_object_unref(pl);
    cairo_destroy(cr);

    pb = gdk_pixbuf_get_from_surface(surf, 0, 0, S, S);
    cairo_surface_destroy(surf);

    return pb;
}

/* 授权记录文件：root 时放 /var/lib/rootmgr，否则放用户配置目录 */
static char *policy_default_path(void)
{
    if (geteuid() == 0)
        return g_strdup("/var/lib/rootmgr/policy.tsv");
    return g_build_filename(g_get_user_config_dir(), "rootmgr", "policy.tsv", NULL);
}

/* 路径在启动时定死：本程序可能中途 grant_root 提权，不能让文件位置跟着变 */
static char *policy_file(App *a)
{
    if (a->policy_path)
        return g_strdup(a->policy_path);
    return policy_default_path();
}

static int policy_get(App *a, const char *path)
{
    if (!a->policy || !path)
        return ST_ASK;
    return GPOINTER_TO_INT(g_hash_table_lookup(a->policy, path));
}

static void policy_load(App *a)
{
    char *pf = policy_file(a);
    char *dir = g_path_get_dirname(pf);
    char *data = NULL;

    g_mkdir_with_parents(dir, 0755);
    g_free(dir);

    if (!a->policy)
        a->policy = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (g_file_get_contents(pf, &data, NULL, NULL)) {
        char **lines = g_strsplit(data, "\n", -1);
        int i;

        for (i = 0; lines[i]; i++) {
            char *line = lines[i];
            char *tab;
            int st;

            if (!*line || line[0] == '#')
                continue;
            tab = strchr(line, '\t');
            if (!tab)
                continue;
            *tab = '\0';
            st = !strcmp(line, "root") ? ST_ROOT :
                 !strcmp(line, "deny") ? ST_DENY : ST_ASK;
            if (!tab[1])
                continue;
            g_hash_table_replace(a->policy, g_strdup(tab + 1),
                                 GINT_TO_POINTER(st));
        }
        g_strfreev(lines);
        g_free(data);
    }
    g_free(pf);
}

static void policy_save(App *a)
{
    char *pf = policy_file(a);
    char *dir = g_path_get_dirname(pf);
    GString *out;
    GHashTableIter it;
    gpointer k, v;

    g_mkdir_with_parents(dir, 0755);

    out = g_string_new("# rootmgr 授权记录：状态<TAB>程序位置\n");
    if (a->policy) {
        g_hash_table_iter_init(&it, a->policy);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            int st = GPOINTER_TO_INT(v);

            g_string_append_printf(out, "%s\t%s\n",
                                   st == ST_ROOT ? "root" :
                                   st == ST_DENY ? "deny" : "ask",
                                   (const char *)k);
        }
    }
    g_file_set_contents(pf, out->str, (gssize)out->len, NULL);
    g_string_free(out, TRUE);
    g_free(dir);
    g_free(pf);

    knl_sync(a);
}

/* --------------------------------------------------------------------------
 * 内核通道：把本地授权表全量灌进 rootmgr.ko
 * ----------------------------------------------------------------------- */

/*
 * 每次变更都全量同步：先 CLEAR 清空内核表，再按 policy 一条条 SET。
 * 条数上限 256，一次点击最多两百多个 ioctl，没有性能问题，也省得算差异。
 *
 * 路径已经不存在（程序被删了）就跳过 —— 内核里绑的是 inode，文件没了
 * 这条授权也就没有意义了。
 */
static void knl_sync(App *a)
{
    GHashTableIter it;
    gpointer k, v;
    guint n = 0, miss = 0;
    guint32 ver = 0;

    a->knl_ok = FALSE;
    a->knl_manager = FALSE;
    a->knl_autoexec = FALSE;
    a->knl_ver = 0;
    a->knl_synced = 0;
    a->knl_miss = 0;

    if (rootmgr_open(&ver) != 0) {
        refresh_settings(a);
        return;                         /* 模块没装，或者版本太老 */
    }

    a->knl_ok = TRUE;
    a->knl_ver = ver;

    {
        struct ksu_get_info_cmd info;

        if (rootmgr_get_info(&info) == 0) {
            a->knl_manager = !!(info.flags & KSU_FLAG_MANAGER);
            a->knl_autoexec = !!(info.flags & KSU_FLAG_AUTOEXEC);
        }
    }

    if (!a->knl_manager) {              /* 通道只读，写也写不进去 */
        refresh_settings(a);
        return;
    }

    if (rootmgr_clear_app() != 0) {
        refresh_settings(a);
        return;
    }

    if (a->policy) {
        g_hash_table_iter_init(&it, a->policy);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            struct ksu_app_entry e;
            int st = GPOINTER_TO_INT(v);

            if (st != ST_ROOT && st != ST_DENY)
                continue;               /* 待授权的不进内核 */
            if (rootmgr_app_id((const char *)k, &e) != 0) {
                miss++;
                continue;
            }
            e.state = (st == ST_ROOT) ? KSU_POLICY_ROOT : KSU_POLICY_DENY;
            if (rootmgr_set_app(&e) == 0)
                n++;
            else
                miss++;
        }
    }
    a->knl_synced = n;
    a->knl_miss = miss;

    refresh_settings(a);
}

/* 从一条命令行里取出真正要执行的程序全路径，取不到返回 NULL */
static char *cmd_program(const char *cmd)
{
    static const char *skip[] = { "sudo", "env", "nohup", "time", "command" };
    char word[512];
    const char *p = cmd;
    size_t i;
    int round;

    if (!cmd)
        return NULL;

    for (round = 0; round < 4; round++) {
        while (*p == ' ' || *p == '\t')
            p++;

        i = 0;
        while (*p && *p != ' ' && *p != '\t' && i + 1 < sizeof(word))
            word[i++] = *p++;
        word[i] = '\0';

        if (!i)
            return NULL;

        /* VAR=value 前缀直接跳过 */
        if (strchr(word, '='))
            continue;

        if (round > 0 || (i = 0, 1)) {
            size_t k;
            gboolean is_skip = FALSE;

            for (k = 0; k < G_N_ELEMENTS(skip); k++)
                if (!strcmp(word, skip[k])) {
                    is_skip = TRUE;
                    break;
                }
            if (!is_skip)
                break;
            if (round == 3)
                return NULL;
        }
    }

    /* 去掉成对的引号 */
    i = strlen(word);
    if (i >= 2 && (word[0] == '\'' || word[0] == '"') && word[i - 1] == word[0]) {
        memmove(word, word + 1, i - 2);
        word[i - 2] = '\0';
    }
    if (!word[0])
        return NULL;

    if (strchr(word, '/'))
        return realpath(word, NULL);

    {
        char *found = g_find_program_in_path(word);

        if (found) {
            char *real = realpath(found, NULL);

            g_free(found);
            return real;
        }
    }
    return NULL;
}

static gint cmp_path(gconstpointer a, gconstpointer b)
{
    return g_strcmp0((const char *)a, (const char *)b);
}

/* 重建超级用户列表：每行一个程序，展开后是 root / 禁止 两个选项 */
static void refresh_super(App *a)
{
    GHashTableIter it;
    gpointer k, v;
    GList *paths = NULL, *l;
    guint n = 0;

    if (!a->store)
        return;

    gtk_tree_store_clear(a->store);

    if (a->policy) {
        g_hash_table_iter_init(&it, a->policy);
        while (g_hash_table_iter_next(&it, &k, &v))
            paths = g_list_prepend(paths, k);
        paths = g_list_sort(paths, cmp_path);
    }

    for (l = paths; l; l = l->next) {
        const char *path = l->data;
        int st = policy_get(a, path);
        GtkTreeIter parent, child;
        GdkPixbuf *ico = prog_icon(path, NULL);

        gtk_tree_store_append(a->store, &parent, NULL);
        gtk_tree_store_set(a->store, &parent,
                           COL_ICON, ico,
                           COL_PATH, path,
                           COL_STATE, STATE_TEXT(st),
                           COL_LEVEL, 0,
                           COL_TIP, path, -1);
        if (ico)
            g_object_unref(ico);

        {
            static const int opts[2] = { ST_ROOT, ST_DENY };
            int i;

            for (i = 0; i < 2; i++) {
                char buf[64];

                g_snprintf(buf, sizeof(buf), "     %s %s",
                           st == opts[i] ? "●" : "○", STATE_TEXT(opts[i]));
                gtk_tree_store_append(a->store, &child, &parent);
                gtk_tree_store_set(a->store, &child,
                                   COL_ICON, NULL,
                                   COL_PATH, buf,
                                   COL_STATE, "",
                                   COL_LEVEL, opts[i],
                                   COL_TIP, NULL, -1);
            }
        }
        n++;
    }
    g_list_free(paths);

    if (a->lbl_count) {
        char cnt[64];

        g_snprintf(cnt, sizeof(cnt), "%u 个程序", n);
        gtk_label_set_text(GTK_LABEL(a->lbl_count), cnt);
    }
    if (a->empty_hint)
        gtk_widget_set_visible(a->empty_hint, n == 0);
}

/* 登记一次 root 请求：程序还没记录过就加进来（状态待授权） */
static void policy_request(App *a, const char *cmd)
{
    char *prog = cmd_program(cmd);
    gboolean added = FALSE;

    if (!prog)
        return;
    if (!a->policy)
        a->policy = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (!g_hash_table_contains(a->policy, prog)) {
        g_hash_table_insert(a->policy, prog, GINT_TO_POINTER(ST_ASK));
        added = TRUE;
    } else {
        g_free(prog);
    }

    if (added) {
        policy_save(a);
        refresh_super(a);
    }
}

/* 把某一行设成 root / 禁止，只更新这一行，不重建列表（保留展开状态） */
static void apply_state(App *a, GtkTreeIter *parent, int st)
{
    GtkTreeModel *m = GTK_TREE_MODEL(a->store);
    GtkTreeIter child;
    char *path = NULL;

    gtk_tree_model_get(m, parent, COL_PATH, &path, -1);
    if (path) {
        g_hash_table_replace(a->policy, path, GINT_TO_POINTER(st));
        policy_save(a);
    }
    gtk_tree_store_set(a->store, parent, COL_STATE, STATE_TEXT(st), -1);

    if (gtk_tree_model_iter_children(m, &child, parent)) {
        do {
            int lvl = 0;
            char buf[64];

            gtk_tree_model_get(m, &child, COL_LEVEL, &lvl, -1);
            g_snprintf(buf, sizeof(buf), "     %s %s",
                       lvl == st ? "●" : "○", STATE_TEXT(lvl));
            gtk_tree_store_set(a->store, &child, COL_PATH, buf, -1);
        } while (gtk_tree_model_iter_next(m, &child));
    }
}

static void on_remove_prog(GtkWidget *mi, gpointer data)
{
    App *a = data;
    char *path = g_object_get_data(G_OBJECT(mi), "path");

    if (!path || !a->policy)
        return;
    g_hash_table_remove(a->policy, path);
    policy_save(a);
    refresh_super(a);
}

/* 右键：移除一条授权记录 */
static gboolean on_super_right(GtkWidget *w, GdkEventButton *ev, gpointer data)
{
    App *a = data;
    GtkTreePath *tp = NULL;
    GtkTreeViewColumn *col = NULL;
    GtkTreeModel *m = gtk_tree_view_get_model(GTK_TREE_VIEW(w));
    GtkTreeIter it, parent;
    char *path = NULL;
    GtkWidget *menu, *item;
    int lvl = 0;

    if (ev->type != GDK_BUTTON_PRESS || ev->button != 3)
        return FALSE;
    if (!gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(w), (int)ev->x, (int)ev->y,
                                       &tp, &col, NULL, NULL))
        return FALSE;
    (void)col;

    if (!gtk_tree_model_get_iter(m, &it, tp)) {
        gtk_tree_path_free(tp);
        return FALSE;
    }
    gtk_tree_path_free(tp);

    gtk_tree_model_get(m, &it, COL_LEVEL, &lvl, -1);
    if (lvl != 0 && gtk_tree_model_iter_parent(m, &parent, &it))
        it = parent;

    gtk_tree_model_get(m, &it, COL_PATH, &path, -1);
    if (!path)
        return FALSE;

    menu = gtk_menu_new();
    item = gtk_menu_item_new_with_label("移除这条记录");
    g_object_set_data_full(G_OBJECT(item), "path", path, g_free);
    g_signal_connect(item, "activate", G_CALLBACK(on_remove_prog), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent *)ev);
    return TRUE;
}

/* 单击：父行展开/收起，子行就是选 root 或禁止 */
static gboolean on_super_click(GtkWidget *w, GdkEventButton *ev, gpointer data)
{
    App *a = data;
    GtkTreePath *tp = NULL;
    GtkTreeViewColumn *col = NULL;
    GtkTreeModel *m = gtk_tree_view_get_model(GTK_TREE_VIEW(w));
    GtkTreeIter it, parent;

    if (ev->type != GDK_BUTTON_PRESS || ev->button != 1)
        return FALSE;
    if (!gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(w), (int)ev->x, (int)ev->y,
                                       &tp, &col, NULL, NULL))
        return FALSE;
    (void)col;

    if (!gtk_tree_model_get_iter(m, &it, tp)) {
        gtk_tree_path_free(tp);
        return FALSE;
    }

    {
        int lvl = 0;

        gtk_tree_model_get(m, &it, COL_LEVEL, &lvl, -1);
        if (lvl == ST_ROOT || lvl == ST_DENY) {
            /* 子行：设置授权 */
            if (gtk_tree_model_iter_parent(m, &parent, &it))
                apply_state(a, &parent, lvl);
        } else if (gtk_tree_view_row_expanded(GTK_TREE_VIEW(w), tp)) {
            gtk_tree_view_collapse_row(GTK_TREE_VIEW(w), tp);
        } else {
            gtk_tree_view_expand_row(GTK_TREE_VIEW(w), tp, FALSE);
        }
    }

    gtk_tree_path_free(tp);
    return TRUE;
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

    {
        char *prog = cmd_program(cmd);

        if (prog) {
            int st = policy_get(a, prog);

            if (st == ST_DENY) {
                term_append(a, prog, "err");
                term_append(a, " 已被设为「禁止」，"
                               "可到「超级用户」页改回 root\n", "err");
                g_free(prog);
                return;
            }
            g_free(prog);
        }
        /* 没记录过的程序登记成待授权，会出现在超级用户列表里 */
        policy_request(a, cmd);
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

static const char *PAGE_NAMES[TAB_COUNT] = { "home", "super", "term", "lpe", "set" };

/* 把选区收成光标处的一个点：GtkEntry 一被 grab_focus 就会把整段文本选中，
   切页时 GTK 又会自动把焦点交给第一个能获焦的控件，于是路径会莫名其妙变成蓝色。 */
static void entry_drop_selection(GtkWidget *w)
{
    int pos;

    if (!w)
        return;
    pos = gtk_editable_get_position(GTK_EDITABLE(w));
    if (pos < 0)
        pos = 0;
    gtk_editable_select_region(GTK_EDITABLE(w), pos, pos);
}

static gboolean reset_entry_selection(gpointer data)
{
    App *a = data;

    entry_drop_selection(a->lpe_target);
    entry_drop_selection(a->lpe_off);
    entry_drop_selection(a->entry);
    return G_SOURCE_REMOVE;
}

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
        refresh_super(a);
    if (idx == 2 && a->entry)
        gtk_widget_grab_focus(a->entry);
    if (idx == 3)
        refresh_lpe(a);
    if (idx == 4)
        refresh_settings(a);

    /* 切页之后 GTK 可能已经把焦点挪到某个输入框并全选了内容，收一下 */
    g_idle_add(reset_entry_selection, a);
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
    "#logview, #logview text { font-family: \"DejaVu Sans Mono\", \"Noto Sans Mono\", monospace;\n"
    "         font-size: 12px; }\n"
    "#lpe_status { color: #6f6f6f; font-size: 13px; }\n"
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
    GtkWidget *overlay, *empty, *tree;

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
    lbl = gtk_label_new("程序位置");
    sub = gtk_label_new("0 个程序");
    a->lbl_count = sub;
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

    a->store = gtk_tree_store_new(COL_N, GDK_TYPE_PIXBUF, G_TYPE_STRING,
                                  G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);
    tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(a->store));
    a->tree = tree;
    gtk_widget_set_name(tree, "proctree");
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(tree), FALSE);
    gtk_tree_view_set_enable_search(GTK_TREE_VIEW(tree), FALSE);
    gtk_tree_view_set_tooltip_column(GTK_TREE_VIEW(tree), COL_TIP);

    {
        GtkCellRenderer *r;
        GtkTreeViewColumn *c;

        r = gtk_cell_renderer_pixbuf_new();
        g_object_set(r, "xpad", 8, "ypad", 6, NULL);
        c = gtk_tree_view_column_new_with_attributes("icon", r, "pixbuf", COL_ICON, NULL);
        gtk_tree_view_column_set_min_width(c, 46);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), c);

        r = gtk_cell_renderer_text_new();
        g_object_set(r, "ellipsize", PANGO_ELLIPSIZE_MIDDLE, "xpad", 6, NULL);
        c = gtk_tree_view_column_new_with_attributes("path", r, "text", COL_PATH, NULL);
        gtk_tree_view_column_set_expand(c, TRUE);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), c);

        r = gtk_cell_renderer_text_new();
        g_object_set(r, "xpad", 6, "xalign", 0.0, NULL);
        c = gtk_tree_view_column_new_with_attributes("state", r, "text", COL_STATE, NULL);
        gtk_tree_view_column_set_min_width(c, 120);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), c);
    }

    gtk_container_add(GTK_CONTAINER(scroll), tree);

    /* 列表为空时盖一层居中提示 */
    overlay = gtk_overlay_new();
    gtk_container_add(GTK_CONTAINER(overlay), scroll);

    empty = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_halign(empty, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(empty, GTK_ALIGN_CENTER);
    {
        GtkWidget *t1 = gtk_label_new("还没有程序申请 root");
        GtkWidget *t2 = gtk_label_new("在「终端」里执行命令后，程序会出现在这里");

        gtk_widget_set_name(t1, "cardtitle");
        gtk_widget_set_name(t2, "cardvalue");
        gtk_widget_set_halign(t1, GTK_ALIGN_CENTER);
        gtk_widget_set_halign(t2, GTK_ALIGN_CENTER);
        gtk_box_pack_start(GTK_BOX(empty), t1, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(empty), t2, FALSE, FALSE, 0);
    }
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), empty);
    a->empty_hint = empty;

    gtk_box_pack_start(GTK_BOX(cbody), overlay, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(card), cbody, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), card, TRUE, TRUE, 0);

    {
        GtkWidget *hint = gtk_label_new("点一行展开，选 root 或禁止；"
                                        "选 root 后该程序每次执行都直接拿到 root，右键可移除。");
        gtk_widget_set_name(hint, "cardvalue");
        gtk_widget_set_halign(hint, GTK_ALIGN_START);
        gtk_widget_set_margin_start(hint, 14);
        gtk_box_pack_start(GTK_BOX(box), hint, FALSE, FALSE, 0);
    }

    g_signal_connect(tree, "button-press-event", G_CALLBACK(on_super_click), a);
    g_signal_connect(tree, "button-press-event", G_CALLBACK(on_super_right), a);
    g_signal_connect_swapped(btn, "clicked", G_CALLBACK(refresh_super), a);
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

/* 设置页：运行身份 + 内核通道 + 说明 */
static void on_escalate(GtkWidget *w, gpointer data)
{
    App *a = data;
    char msg[192];

    (void)w;

    if (rootmgr_grant_root() != 0) {
        g_snprintf(msg, sizeof(msg), "提权失败：%s\n", g_strerror(errno));
        term_append(a, msg, "err");
        return;
    }

    g_snprintf(msg, sizeof(msg),
               "已提权到 root（euid=%u），之后的命令直接以 root 执行。\n",
               (unsigned)geteuid());
    term_append(a, msg, "dim");

    refresh_home(a);
    refresh_settings(a);
}

static void refresh_settings(App *a)
{
    char buf[192];

    if (!a->val_knl)
        return;

    if (!a->knl_ok) {
        gtk_label_set_text(GTK_LABEL(a->val_knl),
                           "未连接（rootmgr.ko 还没加载）");
        gtk_label_set_text(GTK_LABEL(a->val_kmgr), "—");
        gtk_label_set_text(GTK_LABEL(a->val_kcnt), "—");
        gtk_label_set_text(GTK_LABEL(a->val_kexec), "—");
    } else {
        g_snprintf(buf, sizeof(buf), "已连接　rootmgr %u.%u.%u",
                   a->knl_ver / 10000, a->knl_ver / 100 % 100,
                   a->knl_ver % 100);
        gtk_label_set_text(GTK_LABEL(a->val_knl), buf);

        gtk_label_set_text(GTK_LABEL(a->val_kmgr),
                           a->knl_manager
                               ? "可写（manager）"
                               : "只读（不是 manager，请以 root 启动）");

        if (a->knl_miss)
            g_snprintf(buf, sizeof(buf), "%u 条生效，%u 条路径已失效",
                       a->knl_synced, a->knl_miss);
        else
            g_snprintf(buf, sizeof(buf), "%u 条生效", a->knl_synced);
        gtk_label_set_text(GTK_LABEL(a->val_kcnt), buf);

        gtk_label_set_text(GTK_LABEL(a->val_kexec),
                           a->knl_autoexec
                               ? "已启用（授权程序执行即 root）"
                               : "未启用（只能手动提权）");
    }

    if (a->btn_escalate) {
        gboolean can = a->knl_ok && a->knl_manager && !is_root();

        gtk_widget_set_visible(a->btn_escalate, can);
        gtk_widget_set_sensitive(a->btn_escalate, can);
    }
}

static GtkWidget *build_settings(App *a)
{
    GtkWidget *box;
    GtkWidget *card_id, *card_knl, *hint;
    GtkWidget *v_uid, *v_euid, *v_sudo, *v_pk;

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);

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

    /* 内核通道 */
    card_knl = card_new();
    gtk_box_pack_start(GTK_BOX(card_knl),
                       info_row(IC_SHIELD, "rootmgr.ko", &a->val_knl), FALSE, FALSE, 0);
    add_divider(card_knl);
    gtk_box_pack_start(GTK_BOX(card_knl),
                       info_row(IC_CHECK, "授权表写权限", &a->val_kmgr), FALSE, FALSE, 0);
    add_divider(card_knl);
    gtk_box_pack_start(GTK_BOX(card_knl),
                       info_row(IC_FILTER, "内核授权条目", &a->val_kcnt), FALSE, FALSE, 0);
    add_divider(card_knl);
    gtk_box_pack_start(GTK_BOX(card_knl),
                       info_row(IC_CHIP, "exec 自动提权", &a->val_kexec), FALSE, FALSE, 0);

    {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

        gtk_widget_set_margin_start(row, 22);
        gtk_widget_set_margin_end(row, 22);
        gtk_widget_set_margin_top(row, 10);
        gtk_widget_set_margin_bottom(row, 16);

        a->btn_escalate = gtk_button_new_with_label("提权本程序到 root");
        gtk_style_context_add_class(gtk_widget_get_style_context(a->btn_escalate),
                                    "primary");
        g_signal_connect(a->btn_escalate, "clicked", G_CALLBACK(on_escalate), a);
        gtk_box_pack_start(GTK_BOX(row), a->btn_escalate, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(card_knl), row, FALSE, FALSE, 0);
    }

    /* 横屏：左右两张卡并排，说明压成一行小字放底部，避免撑高窗口 */
    {
        GtkWidget *cols = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

        gtk_box_pack_start(GTK_BOX(cols), card_id, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(cols), card_knl, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(box), cols, FALSE, FALSE, 0);
    }

    hint = gtk_label_new("RootMgr " MGR_VERSION
                         "　授权表按 exe 的 inode 存内核，模块重装后自动重灌；"
                         "被授权为 root 的程序执行时由 exec 钩子直接变成 root。");
    gtk_widget_set_name(hint, "cardvalue");
    gtk_widget_set_halign(hint, GTK_ALIGN_START);
    gtk_widget_set_margin_start(hint, 18);
    gtk_widget_set_margin_top(hint, 4);
    gtk_box_pack_start(GTK_BOX(box), hint, FALSE, FALSE, 0);

    refresh_settings(a);
    return box;
}

/* --------------------------------------------------------------------------
 * 漏洞页：CVE-2026-46300 Fragnesia
 *
 * PoC 源码在 tools/lpe/fragnesia.c，这里只做三件事：编译、传参运行、把
 * 输出读回来。两个环境变量是关键：
 *   FRAGNESIA_PLAIN=1     不画 hex 动画（文本视图里没法看）
 *   FRAGNESIA_NO_SHELL=1  最后不要 exec 目标 —— 否则整个 GUI 进程会被
 *                         换成 /bin/sh，窗口直接消失
 * ----------------------------------------------------------------------- */

#define LPE_IDLE  0
#define LPE_BUILD 1
#define LPE_RUN   2

#define LPE_NONE  0
#define LPE_GOOD  1
#define LPE_BAD   2

/* <exe 所在目录>/tools/lpe/<leaf>：仓库里那个 PoC */
static char *lpe_path(const char *leaf)
{
    char exe[PATH_MAX];
    ssize_t n;
    char *dir, *path;

    n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        dir = g_path_get_dirname(exe);
    } else {
        dir = g_strdup(".");
    }
    path = g_build_filename(dir, "tools", "lpe", leaf, NULL);
    g_free(dir);
    return path;
}

/* 日志视图写入（和终端一样的三档样式） */
static void lpe_log(App *a, const char *text, const char *tag)
{
    GtkTextIter end;
    GtkTextMark *mark;

    if (!a->lpe_buf || !text)
        return;

    gtk_text_buffer_get_end_iter(a->lpe_buf, &end);
    if (tag)
        gtk_text_buffer_insert_with_tags_by_name(a->lpe_buf, &end, text, -1,
                                                 tag, NULL);
    else
        gtk_text_buffer_insert(a->lpe_buf, &end, text, -1);

    gtk_text_buffer_get_end_iter(a->lpe_buf, &end);
    gtk_text_buffer_place_cursor(a->lpe_buf, &end);
    mark = gtk_text_buffer_get_insert(a->lpe_buf);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(a->lpe_view), mark);
}

/* 结果一行：颜色靠 markup，省得为一个标签多加一套 CSS 类 */
static void lpe_set_status(App *a, const char *text, int kind)
{
    const char *color = kind == LPE_GOOD ? "#2e7d32" :
                        kind == LPE_BAD  ? "#c0392b" : "#6f6f6f";
    char *esc, *markup;

    if (!a->lpe_status)
        return;

    esc = g_markup_escape_text(text, -1);
    markup = g_strdup_printf("<span foreground=\"%s\">%s</span>", color, esc);
    gtk_label_set_markup(GTK_LABEL(a->lpe_status), markup);
    g_free(markup);
    g_free(esc);
}

/*
 * 剥掉 ANSI 控制序列。PoC 即使关掉 hex 帧，行内还是有颜色码；
 * 逐行处理可以避免转义序列被 read() 切成两半。
 */
static void ansi_strip(const char *in, gsize len, GString *out)
{
    const char *p = in, *end = in + len;

    while (p < end) {
        if ((unsigned char)*p == 0x1b) {
            p++;
            if (p < end && *p == '[') {          /* CSI ... 终止字节 @~ */
                p++;
                while (p < end && !(*p >= '@' && *p <= '~'))
                    p++;
                if (p < end)
                    p++;
            } else if (p < end && *p == ']') {   /* OSC ... BEL */
                p++;
                while (p < end && *p != '\a')
                    p++;
                if (p < end)
                    p++;
            } else if (p < end) {
                p++;
            }
            continue;
        }
        if (*p == '\r' || *p == '\a') {          /* 覆盖式刷新在视图里没意义 */
            p++;
            continue;
        }
        g_string_append_c(out, *p++);
    }
}

/* 凑满一行就吐出去；force 时把最后半行也吐掉 */
static void lpe_flush(App *a, gboolean force)
{
    char *nl;

    if (!a->lpe_pending)
        return;

    while ((nl = strchr(a->lpe_pending->str, '\n')) != NULL) {
        gsize len = (gsize)(nl - a->lpe_pending->str);
        GString *line = g_string_new(NULL);

        ansi_strip(a->lpe_pending->str, len, line);
        g_string_append_c(line, '\n');
        lpe_log(a, line->str, NULL);
        g_string_free(line, TRUE);
        g_string_erase(a->lpe_pending, 0, (gssize)len + 1);
    }

    if (force && a->lpe_pending->len > 0) {
        GString *line = g_string_new(NULL);

        ansi_strip(a->lpe_pending->str, a->lpe_pending->len, line);
        lpe_log(a, line->str, NULL);
        g_string_free(line, TRUE);
        g_string_truncate(a->lpe_pending, 0);
    }
}

static gboolean lpe_pipe_read(GIOChannel *ch, GIOCondition cond, gpointer data)
{
    App *a = data;
    gchar buf[1024];
    gsize n = 0;
    GError *err = NULL;
    GIOStatus st;

    st = g_io_channel_read_chars(ch, buf, sizeof(buf) - 1, &n, &err);
    if (n > 0) {
        buf[n] = '\0';
        if (!a->lpe_pending)
            a->lpe_pending = g_string_new(NULL);
        g_string_append_len(a->lpe_pending, buf, (gssize)n);
        lpe_flush(a, FALSE);
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

static void lpe_on_exit(GPid pid, gint status, gpointer data);

/* 起一个子进程，stdout/stderr 都接到漏洞页的日志里 */
static gboolean lpe_spawn(App *a, char **argv, char **envp, int mode)
{
    GPid pid = 0;
    gint out_fd = -1, err_fd = -1;
    GError *ge = NULL;

    if (!g_spawn_async_with_pipes(NULL, argv, envp,
                                  G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD,
                                  NULL, NULL, &pid, NULL, &out_fd, &err_fd, &ge)) {
        char msg[320];

        g_snprintf(msg, sizeof(msg), "启动失败：%s\n",
                   ge ? ge->message : "未知错误");
        lpe_log(a, msg, "err");
        if (ge)
            g_error_free(ge);
        return FALSE;
    }

    a->lpe_pid = pid;
    a->lpe_mode = mode;

    if (out_fd >= 0) {
        GIOChannel *ch = g_io_channel_unix_new(out_fd);

        g_io_channel_set_encoding(ch, NULL, NULL);
        g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR, lpe_pipe_read, a);
    }
    if (err_fd >= 0) {
        GIOChannel *ch = g_io_channel_unix_new(err_fd);

        g_io_channel_set_encoding(ch, NULL, NULL);
        g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR, lpe_pipe_read, a);
    }

    g_child_watch_add(pid, lpe_on_exit, a);
    return TRUE;
}

static void lpe_busy(App *a, gboolean busy)
{
    if (a->lpe_btn_run)
        gtk_widget_set_sensitive(a->lpe_btn_run, !busy);
    if (a->lpe_btn_build)
        gtk_widget_set_sensitive(a->lpe_btn_build, !busy);
}

static void lpe_on_exit(GPid pid, gint status, gpointer data)
{
    App *a = data;
    int mode = a->lpe_mode;
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    char msg[384];

    g_spawn_close_pid(pid);
    a->lpe_pid = 0;
    a->lpe_mode = LPE_IDLE;
    lpe_flush(a, TRUE);
    lpe_busy(a, FALSE);

    if (mode == LPE_BUILD) {
        if (code == 0) {
            lpe_log(a, "\n[编译完成] tools/lpe/fragnesia\n", "ok");
            lpe_set_status(a, "编译完成，可以运行验证", LPE_GOOD);
        } else {
            lpe_log(a, "\n[编译失败] 看上面的报错\n", "err");
            lpe_set_status(a, "编译失败", LPE_BAD);
        }
        return;
    }

    if (mode != LPE_RUN)
        return;

    switch (code) {
    case 1:
        g_snprintf(msg, sizeof(msg),
                   "存在漏洞：目标文件的内容已被改写（exit=1）");
        lpe_log(a, "\n结论：内核可被非特权用户改写只读文件的 page cache。\n"
                   "      这只改了内存里的页，重启或 drop_caches 后恢复；"
                   "目标文件若被替换成 ELF，执行它即以 root 运行。\n", "warn");
        lpe_set_status(a, msg, LPE_BAD);
        break;
    case 0:
        lpe_log(a, "\n结论：字节没有被改写，内核已修复。\n", "ok");
        lpe_set_status(a, "已修复：目标字节未被改写（exit=0）", LPE_GOOD);
        break;
    case 4:
        lpe_set_status(a, "被前置条件挡住（exit=4），见日志", LPE_BAD);
        break;
    case 2:
        lpe_set_status(a, "运行失败：参数或环境不对（exit=2）", LPE_BAD);
        break;
    default:
        g_snprintf(msg, sizeof(msg), "异常退出（exit=%d）", code);
        lpe_set_status(a, msg, LPE_BAD);
        break;
    }
}

static void on_lpe_build(GtkWidget *w, gpointer data)
{
    App *a = data;
    char *bin, *src;
    char *argv[8];
    char *shown;

    (void)w;

    if (a->lpe_mode != LPE_IDLE) {
        lpe_log(a, "上一个任务还没结束\n", "err");
        return;
    }

    bin = lpe_path("fragnesia");
    src = lpe_path("fragnesia.c");
    if (access(src, R_OK) != 0) {
        lpe_log(a, "找不到源码：", "err");
        lpe_log(a, src, "err");
        lpe_log(a, "\n（这个页面要在仓库目录里用，源码在 tools/lpe/）\n", "err");
        lpe_set_status(a, "找不到 PoC 源码", LPE_BAD);
        g_free(bin);
        g_free(src);
        return;
    }

    argv[0] = "cc";
    argv[1] = "-O2";
    argv[2] = "-Wall";
    argv[3] = "-Wextra";
    argv[4] = "-o";
    argv[5] = bin;
    argv[6] = src;
    argv[7] = NULL;

    shown = g_strdup_printf("$ cc -O2 -Wall -Wextra -o %s %s\n", bin, src);
    lpe_log(a, shown, "dim");
    g_free(shown);

    if (lpe_spawn(a, argv, NULL, LPE_BUILD)) {
        lpe_busy(a, TRUE);
        lpe_set_status(a, "编译中…", LPE_NONE);
    }
    g_free(bin);
    g_free(src);
}

static void on_lpe_run(GtkWidget *w, gpointer data)
{
    App *a = data;
    const char *tgt, *off;
    char *bin;
    char *argv[4];
    char **env;

    (void)w;

    if (a->lpe_mode != LPE_IDLE) {
        lpe_log(a, "上一个任务还没结束\n", "err");
        return;
    }

    tgt = gtk_entry_get_text(GTK_ENTRY(a->lpe_target));
    off = gtk_entry_get_text(GTK_ENTRY(a->lpe_off));
    if (!tgt || !*tgt) {
        lpe_set_status(a, "先填目标文件", LPE_BAD);
        return;
    }

    bin = lpe_path("fragnesia");
    if (access(bin, X_OK) != 0) {
        lpe_log(a, "还没编译：先点「编译」\n", "err");
        lpe_set_status(a, "未编译", LPE_BAD);
        g_free(bin);
        return;
    }

    lpe_log(a, "\n$ fragnesia ", "dim");
    lpe_log(a, tgt, "cmd");
    lpe_log(a, " ", NULL);
    lpe_log(a, (*off ? off : "0"), "cmd");
    lpe_log(a, "\n", NULL);

    if (geteuid() == 0)
        lpe_log(a, "[提示] 当前以 root 运行，PoC 的写权限边界检查会直接失败"
                   "（exit=4）；要真正验证请用普通用户启动本程序。\n", "warn");

    argv[0] = bin;
    argv[1] = (char *)tgt;
    argv[2] = (char *)(*off ? off : "0");
    argv[3] = NULL;

    env = g_get_environ();
    env = g_environ_setenv(env, "FRAGNESIA_PLAIN", "1", TRUE);
    env = g_environ_setenv(env, "FRAGNESIA_NO_SHELL", "1", TRUE);

    if (lpe_spawn(a, argv, env, LPE_RUN)) {
        lpe_busy(a, TRUE);
        lpe_set_status(a, "运行中…", LPE_NONE);
    }

    g_strfreev(env);
    g_free(bin);
}

static void refresh_lpe(App *a)
{
    char *bin;

    if (!a->lpe_status || a->lpe_mode != LPE_IDLE)
        return;

    bin = lpe_path("fragnesia");
    if (access(bin, X_OK) == 0)
        lpe_set_status(a, "就绪，可运行", LPE_NONE);
    else
        lpe_set_status(a, "未编译，先点「编译」", LPE_NONE);
    g_free(bin);
}

static GtkWidget *build_lpe(App *a)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *card, *card_log, *head, *row, *lbl, *sub, *btn_clear, *scroll, *hint;

    gtk_widget_set_margin_start(box, 8);
    gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 12);

    gtk_box_pack_start(GTK_BOX(box), page_title("漏洞", NULL), FALSE, FALSE, 0);

    /* 上半：一段说明 + 一行参数，尽量矮，把高度留给日志 */
    card = card_new();

    head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    gtk_widget_set_margin_start(head, 22);
    gtk_widget_set_margin_end(head, 22);
    gtk_widget_set_margin_top(head, 14);
    gtk_widget_set_margin_bottom(head, 10);
    {
        GtkWidget *ico = make_icon(IC_BUG, 24);
        GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);

        gtk_widget_set_valign(ico, GTK_ALIGN_START);
        gtk_widget_set_margin_top(ico, 1);

        lbl = gtk_label_new("CVE-2026-46300 · Fragnesia");
        gtk_widget_set_name(lbl, "cardtitle");
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);

        sub = gtk_label_new("xfrm espintcp 的 ESP 分片被当成普通数据写回页缓存，"
                            "非特权用户即可改写只读文件");
        gtk_widget_set_name(sub, "cardvalue");
        gtk_widget_set_halign(sub, GTK_ALIGN_START);
        gtk_label_set_line_wrap(GTK_LABEL(sub), TRUE);
        gtk_label_set_max_width_chars(GTK_LABEL(sub), 86);

        gtk_box_pack_start(GTK_BOX(col), lbl, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(col), sub, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(head), ico, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(head), col, TRUE, TRUE, 0);
    }
    gtk_box_pack_start(GTK_BOX(card), head, FALSE, FALSE, 0);

    /* 参数条：目标文件 / 偏移 / 编译 / 运行 */
    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_start(row, 62);
    gtk_widget_set_margin_end(row, 22);
    gtk_widget_set_margin_top(row, 4);
    gtk_widget_set_margin_bottom(row, 4);

    a->lpe_target = gtk_entry_new();
    gtk_widget_set_name(a->lpe_target, "cmdline");
    gtk_entry_set_text(GTK_ENTRY(a->lpe_target), "/usr/bin/su");
    gtk_editable_select_region(GTK_EDITABLE(a->lpe_target), 0, 0);
    gtk_widget_set_hexpand(a->lpe_target, TRUE);

    a->lpe_off = gtk_entry_new();
    gtk_widget_set_name(a->lpe_off, "cmdline");
    gtk_entry_set_text(GTK_ENTRY(a->lpe_off), "0");
    gtk_editable_select_region(GTK_EDITABLE(a->lpe_off), 0, 0);
    gtk_entry_set_width_chars(GTK_ENTRY(a->lpe_off), 5);
    gtk_entry_set_max_width_chars(GTK_ENTRY(a->lpe_off), 5);

    a->lpe_btn_build = gtk_button_new_with_label("编译");
    a->lpe_btn_run = gtk_button_new_with_label("运行验证");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->lpe_btn_run),
                                "primary");

    {
        GtkWidget *lbl_t = gtk_label_new("目标文件");
        GtkWidget *lbl_o = gtk_label_new("偏移");

        gtk_widget_set_name(lbl_t, "rowlabel");
        gtk_widget_set_name(lbl_o, "rowlabel");
        gtk_widget_set_valign(lbl_t, GTK_ALIGN_CENTER);
        gtk_widget_set_valign(lbl_o, GTK_ALIGN_CENTER);

        gtk_box_pack_start(GTK_BOX(row), lbl_t, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(row), a->lpe_target, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(row), lbl_o, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(row), a->lpe_off, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(row), a->lpe_btn_build, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), a->lpe_btn_run, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(card), row, FALSE, FALSE, 0);

    a->lpe_status = gtk_label_new("");
    gtk_widget_set_halign(a->lpe_status, GTK_ALIGN_START);
    gtk_widget_set_margin_start(a->lpe_status, 62);
    gtk_widget_set_margin_end(a->lpe_status, 22);
    gtk_widget_set_margin_top(a->lpe_status, 4);
    gtk_widget_set_margin_bottom(a->lpe_status, 12);
    gtk_label_set_line_wrap(GTK_LABEL(a->lpe_status), TRUE);
    gtk_box_pack_start(GTK_BOX(card), a->lpe_status, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(box), card, FALSE, FALSE, 0);

    /* 下半：日志 */
    card_log = card_new();
    gtk_widget_set_vexpand(card_log, TRUE);

    {
        GtkWidget *cbody = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

        gtk_widget_set_margin_start(cbody, 14);
        gtk_widget_set_margin_end(cbody, 14);
        gtk_widget_set_margin_top(cbody, 10);
        gtk_widget_set_margin_bottom(cbody, 10);

        head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        lbl = gtk_label_new("输出");
        gtk_widget_set_name(lbl, "cardtitle");
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);
        btn_clear = gtk_button_new_with_label("清屏");
        gtk_widget_set_name(btn_clear, "textbtn");
        gtk_box_pack_start(GTK_BOX(head), lbl, TRUE, TRUE, 0);
        gtk_box_pack_end(GTK_BOX(head), btn_clear, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(cbody), head, FALSE, FALSE, 0);

        scroll = gtk_scrolled_window_new(NULL, NULL);
        gtk_widget_set_name(scroll, "logscroll");
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                       GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_widget_set_vexpand(scroll, TRUE);

        a->lpe_buf = gtk_text_buffer_new(NULL);
        gtk_text_buffer_create_tag(a->lpe_buf, "cmd",
                                   "weight", PANGO_WEIGHT_BOLD, NULL);
        gtk_text_buffer_create_tag(a->lpe_buf, "err",
                                   "foreground", "#c0392b", NULL);
        gtk_text_buffer_create_tag(a->lpe_buf, "warn",
                                   "foreground", "#b26a00", NULL);
        gtk_text_buffer_create_tag(a->lpe_buf, "ok",
                                   "foreground", "#2e7d32", NULL);
        gtk_text_buffer_create_tag(a->lpe_buf, "dim",
                                   "foreground", "#8e8e93", NULL);

        a->lpe_view = gtk_text_view_new_with_buffer(a->lpe_buf);
        gtk_widget_set_name(a->lpe_view, "logview");
        gtk_text_view_set_editable(GTK_TEXT_VIEW(a->lpe_view), FALSE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(a->lpe_view), FALSE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(a->lpe_view), GTK_WRAP_WORD_CHAR);
        gtk_text_view_set_left_margin(GTK_TEXT_VIEW(a->lpe_view), 10);
        gtk_text_view_set_right_margin(GTK_TEXT_VIEW(a->lpe_view), 10);
        gtk_text_view_set_top_margin(GTK_TEXT_VIEW(a->lpe_view), 6);
        gtk_container_add(GTK_CONTAINER(scroll), a->lpe_view);
        gtk_box_pack_start(GTK_BOX(cbody), scroll, TRUE, TRUE, 0);

        gtk_box_pack_start(GTK_BOX(card_log), cbody, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(box), card_log, TRUE, TRUE, 0);

        g_signal_connect_swapped(btn_clear, "clicked",
                                 G_CALLBACK(gtk_text_buffer_set_text),
                                 a->lpe_buf);
    }

    hint = gtk_label_new("载荷固定为内置 192 字节 ELF（setuid(0) + execve /bin/sh），"
                         "只改目标文件的前 192 字节，且只改 page cache。");
    gtk_widget_set_name(hint, "cardvalue");
    gtk_widget_set_halign(hint, GTK_ALIGN_START);
    gtk_widget_set_margin_start(hint, 18);
    gtk_widget_set_margin_top(hint, 2);
    gtk_box_pack_start(GTK_BOX(box), hint, FALSE, FALSE, 0);

    g_signal_connect(a->lpe_btn_build, "clicked", G_CALLBACK(on_lpe_build), a);
    g_signal_connect(a->lpe_btn_run, "clicked", G_CALLBACK(on_lpe_run), a);

    lpe_log(a, "CVE-2026-46300（Fragnesia）\n", "cmd");
    lpe_log(a, "ESP 分片在 TCP coalesce 后被当成普通数据写回页缓存，\n"
               "非特权用户即可改写只读文件。\n", "dim");
    lpe_log(a, "载荷：192 字节 ELF，setuid(0) + execve(\"/bin/sh\")\n", "dim");
    refresh_lpe(a);
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
    gtk_box_pack_start(GTK_BOX(bar), tab_item(a, 3, IC_T_BUG, "漏洞"), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(bar), tab_item(a, 4, IC_T_GEAR, "设置"), TRUE, TRUE, 0);
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
    gtk_stack_add_named(GTK_STACK(a->stack), build_lpe(a), "lpe");
    gtk_stack_add_named(GTK_STACK(a->stack), build_settings(a), "set");

    gtk_box_pack_end(GTK_BOX(shell), build_tabbar(a), FALSE, FALSE, 0);

    gtk_widget_show_all(a->win);
    switch_page(a, 0);

    /* 启动时 GTK 会把焦点交给第一个可获得焦点的控件（漏洞页的目标文件框），
       顺带把里面的路径整段选中，看上去像被用户划了一半。等焦点分配完再清一次。 */
    gtk_window_set_focus(GTK_WINDOW(a->win), NULL);
    g_idle_add(reset_entry_selection, a);
}

int main(int argc, char **argv)
{
    App a;

    memset(&a, 0, sizeof(a));
    gtk_init(&argc, &argv);

    /* 授权文件位置在提权之前定死，免得中途换到 /var/lib */
    a.policy_path = policy_default_path();

    build_ui(&a);

    policy_load(&a);
    knl_sync(&a);
    refresh_home(&a);
    refresh_super(&a);

    term_append(&a, "RootMgr " MGR_VERSION " 终端\n", "dim");
    if (is_root())
        term_append(&a, "当前是 root，命令直接以 root 执行。\n\n", "dim");
    else
        term_append(&a, "当前不是 root，命令会走 sudo -n / pkexec。\n\n", "dim");

    gtk_main();
    return 0;
}
