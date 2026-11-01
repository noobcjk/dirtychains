/*
 * rootmgr-gui.c —— root 管理器的图形界面
 *
 * 版式参照 KernelSU（Material 3）：浅灰底、大标题、白色圆角卡片。
 * 窗口默认 960x600 横屏，卡片在宽屏下分左右两列，底部是四格切换栏：
 *   主页 / 超级用户 / 终端 / 设置
 *
 * 超级用户页是一张授权表（仿 KernelSU）：
 *   - 默认是空的，程序在终端里执行时会被登记成「待授权」；
 *   - 点一行展开，里面是 root / 禁止 两个选项；
 *   - 记录存在 /var/lib/rootmgr/policy.tsv（非 root 时放用户配置目录），
 *     重启后状态还在；右键可以移除一条记录。
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
#define MGR_VERSION "1.3"

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
static char *policy_file(void)
{
    if (geteuid() == 0)
        return g_strdup("/var/lib/rootmgr/policy.tsv");
    return g_build_filename(g_get_user_config_dir(), "rootmgr", "policy.tsv", NULL);
}

static int policy_get(App *a, const char *path)
{
    if (!a->policy || !path)
        return ST_ASK;
    return GPOINTER_TO_INT(g_hash_table_lookup(a->policy, path));
}

static void policy_load(App *a)
{
    char *pf = policy_file();
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
    char *pf = policy_file();
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
        refresh_super(a);
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
        GtkWidget *hint = gtk_label_new("点一行展开，选 root 或禁止；右键可以移除记录。");
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

    policy_load(&a);
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
