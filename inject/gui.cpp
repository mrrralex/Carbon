// Carbon — menu UI. "Editor" tab: write Luau, press Attach/Inject, then Execute. "Console" tab:
// everything the pipeline (and later the target itself) reports.
//
// Two design rules, both load-bearing:
//
//   * The UI is a thin shell over the SAME pipeline the CLI uses. The self-test gate on the exact
//     payload bytes runs before anything is placed, whether the run started from a button or from
//     the command line. A UI that could skip the gate would be a second, unaudited injector.
//   * Nothing here pretends. If the Luau execution engine is not built yet, pressing Execute says
//     so in the console instead of silently doing nothing or, worse, faking output.
//
// The execution engine is: compile the editor's text HERE (Luau::compile in luau_bridge.cpp, linked
// from third_party/luau-obj), hand the bytecode to the CLIENT's own loader (0x25ffdd0) and then call
// the CLIENT's own resume wrapper (0x418fef0). The mode picker next to the Execute button says how
// far that chain is allowed to go on the next press, and the default is the one that actually runs
// the chunk - a button labelled Execute that refuses to execute would be the misleading thing.
//
// What is NOT claimed: the resume runs on whichever thread delivered the payload, and the client's
// scheduler may be working on that same thread. Every stage the payload reaches is written to the
// target BEFORE the call that follows it, so a run that dies still says where; and the client's own
// liveness is measured after every run instead of assumed (SIGNATURES.md 9.4/9.6).
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <CommCtrl.h>
#include <TlHelp32.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")

/* the pipeline, exposed by injector.cpp */
extern "C" void          ccui_set_sink(void (*fn)(const char*));
extern "C" int           ccui_selftest(void);                 /* 0 = gate passed            */
extern "C" unsigned long ccui_find_roblox(void);              /* pid or 0                   */
extern "C" int           ccui_version_ok(unsigned long pid);  /* 0 = cec3ad58, 1 = mismatch */
extern "C" int           ccui_attach(unsigned long pid, int timeout_ms, int watch_ms, int threads,
                                      int use_redirect);
extern "C" int           ccui_compile(const char* source, size_t len, char* summary, size_t cap);
extern "C" int           ccui_exec(unsigned long pid, const char* source, int mode, int* exec_status_out);

namespace {

enum {
    ID_TAB = 1001, ID_EDIT, ID_CONSOLE, ID_ATTACH, ID_EXECUTE, ID_STATUS, ID_MODE, ID_DELIVERY,
    ID_M_ATTACH = 2001, ID_M_EXECUTE, ID_M_CLEAR, ID_M_ABOUT, ID_M_EXIT
};

/* The modes the payload understands (payload.h / SIGNATURES.md 9.5, 9.10). Kept as an enum so the
   combo box and ccui_exec cannot drift apart. The DEFAULT is now the container: the direct loader
   call is refused unless the state's [L+0x18] satisfies the loader's own first dereference, measured
   live on 2026-10-10, so leading with it would lead with a refusal. */
enum { MODE_DRY = 3, MODE_LOAD = 1, MODE_RUN = 2, MODE_CONTAINER = 4, MODE_CONTAINER_LOAD = 5 };

/* How the payload gets to run at all, which is a separate question from what it then does, and the
   one the Attach button used to answer silently wrong: it always queued APCs, and APCs essentially
   never dispatch on this client (146 across all threads over 60 s, zero dispatches - SIGNATURES.md
   9.4). Redirecting one thread's RIP at a stub is the delivery every run that actually reached the
   payload has used. Index IS the flag: [0] = APC only, [1] = redirect. */
enum { DELIVERY_APC = 0, DELIVERY_REDIRECT = 1 };

constexpr UINT WM_APP_LOG  = WM_APP + 1;   /* lParam = heap char*, freed by the handler */
constexpr UINT WM_APP_DONE = WM_APP + 2;   /* worker finished                          */

HWND  g_hwnd = nullptr, g_tab = nullptr, g_edit = nullptr, g_console = nullptr;
HWND  g_attach = nullptr, g_execute = nullptr, g_status = nullptr, g_mode = nullptr;
HWND  g_delivery = nullptr;
HFONT g_fontMono = nullptr, g_fontUi = nullptr;
bool  g_busy = false;
unsigned long g_pid = 0;
int   g_exec_mode = MODE_RUN;      /* what the next Execute press is allowed to do */
int   g_delivery_mode = DELIVERY_REDIRECT;  /* how the next Attach press delivers the payload */

/* the combo's index -> mode, in one place. [0] is the client's own entry.
   The order on screen and the mapping live together so they cannot drift: the label the operator
   picks is the mode number they get. */
int mode_from_index(int idx)
{
    switch (idx) {
        case 1:  return MODE_CONTAINER_LOAD;
        case 2:  return MODE_RUN;
        case 3:  return MODE_LOAD;
        case 4:  return MODE_DRY;
        default: return MODE_CONTAINER;
    }
}

/* the delivery combo's index -> flag, same rule: the mapping lives in exactly one place */
int delivery_from_index(int idx) { return idx == DELIVERY_APC ? DELIVERY_APC : DELIVERY_REDIRECT; }

const char* delivery_name(int mode)
{
    return mode == DELIVERY_APC ? "APC only" : "thread redirect";
}

/* ---- console plumbing: every line goes through PostMessage so only the UI thread touches a
        control, while the worker thread (and the pipeline's own logf_) can emit at any time ---- */

/* <exe>_ui_trace.txt: the console path is the one thing an external probe cannot see into, so when a
   line is dropped there has to be a record of it. Absolute, next to the exe - a relative path lands
   in whatever directory the process happened to inherit, which is where the first version of this
   instrumentation ended up. Only anomalies are written, so the file stays empty when all is well. */
void trace(const char* fmt, ...)
{
    static FILE* f = nullptr;
    if (!f) {
        char path[MAX_PATH]{};
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        char* dot = strrchr(path, '.');
        if (dot) *dot = 0;
        strncat_s(path, "_ui_trace.txt", _TRUNCATE);
        fopen_s(&f, path, "w");
        if (!f) return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fflush(f);
}

void console_line(const char* line)
{
    if (!g_hwnd) return;
    char* copy = _strdup(line);
    if (!copy) { trace("strdup failed len=%zu\n", strlen(line)); return; }
    if (!PostMessageA(g_hwnd, WM_APP_LOG, 0, (LPARAM)copy)) {
        trace("post failed err=%lu len=%zu\n", GetLastError(), strlen(line));
        free(copy);
    }
}

void consolef(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    console_line(buf);
}

void sink(const char* line) { console_line(line); }   /* logf_ -> console tab */

/* The console control is ES_READONLY, and EM_REPLACESEL is IGNORED on a read-only edit - silently,
   with no error. Every log line was vanishing until the button probe showed an empty tab. Clearing
   the read-only style for the duration of the replace is the documented way; the console is
   permanently read-only by design (it is output, not input), so the style is set back after. */
void append(HWND h, const char* text)
{
    SendMessageA(h, EM_SETREADONLY, FALSE, 0);
    int n = GetWindowTextLengthA(h);
    SendMessageA(h, EM_SETSEL, (WPARAM)n, (LPARAM)n);
    SendMessageA(h, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessageA(h, EM_SCROLLCARET, 0, 0);
    SendMessageA(h, EM_SETREADONLY, TRUE, 0);
}

void set_status(const char* text) { if (g_status) SetWindowTextA(g_status, text); }

void refresh_status(const char* suffix = nullptr)
{
    /* Re-detect before building the line. The status used to be computed from whatever happened to be
       running when the window opened, so a client started afterwards left the line reading "not
       running" while the Attach button would in fact have found that client - the worker re-detects
       whenever g_pid is 0. A status that contradicts the button is worse than no status: it is the
       one thing a user reads to decide whether to press. ccui_version_ok() answers 2 for a pid that
       no longer exists, which is what lets a dead target self-correct instead of pinning the window
       to a process that is already gone. */
    if (!g_pid || ccui_version_ok(g_pid) == 2) g_pid = ccui_find_roblox();
    char buf[512];
    char target[128];
    if (g_pid) {
        int v = ccui_version_ok(g_pid);
        _snprintf_s(target, sizeof(target), _TRUNCATE, "pid %lu (%s)", g_pid,
                    v == 0 ? "cec3ad58" : v == 1 ? "VERSION MISMATCH" : "version unknown");
    } else {
        _snprintf_s(target, sizeof(target), _TRUNCATE, "not running");
    }
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "target: %s   |   attach delivery: %s   |   self-test gate: run before every attach   "
                "|   engine: compile -> client loader 0x25ffdd0 -> resume 0x418fef0%s%s",
                target, delivery_name(g_delivery_mode), suffix ? "   |   " : "",
                suffix ? suffix : "");
    set_status(buf);
}

/* ---- worker: attach must not block the UI ---- */

DWORD WINAPI attach_worker(LPVOID)
{
    console_line("--- attach requested from the UI ---\r\n");
    int st = ccui_selftest();
    if (st != 0) {
        consolef("[gate ] self-test FAILED (code %d) - refusing to attach. The payload bytes that\r\n"
                  "        would have gone into the client did not behave here first.\r\n", st);
        PostMessage(g_hwnd, WM_APP_DONE, 0, 0);
        return 0;
    }
    console_line("[gate ] self-test PASSED - the exact payload bytes were executed here first\r\n");

    unsigned long pid = g_pid ? g_pid : ccui_find_roblox();
    if (!pid) {
        console_line("[target] RobloxPlayerBeta.exe is not running - open an experience, then attach\r\n");
        PostMessage(g_hwnd, WM_APP_DONE, 0, 0);
        return 0;
    }
    g_pid = pid;

    int v = ccui_version_ok(pid);
    if (v == 1) {
        console_line("[target] VERSION MISMATCH: this client is not version-cec3ad5889b447cf.\r\n"
                     "         Every offset in this build is version-locked; refusing to inject.\r\n");
        PostMessage(g_hwnd, WM_APP_DONE, 0, 0);
        return 0;
    }
    consolef("[target] pid %lu accepted\r\n", pid);

    /* Say which delivery is about to be used BEFORE it is used. The two are not variations in
       style: one steals a thread's RIP and is the only one measured to dispatch on this client,
       the other is safe and usually does nothing. */
    consolef("[deliver] %s\r\n", g_delivery_mode == DELIVERY_REDIRECT
        ? "thread redirect: one thread is suspended, its RIP pointed at a stub that calls the\r\n"
          "          payload, and its saved context restored on the way out. This is the delivery\r\n"
          "          that actually runs; a redirect that lands badly can kill the client.\r\n"
        : "APC only: nothing is stolen, no thread context is touched - and measured on this client\r\n"
          "          APCs do not dispatch (146 across all threads over 60 s, zero dispatches), so\r\n"
          "          this will usually report no dispatch.\r\n");

    ccui_attach(pid, 5000, 0, 12, g_delivery_mode);
    PostMessage(g_hwnd, WM_APP_DONE, 0, 0);
    return 0;
}

void start_attach()
{
    if (g_busy) return;
    g_busy = true;
    EnableWindow(g_attach, FALSE);
    EnableWindow(g_execute, FALSE);
    set_status(g_delivery_mode == DELIVERY_REDIRECT
                   ? "working: gate, then attach (thread redirect)..."
                   : "working: gate, then attach (APC only)...");
    HANDLE th = CreateThread(nullptr, 0, attach_worker, nullptr, 0, nullptr);
    if (th) CloseHandle(th);
    else { g_busy = false; EnableWindow(g_attach, TRUE); console_line("[ui   ] could not start worker thread\r\n"); }
}

/* Did the client survive the run? This cannot be inferred from our own report: a delivery that gets
   swallowed can kill the client AFTER the payload has already reported success (SIGNATURES.md 9.4).
   So it is measured after every run and printed, instead of assumed from an exit code we never read. */
void client_after_run(unsigned long pid)
{
    if (!pid) { console_line("[post ] no target to check\r\n"); return; }
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!p) {
        consolef("[post ] the client is GONE (OpenProcess err=%lu) - it exited after the run\r\n",
                 GetLastError());
        return;
    }
    DWORD ec = 0;
    bool alive = GetExitCodeProcess(p, &ec) && ec == STILL_ACTIVE;
    int threads = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{ sizeof(te) };
        if (Thread32First(snap, &te)) {
            do { if (te.th32OwnerProcessID == (DWORD)pid) ++threads; } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    CloseHandle(p);
    if (alive) consolef("[post ] client survived the run: pid %lu alive, %d thread(s)\r\n", pid, threads);
    else       consolef("[post ] the client EXITED (code 0x%lx) - suspect the run just made\r\n", ec);
}

/* Execute runs on a worker thread like Attach does: the exec path blocks on the target's own
   timing, and a frozen menu would hide exactly the moment worth watching. */
DWORD WINAPI exec_worker(LPVOID param)
{
    char* code = (char*)param;
    const int mode = g_exec_mode;
    consolef("[exec ] mode %d - %s\r\n", mode,
             mode == MODE_DRY  ? "dry run: every guard plus the loader's argument struct, nothing called"
           : mode == MODE_LOAD ? "load only: call the client's own loader (0x25ffdd0), no resume"
                               : "load + resume: the loader pushes the chunk, then 0x418fef0 runs it");
    int rc = ccui_exec(g_pid, code, mode, nullptr);
    consolef("[exec ] rc=%d. Full report, every stage: injector_log.txt next to the exe\r\n", rc);
    client_after_run(g_pid);
    if (mode == MODE_RUN)
        console_line("[exec ] the chunk's own output is not ours to see: have it print(...) and read\r\n"
                     "        %LOCALAPPDATA%\\Roblox\\logs\\<version>_Player_*_last.log\r\n");
    free(code);
    PostMessage(g_hwnd, WM_APP_DONE, 0, 0);
    return 0;
}

void on_execute()
{
    int n = GetWindowTextLengthA(g_edit);
    char* code = (char*)malloc((size_t)n + 1);
    if (!code) return;
    GetWindowTextA(g_edit, code, n + 1);

    console_line("\r\n--- execute ---\r\n");
    int lines = 1;
    for (int i = 0; i < n; ++i) if (code[i] == '\n') ++lines;
    consolef("[exec ] %d byte(s), %d line(s) of Luau from the editor.\r\n", n, lines);

    /* The compile half is real and runs here, in this process: the editor's text is compiled to
       Luau bytecode by the prebuilt compiler objects, and the result is checked against the rule
       the CLIENT's loader enforces (version 3..14, type version 1..3). A syntax error is reported
       with the compiler's own message. Only the bytes would ever cross into the target. */
    if (n > 0) {
        char summary[512] = { 0 };
        int rc = ccui_compile(code, (size_t)n, summary, sizeof(summary));
        consolef("[exec ] %s\r\n", summary);
        if (rc == 0) {
            console_line("[exec ] chain: compile (done above) -> loader 0x25ffdd0 -> resume 0x418fef0.\r\n"
                         "        The loader's argument struct and the resume call form are pinned from\r\n"
                         "        the client's own code; see SIGNATURES.md 9.1/9.2.\r\n");
            if (!g_pid) {
                console_line("[exec ] attach first: the bytecode only matters once there is a state to load it into\r\n");
            } else if (g_busy) {
                console_line("[exec ] busy with another run - try again when the status line settles\r\n");
            } else {
                console_line("[exec ] what the press will do is the mode picked next to the button.\r\n"
                             "        Load + resume is the one that runs the chunk; the resume then runs on\r\n"
                             "        the thread that delivered the payload, which no run has yet proven\r\n"
                             "        end to end - so the client's liveness is measured afterwards and\r\n"
                             "        printed, instead of being assumed.\r\n");
                /* No modal dialog: pressing Execute is the consent, a popup here would block this
                   thread (and the external ui_probe that drives this window through
                   SendMessage). What the press will do is stated in the console below, and the
                   client's liveness is measured after the run rather than assumed. */
                g_busy = true;
                EnableWindow(g_execute, FALSE);
                EnableWindow(g_attach, FALSE);
                EnableWindow(g_mode, FALSE);       /* the mode cannot change mid-run */
                set_status(g_exec_mode == MODE_RUN  ? "working: compile -> loader -> resume on the client..."
                         : g_exec_mode == MODE_LOAD ? "working: compile -> loader (no resume)..."
                                                    : "working: dry exec run (guards + struct, no call)...");
                HANDLE th = CreateThread(nullptr, 0, exec_worker, code, 0, nullptr);
                if (th) { CloseHandle(th); return; }       /* code is owned by the worker now */
                g_busy = false;
                EnableWindow(g_execute, TRUE);
                EnableWindow(g_attach, TRUE);
                EnableWindow(g_mode, TRUE);
                console_line("[ui   ] could not start the worker thread\r\n");
            }
        }
    }
    free(code);
    refresh_status();
}

/* ---- layout ---- */

RECT page_rect(HWND hwnd)
{
    RECT rc{};
    GetClientRect(hwnd, &rc);
    RECT pg{ 10, 32, rc.right - 10, rc.bottom - 30 };
    if (pg.right < pg.left + 200) pg.right = pg.left + 200;
    if (pg.bottom < pg.top + 100) pg.bottom = pg.top + 100;
    return pg;
}

void layout(HWND hwnd)
{
    RECT rc{};
    GetClientRect(hwnd, &rc);
    MoveWindow(g_tab, 6, 6, rc.right - 12, rc.bottom - 12 - 26, TRUE);

    RECT pg = page_rect(hwnd);
    const int pw = pg.right - pg.left, ph = pg.bottom - pg.top;
    const int btnW = 150, btnH = 32, pad = 8;

    MoveWindow(g_edit, pg.left, pg.top, pw, ph - btnH - pad, TRUE);
    MoveWindow(g_attach, pg.left, pg.top + ph - btnH, btnW, btnH, TRUE);
    MoveWindow(g_execute, pg.left + btnW + pad, pg.top + ph - btnH, btnW, btnH, TRUE);
    MoveWindow(g_mode, pg.left + 2 * (btnW + pad), pg.top + ph - btnH, 260, btnH + 200, TRUE);
    MoveWindow(g_delivery, pg.left + 2 * (btnW + pad) + 260 + pad, pg.top + ph - btnH, 300,
               btnH + 200, TRUE);
    MoveWindow(g_console, pg.left, pg.top, pw, ph, TRUE);
    MoveWindow(g_status, 8, rc.bottom - 24, rc.right - 16, 20, TRUE);

    int sel = (int)SendMessage(g_tab, TCM_GETCURSEL, 0, 0);
    const BOOL editor = (sel <= 0);
    ShowWindow(g_edit, editor ? SW_SHOW : SW_HIDE);
    ShowWindow(g_attach, editor ? SW_SHOW : SW_HIDE);
    ShowWindow(g_execute, editor ? SW_SHOW : SW_HIDE);
    ShowWindow(g_mode, editor ? SW_SHOW : SW_HIDE);
    ShowWindow(g_delivery, editor ? SW_SHOW : SW_HIDE);
    ShowWindow(g_console, editor ? SW_HIDE : SW_SHOW);
}

/* ---- window ---- */

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        g_tab = CreateWindowExA(0, WC_TABCONTROLA, "", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                0, 0, 10, 10, hwnd, (HMENU)ID_TAB, nullptr, nullptr);
        TCITEMW it{};
        it.mask = TCIF_TEXT;
        it.pszText = (LPWSTR)L"Editor";  TabCtrl_InsertItem(g_tab, 0, &it);
        it.pszText = (LPWSTR)L"Console"; TabCtrl_InsertItem(g_tab, 1, &it);

        g_edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "print(\"hello\")",
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                 ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN | ES_NOHIDESEL,
                                 0, 0, 10, 10, hwnd, (HMENU)ID_EDIT, nullptr, nullptr);
        g_attach = CreateWindowExA(0, "BUTTON", "Attach / Inject",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                   0, 0, 10, 10, hwnd, (HMENU)ID_ATTACH, nullptr, nullptr);
        g_execute = CreateWindowExA(0, "BUTTON", "Execute",
                                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                    0, 0, 10, 10, hwnd, (HMENU)ID_EXECUTE, nullptr, nullptr);
        /* The mode the payload is allowed to reach. The index IS the mode number via
           mode_from_index(), so the two cannot drift: [0] runs the chunk, [2] is the dry run. */
        g_mode = CreateWindowExA(0, "COMBOBOX", "",
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST,
                                 0, 0, 10, 300, hwnd, (HMENU)ID_MODE, nullptr, nullptr);
        SendMessageA(g_mode, CB_ADDSTRING, 0, (LPARAM)"Run  -  the client's own entry  (LuaVM_Load)");
        SendMessageA(g_mode, CB_ADDSTRING, 0, (LPARAM)"Container only  (LuaVM_Load, no resume)");
        SendMessageA(g_mode, CB_ADDSTRING, 0, (LPARAM)"Run  -  bytecode loader + resume  (direct)");
        SendMessageA(g_mode, CB_ADDSTRING, 0, (LPARAM)"Loader only  (no resume)");
        SendMessageA(g_mode, CB_ADDSTRING, 0, (LPARAM)"Dry run  (guards + struct, no call)");
        SendMessageA(g_mode, CB_SETCURSEL, (WPARAM)0, 0);
        g_exec_mode = mode_from_index(0);
        /* Delivery for the Attach press. Index IS the flag via delivery_from_index(), so the list
           and ccui_attach cannot drift apart; the default is the one that delivers, for the same
           reason the Execute picker defaults to the mode that runs the chunk. */
        g_delivery = CreateWindowExA(0, "COMBOBOX", "",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST,
                                     0, 0, 10, 300, hwnd, (HMENU)ID_DELIVERY, nullptr, nullptr);
        SendMessageA(g_delivery, CB_ADDSTRING, 0, (LPARAM)"APC only  (safe, rarely dispatches)");
        SendMessageA(g_delivery, CB_ADDSTRING, 0, (LPARAM)"Thread redirect  (delivers)");
        SendMessageA(g_delivery, CB_SETCURSEL, (WPARAM)DELIVERY_REDIRECT, 0);
        g_delivery_mode = delivery_from_index(DELIVERY_REDIRECT);
        g_console = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                    WS_CHILD | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                    ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
                                    0, 0, 10, 10, hwnd, (HMENU)ID_CONSOLE, nullptr, nullptr);
        g_status = CreateWindowExA(0, "STATIC", "", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   0, 0, 10, 10, hwnd, (HMENU)ID_STATUS, nullptr, nullptr);

        g_fontMono = CreateFontA(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                 FIXED_PITCH | FF_MODERN, "Consolas");
        g_fontUi = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        SendMessageA(g_edit, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
        SendMessageA(g_console, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
        SendMessageA(g_attach, WM_SETFONT, (WPARAM)g_fontUi, TRUE);
        SendMessageA(g_execute, WM_SETFONT, (WPARAM)g_fontUi, TRUE);
        SendMessageA(g_mode, WM_SETFONT, (WPARAM)g_fontUi, TRUE);
        SendMessageA(g_delivery, WM_SETFONT, (WPARAM)g_fontUi, TRUE);
        SendMessageA(g_status, WM_SETFONT, (WPARAM)g_fontUi, TRUE);
        SendMessageA(g_tab, WM_SETFONT, (WPARAM)g_fontUi, TRUE);

        ccui_set_sink(sink);
        console_line("Carbon menu UI\r\n");
        console_line("Editor tab holds the Luau chunk; Attach/Inject runs the gate, finds the client\r\n"
                     "and places the read-only payload. Console tab shows everything it reports.\r\n");
        console_line("Two pickers, both stated rather than hidden. Attach delivery: thread redirect\r\n"
                     "is the one that dispatches on this client, APC-only steals nothing and usually\r\n"
                     "does nothing. Execute mode: how far the chunk is allowed to go.\r\n");
        g_pid = ccui_find_roblox();
        refresh_status();
        layout(hwnd);
        return 0;
    }
    case WM_ACTIVATE:
        /* Clicking the window is when a user looks at the status line, so that is when it is worth
           re-reading the target: start the client after the UI, alt-tab back, and the line is right
           without a button press. */
        if (LOWORD(wp) != WA_INACTIVE) refresh_status();
        return 0;
    case WM_SIZE:
        layout(hwnd);
        return 0;
    case WM_NOTIFY: {
        auto nm = (LPNMHDR)lp;
        if (nm && nm->idFrom == ID_TAB && nm->code == TCN_SELCHANGE) layout(hwnd);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == ID_MODE && HIWORD(wp) == CBN_SELCHANGE) {
            g_exec_mode = mode_from_index((int)SendMessageA(g_mode, CB_GETCURSEL, 0, 0));
            consolef("[ui   ] next Execute will use mode %d\r\n", g_exec_mode);
            return 0;
        }
        if (LOWORD(wp) == ID_DELIVERY && HIWORD(wp) == CBN_SELCHANGE) {
            g_delivery_mode = delivery_from_index((int)SendMessageA(g_delivery, CB_GETCURSEL, 0, 0));
            consolef("[ui   ] next Attach / Inject will use %s\r\n", delivery_name(g_delivery_mode));
            return 0;
        }
        switch (LOWORD(wp)) {
        case ID_ATTACH: case ID_M_ATTACH: start_attach(); return 0;
        case ID_EXECUTE: case ID_M_EXECUTE: on_execute(); return 0;
        case ID_M_CLEAR: SetWindowTextA(g_console, ""); return 0;
        case ID_M_ABOUT:
            MessageBoxA(hwnd,
                        "Carbon menu UI\n\n"
                        "Attach/Inject runs the payload self-test gate first, then places the\n"
                        "read-only payload with an APC - no CreateRemoteThread, no module.\n\n"
                        "Execute compiles the editor's Luau here (Luau::compile, linked from\n"
                        "third_party/luau-obj), then hands the bytecode to the client's own loader\n"
                        "(0x25ffdd0) and, in the default mode, calls the client's own resume wrapper\n"
                        "(0x418fef0). Both contracts are read out of the client's code, not assumed\n"
                        "(SIGNATURES.md 9.1/9.2). The mode picker says how far to go.\n\n"
                        "Attach delivery is a picker because the two are not equivalent: thread\n"
                        "redirect is the only one measured to run the payload on this client, and\n"
                        "APC-only, while it steals nothing, mostly never dispatches.\n\n"
                        "Stated rather than hidden: the resume runs on the thread that delivered the\n"
                        "payload, so the client's liveness is measured after every run.\n",
                        "Carbon", MB_OK | MB_ICONINFORMATION);
            return 0;
        case ID_M_EXIT: DestroyWindow(hwnd); return 0;
        }
        return 0;
    case WM_APP_LOG: {
        char* line = (char*)lp;
        if (line) {
            /* Invariant guard, not decoration: a read-only edit silently ignores EM_REPLACESEL, which
               is exactly how every log line once vanished with no error anywhere. If the control did
               not grow, that has happened again and it is recorded rather than swallowed. */
            int before = g_console ? GetWindowTextLengthA(g_console) : -1;
            append(g_console, line);
            int after = g_console ? GetWindowTextLengthA(g_console) : -1;
            if (g_console && after <= before) trace("append did not grow the console (%d -> %d)\n", before, after);
            free(line);
        }
        return 0;
    }
    case WM_APP_DONE:
        g_busy = false;
        EnableWindow(g_attach, TRUE);
        EnableWindow(g_execute, TRUE);
        if (!g_pid) g_pid = ccui_find_roblox();
        refresh_status();
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

}  // namespace

/* Entry point used by injector.cpp when it is started with --ui. */
extern "C" int cc_ui_run()
{
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_TAB_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSA wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "CarbonUI";
    if (!RegisterClassA(&wc)) return 1;

    HMENU menu = CreateMenu();
    HMENU pop = CreatePopupMenu();
    AppendMenuA(pop, MF_STRING, ID_M_ATTACH, "&Attach / Inject");
    AppendMenuA(pop, MF_STRING, ID_M_EXECUTE, "&Execute");
    AppendMenuA(pop, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(pop, MF_STRING, ID_M_CLEAR, "&Clear console");
    AppendMenuA(pop, MF_STRING, ID_M_ABOUT, "&How this works");
    AppendMenuA(pop, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(pop, MF_STRING, ID_M_EXIT, "E&xit");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)pop, "&Carbon");

    HWND hwnd = CreateWindowExA(0, "CarbonUI", "Carbon - Editor",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 720,
                                nullptr, menu, wc.hInstance, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageA(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageA(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    return 0;
}
