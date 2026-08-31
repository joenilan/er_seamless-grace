"""List top-level windows owned by eldenring.exe and their titles."""
import ctypes, ctypes.wintypes as wt, subprocess

user32 = ctypes.WinDLL("user32.dll")
enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)

results = []
pids = {}
for proc in subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True).stdout.splitlines():
    parts = [p.strip('"') for p in proc.split('","')]
    if len(parts) >= 2:
        try:
            pids[int(parts[1])] = parts[0]
        except ValueError:
            pass

@enum_proc
def cb(hwnd, lparam):
    pid = wt.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    name = pids.get(pid.value, "?")
    if name.lower() in ("eldenring.exe", "x64dbg.exe", "ersc_launcher.exe"):
        buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, buf, 256)
        if buf.value:
            results.append((name, pid.value, hex(hwnd), buf.value))
    return True

user32.EnumWindows(cb, 0)
for r in results:
    print(f"{r[0]:18} PID {r[1]:6} hwnd {r[2]}: {r[3]}")
