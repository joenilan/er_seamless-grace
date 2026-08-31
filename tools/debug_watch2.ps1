# Grace debug watcher v2b - full automation with inline P/Invoke
$ProgressPreference = "SilentlyContinue"
$game = "E:\SteamLibrary\steamapps\common\ELDEN RING\Game"
$x64dbg = "E:\git\er-seamless-grace\dbg\x64dbg\release\x64\x64dbg.exe"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Native {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr written);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, int size, uint protect, out uint oldp);
    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr h);
    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr h);
}
"@

Get-Process eldenring, x64dbg, ersc_launcher -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1

Start-Process -FilePath "$game\ersc_launcher.exe" -WorkingDirectory $game
$pid2 = $null
foreach ($i in 1..3000) {
    $p = Get-Process eldenring -ErrorAction SilentlyContinue
    if ($p) { $pid2 = $p.Id; break }
    Start-Sleep -Milliseconds 10
}
if (-not $pid2) { Write-Host "no process"; exit 1 }
Write-Host "eldenring PID $pid2"

$erscBase = [IntPtr]::Zero
foreach ($i in 1..3000) {
    $h = Get-Process -Id $pid2 -ErrorAction SilentlyContinue
    if (-not $h) { Write-Host "died"; exit 1 }
    try {
        $m = $h.Modules | Where-Object { $_.ModuleName -ieq "ersc.dll" }
        if ($m) { $erscBase = $m.BaseAddress; break }
    } catch {}
    Start-Sleep -Milliseconds 5
}
if ($erscBase -eq [IntPtr]::Zero) { Write-Host "ersc never mapped"; exit 1 }
$bpAddr = [IntPtr]::New($erscBase.ToInt64() + 0xD5476)
Write-Host ("ersc base {0:X}  bp {1:X}" -f $erscBase.ToInt64(), $bpAddr.ToInt64())

$proc = [Native]::OpenProcess(0x1F0FFF, $false, $pid2)
if ($proc -eq [IntPtr]::Zero) { Write-Host "OpenProcess failed"; exit 1 }

$orig = [byte[]]::new(1); $r = [IntPtr]::Zero
[Native]::ReadProcessMemory($proc, $bpAddr, $orig, 1, [ref]$r) | Out-Null
Write-Host ("original byte: {0:X2}" -f $orig[0])
if ($orig[0] -ne 0xE8) { Write-Host "unexpected byte - aborting"; exit 1 }

$oldp = [uint32]0
[Native]::VirtualProtectEx($proc, $bpAddr, 1, 0x40, [ref]$oldp) | Out-Null
$cc = [byte[]]::new(1); $cc[0] = 0xCC
$w = [IntPtr]::Zero
$ok = [Native]::WriteProcessMemory($proc, $bpAddr, $cc, 1, [ref]$w)
[Native]::VirtualProtectEx($proc, $bpAddr, 1, 0x20, [ref]$oldp) | Out-Null
Write-Host "write 0xCC: $ok"

$rc = [Native]::NtSuspendProcess($proc)
Write-Host "NtSuspendProcess: $rc"

Start-Process -FilePath $x64dbg -ArgumentList "-p $pid2"
Start-Sleep 6

$rc2 = [Native]::NtResumeProcess($proc)
Write-Host "NtResumeProcess: $rc2"
Write-Host "ARMED - in x64dbg press F9 to run; int3 will break at the fatal site"
