# Carbon — write a minidump of a live Roblox client.
#
# Why: when the client dies after a run, crashpad uploads its minidump and deletes the local copy,
# so there is nothing left to post-mortem. If the client is parked on Roblox's "unexpected error"
# dialog its threads (and their stacks, if the fault is still on one) are still there to read.
#
#   powershell -File tools/dump_client.ps1                 # all RobloxPlayerBeta, into tools/out
#   powershell -File tools/dump_client.ps1 -ProcId 21032   # one process
#   powershell -File tools/dump_client.ps1 -Full           # full memory (GBs, slow, last resort)
#
# MiniDumpNormal already carries every thread's CONTEXT and the memory of its stack, which is what
# we need to answer "faulting rip in the client image (rva) or in ntdll". Full memory is only for
# when a stack walk needs heap-resident frames; it costs gigabytes and minutes.

# NB: $Pid is a read-only automatic variable in PowerShell 5.1 -- the parameter is $ProcId.
param(
  [int]$ProcId = 0,
  [switch]$Full,
  [string]$OutDir = ""
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $repo 'tools\out' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Add-Type adds `using System.Runtime.InteropServices;` itself, so only the SafeHandles one is listed.
Add-Type -Namespace CarbonDump -Name Native -UsingNamespace Microsoft.Win32.SafeHandles -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct MINIDUMP_EXCEPTION_INFORMATION {
    public uint ThreadId;
    public IntPtr ExceptionPointers;
    public bool ClientPointers;
}

[DllImport("dbghelp.dll", SetLastError = true)]
public static extern bool MiniDumpWriteDump(
    IntPtr hProcess, uint ProcessId, SafeFileHandle hFile,
    uint DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
'@

# 0 = MiniDumpNormal (thread contexts + stack memory); 0x1000 = MiniDumpWithThreadInfo
$type = 0
if ($Full) { $type = 0x2 }  # MiniDumpWithFullMemory

$targets = @()
if ($ProcId -gt 0) {
  $p = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
  if (-not $p) { Write-Error "pid $ProcId is not running"; exit 2 }
  $targets = @($p)
} else {
  $targets = @(Get-Process RobloxPlayerBeta -ErrorAction SilentlyContinue)
  if ($targets.Count -eq 0) { Write-Error "no RobloxPlayerBeta process is running"; exit 2 }
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
foreach ($t in $targets) {
  $path = Join-Path $OutDir ("client_{0}_{1}.dmp" -f $t.Id, $stamp)
  Write-Host ("dumping pid {0} ({1} threads, {2:N0} MB working set) -> {3}" -f `
    $t.Id, $t.Threads.Count, ($t.WorkingSet64 / 1MB), $path)
  $fs = [System.IO.File]::Create($path)
  try {
    $ok = [CarbonDump.Native]::MiniDumpWriteDump($t.Handle, [uint32]$t.Id, $fs.SafeFileHandle,
                                                 [uint32]$type, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if (-not $ok) {
      $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      Write-Error ("MiniDumpWriteDump failed for pid {0}: win32 error {1}" -f $t.Id, $err)
    }
  } finally { $fs.Dispose() }
  $fi = Get-Item $path
  Write-Host ("  wrote {0:N0} bytes" -f $fi.Length)
}
