<#
 DNSHollow Windows agent installer (served by the manager at /install/windows.ps1).
 Run it in an ADMINISTRATOR PowerShell on the Windows machine you want to watch.

   Install:  powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Invoke-RestMethod -UseBasicParsing 'http://MANAGER:8000/install/windows.ps1'))) -Server 'http://MANAGER:8000' -Token 'TOKEN' -Sha256 'HASH' -EnableBlocking"
   Remove:   powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Invoke-RestMethod -UseBasicParsing 'http://MANAGER:8000/install/windows.ps1'))) -Server 'http://MANAGER:8000' -Uninstall"

 Options: -Insecure (self-signed HTTPS)   -EnableBlocking (let the manager block DNS here)
          -NoService (install the files only)

 What it does: checks Python 3.8+, downloads the agent from the manager and verifies its
 SHA-256, registers this machine with the one-time token, runs a self-check, then creates a
 Scheduled Task that runs the agent as SYSTEM at every boot and restarts it if it crashes.
#>
param(
  [string]$Server = "",
  [string]$Token = "",
  [string]$Sha256 = "",
  [switch]$Insecure,
  [switch]$EnableBlocking,
  [switch]$NoService,
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$AppDir  = Join-Path $env:ProgramFiles 'DNSHollow\agent'
$DataDir = Join-Path $env:ProgramData  'DNSHollow'
$Conf    = Join-Path $DataDir 'agent.json'
$Spool   = Join-Path $DataDir 'spool'
$LogFile = Join-Path $DataDir 'agent.log'
$Runner  = Join-Path $AppDir  'run-agent.cmd'
$TaskName = 'DNSHollow Agent'

function Say($m)  { Write-Host "==> $m" -ForegroundColor Green }
function Warn($m) { Write-Host "WARNING: $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

try {
  $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "Run this in an Administrator PowerShell (right-click PowerShell, Run as administrator)."
  }

  # ---- web settings: TLS 1.2, optional self-signed certificate ----
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $web = @{ UseBasicParsing = $true }
  if ($Insecure) {
    if ($PSVersionTable.PSVersion.Major -ge 6) { $web['SkipCertificateCheck'] = $true }
    else { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
  }

  # ---- find Python (a machine-wide one: the service runs as SYSTEM) ----
  function Find-Python {
    $cands = @()
    foreach ($n in 'python.exe', 'python3.exe') {
      $c = Get-Command $n -ErrorAction SilentlyContinue
      if ($c) { $cands += $c.Source }
    }
    foreach ($root in @($env:ProgramFiles, "${env:ProgramFiles(x86)}", (Join-Path $env:LOCALAPPDATA 'Programs\Python'))) {
      if ($root -and (Test-Path $root)) {
        $cands += Get-ChildItem -Path $root -Filter 'python.exe' -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                  Where-Object { $_.FullName -match 'Python3\d+' } | Sort-Object FullName -Descending |
                  ForEach-Object { $_.FullName }
      }
    }
    foreach ($p in ($cands | Select-Object -Unique)) {
      if ($p -match 'WindowsApps') { continue }        # the Store shortcut does not work for SYSTEM
      $v = & $p -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
      if ($LASTEXITCODE -eq 0 -and $v) {
        $parts = $v.Trim().Split('.')
        if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 8) { return $p }
      }
    }
    return $null
  }

  # ---------------- uninstall ----------------
  if ($Uninstall) {
    Say "Removing the DNSHollow agent"
    $py = Find-Python
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
      Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
      Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -like '*dnshollow_agent*' } |
      ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    if ($py -and (Test-Path $AppDir)) {
      $env:PYTHONPATH = $AppDir
      & $py -m dnshollow_agent --unblock-all          # take our DNS block rules out of Windows
    }
    Remove-Item -Recurse -Force (Split-Path $AppDir -Parent) -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
    Say "Done. (Delete the agent in the dashboard too if you no longer need it.)"
    exit 0
  }

  # ---------------- checks ----------------
  if (-not $Server) { Die "-Server is required (the manager address, e.g. http://192.168.1.10:8000)" }
  $Server = $Server.TrimEnd('/')
  if (-not $Token -and -not (Test-Path $Conf)) { Die "-Token is required for a first install (copy the command from the dashboard)" }
  if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) { Die "tar.exe was not found. It ships with Windows 10 (1803+) and Windows Server 2019+." }

  $py = Find-Python
  if (-not $py) {
    Die ("Python 3.8 or newer was not found. Install it for all users, then run this command again:`n" +
         "    winget install -e --id Python.Python.3.12 --scope machine`n" +
         "(or download it from https://www.python.org/downloads/ and tick 'Install for all users').")
  }
  Say "Using Python at $py"

  # ---------------- download + verify ----------------
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("dnshollow-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $archive = Join-Path $tmp 'agent.tar.gz'
    Say "Downloading the agent from $Server"
    try { Invoke-WebRequest @web -Uri "$Server/api/v1/agent/bundle.tar.gz" -OutFile $archive }
    catch { Die "Cannot download the agent. Is $Server reachable from this machine? ($($_.Exception.Message))" }
    if ($Sha256) {
      $got = (Get-FileHash -Algorithm SHA256 -Path $archive).Hash.ToLower()
      if ($got -ne $Sha256.ToLower()) { Die "Checksum mismatch! Expected $Sha256 but got $got. The download was changed. Nothing was installed." }
      Say "Checksum OK"
    } else { Warn "No -Sha256 given: the download was not verified." }

    # ---------------- install ----------------
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
      Say "Stopping the running agent (upgrade)"
      Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 2
    }
    Say "Installing to $AppDir"
    New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
    if (Test-Path (Join-Path $AppDir 'dnshollow_agent')) { Remove-Item -Recurse -Force (Join-Path $AppDir 'dnshollow_agent') }
    & tar.exe -xzf $archive -C $AppDir
    if ($LASTEXITCODE -ne 0) { Die "Could not unpack the agent (tar.exe failed)." }
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }

  # data folder: only SYSTEM and Administrators (it holds the agent key)
  New-Item -ItemType Directory -Force -Path $DataDir, $Spool | Out-Null
  & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

  # ---------------- register with the manager ----------------
  if ($Token) {
    Say "Registering this machine with the manager"
    $os = ("{0} {1}" -f (Get-CimInstance Win32_OperatingSystem).Caption.Trim(), [Environment]::OSVersion.Version)
    if ($os.Length -gt 64) { $os = $os.Substring(0, 64) }
    $body = @{ token = $Token; os = $os } | ConvertTo-Json -Compress
    try {
      $r = Invoke-RestMethod @web -Method Post -Uri "$Server/api/v1/agent/enroll" -ContentType 'application/json' -Body $body
    } catch {
      $msg = $_.Exception.Message
      if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        try { $msg = ($_.ErrorDetails.Message | ConvertFrom-Json).detail } catch { $msg = $_.ErrorDetails.Message }
      }
      Die "Registration failed: $msg"
    }
    $cfg = [ordered]@{
      server = $Server; api_key = $r.api_key; name = $r.name; verify_tls = (-not $Insecure)
      spool_dir = $Spool; log_file = $LogFile; allow_blocking = [bool]$EnableBlocking
    }
    # UTF-8 WITHOUT a byte-order mark
    [IO.File]::WriteAllText($Conf, ($cfg | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    Say "Registered as '$($r.name)'"
  } else {
    Say "Keeping the existing configuration"
  }

  # ---------------- self-check ----------------
  $env:PYTHONPATH = $AppDir
  Say "Checking capture permission, a test lookup and the manager connection"
  & $py -m dnshollow_agent --config $Conf --check
  if ($LASTEXITCODE -ne 0) { Die "The self-check failed (see above). Nothing is running yet." }

  if ($NoService) {
    Say "Installed (no service). Start it with:"
    Write-Host "    `$env:PYTHONPATH='$AppDir'; & '$py' -m dnshollow_agent --config '$Conf'"
    exit 0
  }

  # ---------------- scheduled task: SYSTEM, at boot, restart on crash ----------------
  Say "Creating the scheduled task (starts at boot, restarts on crash)"
  $cmd = "@echo off`r`nset PYTHONPATH=$AppDir`r`nset PYTHONUNBUFFERED=1`r`n`"$py`" -m dnshollow_agent --config `"$Conf`"`r`n"
  [IO.File]::WriteAllText($Runner, $cmd, (New-Object Text.UTF8Encoding($false)))
  $action    = New-ScheduledTaskAction -Execute $Runner
  $trigger   = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
               -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'DNSHollow DNS monitoring agent' -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep -Seconds 4
  $state = (Get-ScheduledTask -TaskName $TaskName).State
  if ($state -eq 'Running') {
    Say "The agent is running and will start at every boot."
    Write-Host "    Log     : $LogFile"
    Write-Host "    Status  : Get-ScheduledTask -TaskName '$TaskName'"
    Write-Host "    Remove  : run the install command again with -Uninstall (see the dashboard help)"
    if ($EnableBlocking) { Write-Host "    Blocking is enabled: the manager can block DNS on this machine." }
  } else {
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 20 }
    Die "The task did not stay running (state: $state). See the log lines above."
  }
}
catch {
  Die $_.Exception.Message
}
