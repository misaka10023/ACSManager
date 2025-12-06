@echo off
setlocal ENABLEDELAYEDEXPANSION

rem 根据远端 ACS Manager API 获取容器 IP，并更新 ~/.ssh/config 中
rem Host container_local / container_remote 的 HostName

set "PSFILE=%TEMP%\update_container_ip_remote_%RANDOM%.ps1"

> "%PSFILE%" echo $ErrorActionPreference = 'Stop'
>>"%PSFILE%" echo $url = 'https://www.reaper.ren/acsmanager/container-ip'
>>"%PSFILE%" echo try ^{
>>"%PSFILE%" echo   Write-Host ("Requesting " + $url + " ...")
>>"%PSFILE%" echo   $resp = Invoke-RestMethod -Uri $url -TimeoutSec 5
>>"%PSFILE%" echo   $ip = $null
>>"%PSFILE%" echo   if ($resp.container_ip) ^{ $ip = $resp.container_ip ^} elseif ($resp.ip) ^{ $ip = $resp.ip ^}
>>"%PSFILE%" echo   if (-not $ip) ^{ throw "响应中没有 IP 字段(container_ip/ip)" ^}
>>"%PSFILE%" echo   Write-Host ("Got IP: " + $ip)
>>"%PSFILE%" echo ^} catch ^{
>>"%PSFILE%" echo   Write-Error ("获取 IP 失败: " + $_.Exception.Message)
>>"%PSFILE%" echo   exit 1
>>"%PSFILE%" echo ^}
>>"%PSFILE%" echo
>>"%PSFILE%" echo $configPath = Join-Path $env:USERPROFILE ".ssh\config"
>>"%PSFILE%" echo if (-not (Test-Path $configPath)) ^{ Write-Error ("找不到 SSH config 文件: " + $configPath); exit 1 ^}
>>"%PSFILE%" echo $lines = Get-Content $configPath
>>"%PSFILE%" echo $currentHost = $null
>>"%PSFILE%" echo for ($i = 0; $i -lt $lines.Count; $i++) ^{
>>"%PSFILE%" echo   $line = $lines[$i]
>>"%PSFILE%" echo   $trim = $line.TrimStart()
>>"%PSFILE%" echo   if ($trim -match '^Host\s+') ^{
>>"%PSFILE%" echo     $parts = $trim -split '\s+'
>>"%PSFILE%" echo     if ($parts.Count -ge 2) ^{ $currentHost = $parts[1] ^} else ^{ $currentHost = $null ^}
>>"%PSFILE%" echo   ^}
>>"%PSFILE%" echo   if (($currentHost -eq 'container_local' -or $currentHost -eq 'container_remote') -and $trim.StartsWith('HostName')) ^{
>>"%PSFILE%" echo     $lines[$i] = "    HostName $ip"
>>"%PSFILE%" echo   ^}
>>"%PSFILE%" echo ^}
>>"%PSFILE%" echo $lines ^| Set-Content -Encoding utf8 $configPath
>>"%PSFILE%" echo Write-Host ("已更新 SSH config 中 container_local / container_remote 的 HostName 为 " + $ip)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PSFILE%"

if errorlevel 1 (
  echo 更新失败
) else (
  echo 更新成功
)

del "%PSFILE%" >nul 2>&1
pause
endlocal

