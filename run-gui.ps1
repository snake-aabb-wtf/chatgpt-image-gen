<#
.SYNOPSIS
    一键启动 cgpt 图形界面。

.DESCRIPTION
    做三件事，然后拉起 GUI：
      1. 把控制台切成 UTF-8（否则中文日志在 Windows PowerShell 里是乱码）
      2. 切到脚本所在目录（工具用的是 .cgpt/、output/ 这类相对路径）
      3. 环境自检：Python 版本、依赖模块、Playwright 的 Chromium

    自检不过时给出**可照抄的修复命令**，而不是丢一个 traceback。

.PARAMETER Install
    缺依赖时自动安装（pip install -r requirements.txt + playwright install chromium）。
    默认不装 —— 静默改环境不是好习惯。

.PARAMETER Headless
    浏览器不显示窗口。默认显示 —— 过 Cloudflare 时看得见更安心，
    被拦了也能立刻发现。

.PARAMETER Check
    只做环境自检，不启动界面。

.EXAMPLE
    .\run-gui.ps1
    一键启动（最常用）。

.EXAMPLE
    .\run-gui.ps1 -Check
    先看看环境齐不齐。

.EXAMPLE
    .\run-gui.ps1 -Install
    首次使用，自动把缺的依赖装上。
#  ⚠ 本文件必须保存为「UTF-8 带 BOM」。
#
#  Windows PowerShell 5.1 在没有 BOM 时按系统 ANSI（本机 cp936/GBK）读取 .ps1，
#  中文会被拆成乱码，甚至错位到把字符串引号弄坏，直接报一堆语法错误。
#  如果你用别的编辑器改过这个文件，请确认 BOM 还在（前 3 字节 EF BB BF）。
#
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Headless,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'

# --- 控制台编码：必须在任何中文输出之前 -------------------------------
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {
    # 某些宿主不允许改编码，忽略即可 —— 不影响功能，只是显示可能乱码
}
$env:PYTHONIOENCODING = 'utf-8'

# --- 定位仓库根：脚本可能从任意目录被调用 -----------------------------
$repoRoot = $PSScriptRoot
if (-not $repoRoot) { $repoRoot = (Get-Location).Path }
Set-Location -LiteralPath $repoRoot

function Write-Step  { param([string]$Text) Write-Host "  $Text" }
function Write-Ok    { param([string]$Text) Write-Host "  [OK]   $Text" -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host "  [警告] $Text" -ForegroundColor Yellow }
function Write-Bad   { param([string]$Text) Write-Host "  [缺失] $Text" -ForegroundColor Red }

Write-Host ""
Write-Host "cgpt 图形界面启动器" -ForegroundColor Cyan
Write-Host "仓库根：$repoRoot" -ForegroundColor DarkGray
Write-Host ""

# --- 1) 找 Python ------------------------------------------------------
function Find-Python {
    foreach ($candidate in @('python', 'py')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            if ($candidate -eq 'py') {
                $version = & py -3 -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
                if ($LASTEXITCODE -eq 0 -and $version) {
                    return @{ Exe = 'py'; Args = @('-3') ; Version = $version.Trim() }
                }
            } else {
                $version = & python -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
                if ($LASTEXITCODE -eq 0 -and $version) {
                    return @{ Exe = 'python'; Args = @(); Version = $version.Trim() }
                }
            }
        } catch { continue }
    }
    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Bad "找不到 Python。"
    Write-Host ""
    Write-Host "  请先安装 Python 3.12 或更高版本：https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  安装时记得勾选 'Add python.exe to PATH'。" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

$pyArgs = $python.Args
$versionParts = $python.Version.Split('.')
$major = [int]$versionParts[0]
$minor = [int]$versionParts[1]
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 12)) {
    Write-Bad "Python 版本过低：$($python.Version)（本项目需要 3.12+）"
    exit 1
}
Write-Ok "Python $($python.Version)（$($python.Exe)）"

# --- 2) 依赖自检 -------------------------------------------------------
function Test-PythonImport {
    param([string]$Statement)
    # 原生命令的 stderr 合进管道后会变成 ErrorRecord，撞上全局的
    # ErrorActionPreference='Stop' 会直接抛错。这里临时放宽。
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $python.Exe @pyArgs -c $Statement 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $previous
    }
}

$missing = @()

if (-not (Test-PythonImport "import tkinter")) { $missing += 'tkinter（Python 自带的 GUI 库，需重装 Python 并勾选 tcl/tk）' }
if (-not (Test-PythonImport "import click")) { $missing += 'click' }
if (-not (Test-PythonImport "import pydantic")) { $missing += 'pydantic' }
if (-not (Test-PythonImport "import curl_cffi")) { $missing += 'curl_cffi' }
if (-not (Test-PythonImport "import playwright")) { $missing += 'playwright' }

$chromiumOk = $false
if ($missing.Count -eq 0) {
    $chromiumOk = Test-PythonImport @"
from playwright.sync_api import sync_playwright
import os, sys
with sync_playwright() as p:
    sys.exit(0 if os.path.exists(p.chromium.executable_path) else 1)
"@
    if (-not $chromiumOk) { $missing += 'Playwright 的 Chromium 浏览器' }
}

if ($missing.Count -gt 0) {
    Write-Bad "缺少以下组件："
    foreach ($item in $missing) { Write-Host "           - $item" -ForegroundColor Red }
    Write-Host ""

    if (-not $Install) {
        Write-Host "  修复命令（复制粘贴即可）：" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "      .\run-gui.ps1 -Install" -ForegroundColor White
        Write-Host ""
        Write-Host "  或手动执行：" -ForegroundColor Yellow
        Write-Host "      $($python.Exe) -m pip install -r requirements.txt" -ForegroundColor White
        Write-Host "      $($python.Exe) -m playwright install chromium" -ForegroundColor White
        Write-Host ""
        exit 1
    }

    # tkinter 是 Python 自带的，pip 装不了 —— 先拦下来，别让用户白等一次 pip
    if ($missing -contains 'tkinter（Python 自带的 GUI 库，需重装 Python 并勾选 tcl/tk）') {
        Write-Host "  tkinter 无法用 pip 安装，请重装 Python 并勾选 tcl/tk 组件。" -ForegroundColor Yellow
        exit 1
    }

    Write-Step "开始安装（-Install）…"
    Write-Host ""
    & $python.Exe @pyArgs -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Bad "pip install 失败。"; exit 1 }
    & $python.Exe @pyArgs -m playwright install chromium
    if ($LASTEXITCODE -ne 0) { Write-Bad "playwright install 失败。"; exit 1 }
    Write-Host ""
    Write-Ok "安装完成，继续启动"
}

Write-Ok "依赖齐全（click / pydantic / curl_cffi / playwright / tkinter）"
Write-Ok "Playwright Chromium 已就绪"

# --- 3) 登录状态提示（不是错误，只是提示）-------------------------------
$credPath = Join-Path $repoRoot '.cgpt\credentials.json'
$accountPath = Join-Path $repoRoot '.cgpt\account.txt'
if (Test-Path -LiteralPath $credPath) {
    Write-Ok "已有会话凭据（.cgpt\credentials.json）"
} else {
    Write-Warn2 "还没有会话凭据 —— 界面里粘贴「邮箱----密码----2FA密钥」后点「登录」"
}
if (-not (Test-Path -LiteralPath $accountPath)) {
    Write-Warn2 "还没有记住账号 —— 首次登录时保持勾选「记住账号」即可自动填充"
}

if ($Check) {
    Write-Host ""
    Write-Ok "自检通过（-Check 模式，不启动界面）"
    Write-Host ""
    exit 0
}

# --- 4) 启动 -----------------------------------------------------------
# 这里刻意**不做**"无控制台启动"（pythonw + Start-Process）：本机同时存在
# NO_PROXY 与 no_proxy 两个拼写，PowerShell 5.1 的 Start-Process 内部用的是
# 大小写敏感的字典，会抛 "Item has already been added. Key: 'NO_PROXY'"。
# 想绕过就得临时删掉重复的那个环境变量，但 Windows 环境变量大小写不敏感，
# 删掉等于把代理排除设置一起删了 —— 而这个工具恰恰需要联网。
# 保留控制台还有个好处：启动失败（Cloudflare / 登录）时输出就在眼前。
$guiArgs = @()
if ($Headless) { $guiArgs += '--headless' }

Write-Host ""
Write-Step "启动界面…（关闭窗口即退出）"
Write-Host ""
& $python.Exe @pyArgs -m cgpt @guiArgs gui
exit $LASTEXITCODE
