<#
.SYNOPSIS
    Shard-parallel driver for pipeline.analyze.

.DESCRIPTION
    Splits every .sys under pipeline_out/drivers/ into N shuffled shards and
    fires one `docker compose run` per shard in parallel. The shards are
    written to reports/_shards/ (inside the mounted volume) so each container
    can read its own sha-list without needing a separate bind mount.

    Safe to re-run: --skip-existing on pipeline.analyze means each container
    steps over drivers that already have a bundle for the chosen scope. Index
    writes are concurrency-safe after the O_APPEND patch to append_index().

.PARAMETER Scope
    Scope profile name (see scope_profiles/). Required.

.PARAMETER Workers
    Number of parallel containers. Defaults to 8.

.EXAMPLE
    scripts\shard-analyze.ps1 hid-input-control 8
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)][string]$Scope,
    [Parameter(Position=1)][int]$Workers = 8
)

$ErrorActionPreference = 'Stop'

# Keep Git Bash / MSYS from rewriting /work/... into a C:\ path when the
# argument is passed through to docker. Harmless on native PowerShell too.
$env:MSYS_NO_PATHCONV = '1'

$RepoRoot    = Split-Path -Parent $PSScriptRoot
$DriversDir  = Join-Path $RepoRoot 'pipeline_out\drivers'
$ShardsDir   = Join-Path $RepoRoot "reports\_shards\$Scope"
$LogDir      = Join-Path $ShardsDir 'logs'

if (-not (Test-Path $DriversDir)) {
    Write-Error "pipeline_out/drivers missing -- run pipeline.collect first"
}

if (Test-Path $ShardsDir) { Remove-Item -Recurse -Force $ShardsDir }
New-Item -ItemType Directory -Force -Path $ShardsDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir    | Out-Null

# Shuffle so each shard gets a mix of big/small drivers rather than
# concentrating slow ones in a single worker.
$allShas = Get-ChildItem -Path $DriversDir -Filter '*.sys' -File |
           ForEach-Object { $_.BaseName } |
           Sort-Object { Get-Random }

$total = $allShas.Count
if ($total -eq 0) {
    Write-Error "no drivers found under $DriversDir"
}
Write-Host "[shard] scope=$Scope workers=$Workers total=$total"

# Round-robin chunking so adjacent SHAs (same vendor / size neighborhood)
# spread across workers evenly.
$shardWriters = @{}
for ($i = 0; $i -lt $Workers; $i++) {
    $path = Join-Path $ShardsDir ("shard-{0:d2}.lst" -f $i)
    $shardWriters[$i] = [System.IO.StreamWriter]::new($path, $false, [System.Text.UTF8Encoding]::new($false))
}
try {
    for ($i = 0; $i -lt $total; $i++) {
        $shardWriters[$i % $Workers].WriteLine($allShas[$i])
    }
} finally {
    foreach ($w in $shardWriters.Values) { $w.Dispose() }
}

# Launch one container per shard, in parallel.
$jobs = @()
for ($i = 0; $i -lt $Workers; $i++) {
    $shardName = 'shard-{0:d2}.lst' -f $i
    $shardIn   = Join-Path $ShardsDir $shardName
    $shardLog  = Join-Path $LogDir  "$shardName.log"
    if ((Get-Item $shardIn).Length -eq 0) {
        Write-Host "[shard] worker $($i): empty, skipping"
        continue
    }
    $count = (Get-Content $shardIn | Measure-Object -Line).Lines
    Write-Host "[shard] worker $($i): $count drivers -> $shardLog"

    # Container-side path for the sha-list; reports/ is mounted at /work/reports.
    $containerSha = "/work/reports/_shards/$Scope/$shardName"

    $job = Start-Job -Name "shard-$i" -ScriptBlock {
        param($Scope, $ContainerSha, $LogPath, $Cwd)
        $env:MSYS_NO_PATHCONV = '1'
        Set-Location $Cwd
        # Redirect combined stdout+stderr to the per-worker log.
        docker compose run --rm --no-TTY analyze `
            pipeline.analyze --all `
            --scope $Scope `
            --skip-existing `
            --sha-list $ContainerSha `
            *>&1 | Out-File -FilePath $LogPath -Encoding utf8
        if ($LASTEXITCODE -ne 0) { throw "docker exited $LASTEXITCODE" }
    } -ArgumentList $Scope, $containerSha, $shardLog, $RepoRoot
    $jobs += $job
}

Write-Host "[shard] launched $($jobs.Count) workers"
Write-Host "[shard] follow one with: Get-Content -Wait $LogDir\shard-00.lst.log"

# Wait for all workers; collect per-job status.
$failed = 0
foreach ($j in $jobs) {
    Wait-Job $j | Out-Null
    if ($j.State -ne 'Completed') {
        $failed++
        Write-Warning "worker $($j.Name) ended in state $($j.State)"
        Receive-Job $j -ErrorAction SilentlyContinue | Out-Null
    }
    Remove-Job $j | Out-Null
}

Write-Host "[shard] all workers done (failed=$failed)"
$indexPath = Join-Path $RepoRoot 'reports\index.jsonl'
if (Test-Path $indexPath) {
    $rows = (Get-Content $indexPath | Measure-Object -Line).Lines
    Write-Host "[shard] index rows: $rows"
}
if ($failed -gt 0) { exit 1 }
