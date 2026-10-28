# Run directly with PowerShell; no credentials or external modules are required.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$tokens = $null
$parseErrors = $null
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Export-DefenderInventoryGraph.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors | Out-String) }

foreach ($name in @('Get-OptionalPropertyValue', 'Get-HttpErrorDetails', 'Invoke-HuntingQuery', 'Invoke-BatchedHuntingQuery')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$Timespan = 'P30D'
$MaxRetryCount = 1
$resultLimit = 100000
$graphEndpoint = 'https://example.invalid/'
$script:parameterSetName = 'AccessToken'
$script:headers = @{}
$script:requests = [Collections.Generic.List[object]]::new()
$script:rowsPerDevice = 1
$script:requestFailure = $false

$DeviceCategory = 'All'
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -is [Management.Automation.Language.AssignmentStatementAst] -and
        $statement.Left.Extent.Text -in @('$categoryFilter', '$selectedDevicesQuery', '$softwareQuery', '$vulnerabilityQuery')) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}
foreach ($query in @($softwareQuery, $vulnerabilityQuery)) {
    Assert-True ($query.Contains('| where CanonicalDeviceId in (InventoryDeviceIds)')) 'Missing canonical-device batch filter.'
    Assert-True ($query.Contains('SourceDeviceId = DeviceId, CanonicalDeviceId')) 'Historical device-ID mapping was lost.'
}

function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $ContentType, $Body)
    if ($script:requestFailure) { throw 'Original request failure' }
    $request = $Body | ConvertFrom-Json
    Assert-True ($request.Timespan -eq 'P30D') 'Timespan was not preserved.'
    $match = [regex]::Match($request.Query, '^let InventoryDeviceIds = dynamic\((.+)\);')
    Assert-True $match.Success 'Missing batch device filter.'
    $ids = @($match.Groups[1].Value | ConvertFrom-Json)
    $script:requests.Add($ids)
    $count = [Math]::Min($resultLimit, $ids.Count * $script:rowsPerDevice)
    $results = for ($index = 0; $index -lt $count; $index++) {
        [PSCustomObject]@{ DeviceId = $ids[[int][Math]::Floor($index / $script:rowsPerDevice)]; Index = $index % $script:rowsPerDevice }
    }
    [PSCustomObject]@{ results = @($results) }
}

try { throw 'Original failure' } catch { $originalError = $_ }
$details = Get-HttpErrorDetails -ErrorRecord $originalError
Assert-True ($details.StatusCode -eq 0 -and $null -eq $details.ResponseBody) 'Null ErrorDetails regression.'

$rows = @(Invoke-BatchedHuntingQuery -Name 'software inventory' -Query $softwareQuery -DeviceIds @())
Assert-True ($rows.Count -eq 0 -and $script:requests.Count -eq 0) 'Empty inventory issued a request.'

$ids = @(1..205 | ForEach-Object { "device-$_" })
$rows = @(Invoke-BatchedHuntingQuery -Name 'software inventory' -Query $softwareQuery -DeviceIds $ids)
Assert-True ($script:requests.Count -eq 3) 'Expected 100/100/5 device batches.'
Assert-True ($rows.Count -eq 205 -and @($rows.DeviceId | Sort-Object -Unique).Count -eq 205) 'Missing or duplicate devices.'
Assert-True (@($script:requests | Where-Object { $_.Count -gt 100 }).Count -eq 0) 'Device batch exceeded 100 devices.'

$script:requests.Clear()
$script:rowsPerDevice = 25000
$rows = @(Invoke-BatchedHuntingQuery -Name 'software inventory' -Query $softwareQuery -DeviceIds @('a', 'b', 'c', 'd'))
Assert-True ($script:requests.Count -eq 3) 'Exact 100,000-row batch was not split.'
Assert-True ($rows.Count -eq 100000) 'Full inventory was not recovered after splitting.'
foreach ($id in @('a', 'b', 'c', 'd')) {
    Assert-True (@($rows | Where-Object DeviceId -eq $id).Count -eq 25000) "Incorrect row count for $id."
}

$resultLimit = 4
$script:rowsPerDevice = 3
$script:requests.Clear()
$rows = @(Invoke-BatchedHuntingQuery -Name 'vulnerability inventory' -Query $vulnerabilityQuery -DeviceIds @('a', 'b', 'c', 'd', 'e'))
Assert-True ($rows.Count -eq 15) 'Recursive odd-sized splits lost rows.'
Assert-True ($script:requests.Count -eq 9) 'Expected recursive splits down to individual devices.'

$script:rowsPerDevice = 4
try {
    Invoke-BatchedHuntingQuery -Name 'software inventory' -Query $softwareQuery -DeviceIds @('large-device')
    throw 'Expected single-device limit failure.'
}
catch {
    Assert-True ($_.Exception.Message -like "*for device 'large-device' reached*") 'Single-device truncation was not reported.'
}

$script:requestFailure = $true
try {
    Invoke-BatchedHuntingQuery -Name 'software inventory' -Query $softwareQuery -DeviceIds @('a', 'b')
    throw 'Expected request failure.'
}
catch {
    Assert-True ($_.Exception.Message -eq 'Original request failure') 'Original request error was masked.'
}

$script:requestFailure = $false
$script:parameterSetName = 'ConnectedUser'
function Invoke-MgGraphRequest {
    param($Method, $Uri, $ContentType, $Body, $OutputType)
    Assert-True ($OutputType -eq 'PSObject') 'Connected-user output type changed.'
    Invoke-RestMethod -Method $Method -Uri $Uri -ContentType $ContentType -Body $Body
}
$script:rowsPerDevice = 1
$rows = @(Invoke-BatchedHuntingQuery -Name 'software inventory' -Query $softwareQuery -DeviceIds @('single'))
Assert-True ($rows.Count -eq 1 -and $rows[0].DeviceId -eq 'single') 'Connected-user single-device batch failed.'

Write-Output 'PASS: syntax, null error details, empty inventory, bounded batches, 100,000-row boundary, recursive splits, single-device overflow, original errors, and connected-user requests.'
