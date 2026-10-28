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

$filterCases = @(
    @{ Category = 'All'; Types = @('Server'); Platforms = $null },
    @{ Category = 'Endpoint'; Types = @('server', 'Mobile'); Platforms = @('linux', 'Android') },
    @{ Category = 'IoT'; Types = @('Custom "type"', "Vendor's device", 'Type\name'); Platforms = @('Custom "OS"', "Vendor's OS", 'OS\name') },
    @{ Category = 'All'; Types = $null; Platforms = @('Windows11') },
    @{ Category = 'Endpoint'; Types = @('Server'); Platforms = @('Windows*', 'Linux')
        Matches = @('Windows', 'Windows11', 'windowsServer2022', 'LINUX')
        Excludes = @('Android', 'MyWindows11', 'LinuxExtra') },
    @{ Category = 'All'; Types = $null; Platforms = @('Windows1?')
        Matches = @('Windows10', 'windows11')
        Excludes = @('Windows1', 'Windows100', 'XWindows10') },
    @{ Category = 'All'; Types = $null; Platforms = @('OS.[x](a)+{b}^$|\*', 'Vendor "OS"# ?', "Vendor's OS")
        Matches = @('OS.[x](a)+{b}^$|\name', 'Vendor "OS"# X', "vendor's os")
        Excludes = @('OSZxaaaa', 'Vendor "OS"# ', "Vendor's OS extra") },
    @{ Category = 'All'; Types = $null; Platforms = @('*')
        Matches = @('', 'Windows11', 'Linux'); Excludes = @() },
    @{ Category = 'All'; Types = @(); Platforms = @() },
    @{ Category = 'All'; Types = $null; Platforms = $null }
)
foreach ($case in $filterCases) {
    $DeviceCategory = $case.Category
    $DeviceType = $case.Types
    $DevicePlatform = $case.Platforms
    foreach ($statement in $ast.EndBlock.Statements) {
        if ($statement -is [Management.Automation.Language.AssignmentStatementAst] -and
            $statement.Left.Extent.Text -in @('$categoryFilter', '$deviceTypeFilter', '$devicePlatformFilter', '$deviceQuery',
                '$selectedDevicesQuery', '$softwareQuery', '$vulnerabilityQuery')) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }
    foreach ($query in @($deviceQuery, $softwareQuery, $vulnerabilityQuery)) {
        if ($null -eq $DeviceType -or $DeviceType.Count -eq 0) {
            Assert-True (-not $query.Contains('| where DeviceType')) 'Default export must include all device types.'
        }
        else {
            $filterMatch = [regex]::Match($query, '(?m)^\| where DeviceType in~ \(dynamic\((.+)\)\)\r?$')
            Assert-True $filterMatch.Success 'Missing case-insensitive device-type include filter.'
            $includedTypes = @($filterMatch.Groups[1].Value | ConvertFrom-Json)
            Assert-True ($includedTypes.Count -eq $DeviceType.Count) 'Device-type include list changed size.'
            for ($index = 0; $index -lt $DeviceType.Count; $index++) {
                Assert-True ($includedTypes[$index] -ceq $DeviceType[$index]) 'Device-type literal was not preserved.'
            }
            Assert-True ($query.IndexOf('| summarize arg_max(Timestamp,') -lt $filterMatch.Index) 'Types must be filtered after selecting current device records.'
            Assert-True ($filterMatch.Index -lt $query.IndexOf('| project')) 'Types must be filtered before projecting or joining inventory.'
        }
        if ($null -eq $DevicePlatform -or $DevicePlatform.Count -eq 0) {
            Assert-True (-not $query.Contains('| where OSPlatform')) 'Default export must include all platforms.'
        }
        else {
            if ($case.ContainsKey('Matches')) {
                $filterMatch = [regex]::Match($query, '(?m)^\| where OSPlatform matches regex (.+)\r?$')
                Assert-True $filterMatch.Success 'Missing wildcard platform filter.'
                $pattern = $filterMatch.Groups[1].Value | ConvertFrom-Json
                foreach ($platform in $case.Matches) {
                    Assert-True ([regex]::IsMatch($platform, $pattern)) "Platform should match: $platform"
                }
                foreach ($platform in $case.Excludes) {
                    Assert-True (-not [regex]::IsMatch($platform, $pattern)) "Platform should not match: $platform"
                }
            }
            else {
                $filterMatch = [regex]::Match($query, '(?m)^\| where OSPlatform in~ \(dynamic\((.+)\)\)\r?$')
                Assert-True $filterMatch.Success 'Missing case-insensitive platform include filter.'
                $includedPlatforms = @($filterMatch.Groups[1].Value | ConvertFrom-Json)
                Assert-True ($includedPlatforms.Count -eq $DevicePlatform.Count) 'Platform include list changed size.'
                for ($index = 0; $index -lt $DevicePlatform.Count; $index++) {
                    Assert-True ($includedPlatforms[$index] -ceq $DevicePlatform[$index]) 'Platform literal was not preserved.'
                }
            }
            $canonicalSummary = [regex]::Match($query, '(?m)^\| summarize arg_max\(Timestamp, (.+)\) by CanonicalDeviceId\r?$')
            Assert-True $canonicalSummary.Success 'Missing canonical-device summary.'
            Assert-True ($canonicalSummary.Groups[1].Value -eq '*' -or
                $canonicalSummary.Groups[1].Value -match '\bOSPlatform\b') 'Canonical-device summary must retain OSPlatform.'
            Assert-True ($canonicalSummary.Index -lt $filterMatch.Index) 'Platforms must be filtered after selecting current canonical device records.'
            Assert-True ($filterMatch.Index -lt $query.IndexOf('| project')) 'Platforms must be filtered before projecting or joining inventory.'
        }
        Assert-True ($query.Contains('| where DeviceCategory') -eq ($DeviceCategory -ne 'All')) 'Category filter behavior changed.'
    }
}

$parameterBinding = [scriptblock]::Create(
    "[CmdletBinding(DefaultParameterSetName = 'AuthData')]`n" + $ast.ParamBlock.Extent.Text)
foreach ($invalidType in @($null, @(), '', '   ', @('Server', ''))) {
    $rejected = $false
    try { & $parameterBinding -AuthDataPath 'unused.json' -DeviceType $invalidType }
    catch [Management.Automation.ParameterBindingException] { $rejected = $true }
    Assert-True $rejected 'Explicit null, empty, or blank device types must be rejected.'
}
& $parameterBinding -AuthDataPath 'unused.json' -DeviceType Server,Mobile
foreach ($invalidPlatform in @($null, @(), '', '   ', @('Linux', ''))) {
    $rejected = $false
    try { & $parameterBinding -AuthDataPath 'unused.json' -DevicePlatform $invalidPlatform }
    catch [Management.Automation.ParameterBindingException] { $rejected = $true }
    Assert-True $rejected 'Explicit null, empty, or blank platforms must be rejected.'
}
& $parameterBinding -AuthDataPath 'unused.json' -DeviceType Server -DevicePlatform Linux,WindowsServer2022
& $parameterBinding -AuthDataPath 'unused.json' -DevicePlatform 'Windows*','Windows1?',Linux

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

Write-Output 'PASS: syntax, device-type and platform include filters, platform wildcards, parameter validation, category filters, null error details, empty inventory, bounded batches, 100,000-row boundary, recursive splits, single-device overflow, original errors, and connected-user requests.'
