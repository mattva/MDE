<#
.SYNOPSIS
Exports Microsoft Defender device, software, and vulnerability inventory through Microsoft Graph Advanced Hunting.

.DESCRIPTION
The app registration used by this script requires the Microsoft Graph application
permission ThreatHunting.Read.All with tenant administrator consent granted.

To use the default authentication method, copy AuthData_sample.json to
AuthData.json in the same directory as this script and replace each placeholder
with the app registration's tenant ID, client ID, and client secret. AuthData.json
is excluded by this repository's .gitignore; do not commit or share it.

Advanced Hunting returns data observed during the selected timespan. A result set
that reaches 100,000 rows is rejected to avoid silently exporting truncated data.
Use a narrower device category or timespan when that occurs.

Historical device IDs are consolidated under MergedToDeviceId, the most recent
device ID, across device, software, and vulnerability output.

.EXAMPLE
.\Export-DefenderInventoryGraph.ps1

Exports all device categories and their software inventory from the past 30 days.

.EXAMPLE
.\Export-DefenderInventoryGraph.ps1 -DeviceCategory Endpoint -IncludeVulnerabilities

Exports endpoint devices, software, and vulnerabilities.

.EXAMPLE
.\Export-DefenderInventoryGraph.ps1 -DeviceCategory IoT -Timespan P7D

Exports IoT inventory observed during the past seven days.
#>
[CmdletBinding(DefaultParameterSetName = 'AuthData')]
param(
    [Parameter(ParameterSetName = 'AuthData')]
    [string]$AuthDataPath = (Join-Path $PSScriptRoot 'AuthData.json'),

    [Parameter(Mandatory, ParameterSetName = 'ClientCredentials')]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'ClientCredentials')]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = 'ClientCredentials')]
    [Security.SecureString]$ClientSecret,

    [Parameter(Mandatory, ParameterSetName = 'AccessToken')]
    [Security.SecureString]$AccessToken,

    [ValidateSet('All', 'Endpoint', 'IoT')]
    [string]$DeviceCategory = 'All',

    [switch]$IncludeVulnerabilities,

    [ValidatePattern('^P(?!$).+')]
    [string]$Timespan = 'P30D',

    [ValidateRange(1, 10)]
    [int]$MaxRetryCount = 5,

    [string]$OutputDirectory = (Join-Path $PWD ('DefenderGraphInventory-{0:yyyyMMdd-HHmmss}' -f (Get-Date)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graphEndpoint = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery'
$resultLimit = 100000

function ConvertFrom-SecureValue {
    param([Parameter(Mandatory)][Security.SecureString]$Value)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Get-GraphAccessToken {
    if ($PSCmdlet.ParameterSetName -eq 'AccessToken') {
        return ConvertFrom-SecureValue -Value $AccessToken
    }

    if ($PSCmdlet.ParameterSetName -eq 'AuthData') {
        if (-not (Test-Path -LiteralPath $AuthDataPath -PathType Leaf)) {
            throw "Authentication data file not found: $AuthDataPath"
        }

        $authData = Get-Content -LiteralPath $AuthDataPath -Raw | ConvertFrom-Json
        $missingFields = @('tenantID', 'clientID', 'clientSecret').Where({
            -not $authData.PSObject.Properties[$_] -or [string]::IsNullOrWhiteSpace($authData.$_)
        })
        if ($missingFields.Count -gt 0) {
            throw "Authentication data file is missing required value(s): $($missingFields -join ', ')"
        }

        $requestTenantId = $authData.tenantID
        $requestClientId = $authData.clientID
        $plainClientSecret = $authData.clientSecret
    }
    else {
        $requestTenantId = $TenantId
        $requestClientId = $ClientId
        $plainClientSecret = ConvertFrom-SecureValue -Value $ClientSecret
    }

    try {
        $tokenResponse = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/$requestTenantId/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body @{
                client_id     = $requestClientId
                client_secret = $plainClientSecret
                scope         = 'https://graph.microsoft.com/.default'
                grant_type    = 'client_credentials'
            }
        return $tokenResponse.access_token
    }
    finally {
        $plainClientSecret = $null
        $authData = $null
    }
}

function Get-HttpErrorDetails {
    param([Parameter(Mandatory)][Management.Automation.ErrorRecord]$ErrorRecord)

    $statusCode = 0
    $retryAfter = $null
    $responseBody = $null
    $responseProperty = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
        $response = $responseProperty.Value
        $statusCode = [int]$response.StatusCode
        $retryAfter = $response.Headers['Retry-After']
        $responseStream = $response.GetResponseStream()
        if ($null -ne $responseStream) {
            $reader = [IO.StreamReader]::new($responseStream)
            try {
                $responseBody = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
    }

    [PSCustomObject]@{
        StatusCode = $statusCode
        RetryAfter = $retryAfter
        ResponseBody = $responseBody
    }
}

function Invoke-HuntingQuery {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Query
    )

    $body = @{
        Query    = $Query
        Timespan = $Timespan
    } | ConvertTo-Json

    for ($attempt = 0; $attempt -le $MaxRetryCount; $attempt++) {
        try {
            Write-Host "Running $Name query..."
            $response = Invoke-RestMethod -Method Post -Uri $graphEndpoint `
                -Headers $script:headers -ContentType 'application/json; charset=utf-8' -Body $body
            $rows = @($response.results)
            if ($rows.Count -ge $resultLimit) {
                throw "$Name query returned $($rows.Count) rows and may be truncated. Narrow DeviceCategory or Timespan."
            }
            return $rows
        }
        catch {
            $httpError = Get-HttpErrorDetails -ErrorRecord $_
            $isRetryable = $httpError.StatusCode -eq 429 -or $httpError.StatusCode -ge 500
            if (-not $isRetryable -or $attempt -eq $MaxRetryCount) {
                if (-not [string]::IsNullOrWhiteSpace($httpError.ResponseBody)) {
                    throw "$Name query failed with HTTP $($httpError.StatusCode): $($httpError.ResponseBody)"
                }
                throw
            }

            $delaySeconds = if ($httpError.RetryAfter) {
                [int]$httpError.RetryAfter
            }
            else {
                [Math]::Min(60, [Math]::Pow(2, $attempt + 1))
            }
            Write-Warning "Microsoft Graph returned HTTP $($httpError.StatusCode). Retrying in $delaySeconds second(s)."
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Write-CsvResult {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$EmptyHeaders
    )

    if ($Rows.Count -gt 0) {
        $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
    else {
        Set-Content -Path $Path -Value ($EmptyHeaders -join ',') -Encoding UTF8
    }
}

$categoryFilter = if ($DeviceCategory -eq 'All') {
    ''
}
else {
    "| where DeviceCategory == '$DeviceCategory'"
}

$deviceQuery = @"
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| extend CanonicalDeviceId = iff(
    isempty(column_ifexists('MergedToDeviceId', '')),
    DeviceId,
    column_ifexists('MergedToDeviceId', ''))
| summarize arg_max(Timestamp, *) by CanonicalDeviceId
$categoryFilter
| project Timestamp, DeviceId = CanonicalDeviceId, DeviceName,
    MergedDeviceIds = tostring(column_ifexists('MergedDeviceIds', '')),
    DeviceCategory = column_ifexists('DeviceCategory', ''),
    DeviceType = column_ifexists('DeviceType', ''),
    DeviceSubtype = column_ifexists('DeviceSubtype', ''),
    Vendor = column_ifexists('Vendor', ''), Model = column_ifexists('Model', ''),
    OSPlatform, OSDistribution = column_ifexists('OSDistribution', ''), OSVersion, OSArchitecture,
    PublicIP, OnboardingStatus, SensorHealthState = column_ifexists('SensorHealthState', ''),
    ExposureLevel = column_ifexists('ExposureLevel', ''), AssetValue = column_ifexists('AssetValue', ''),
    MachineGroup, IsInternetFacing = column_ifexists('IsInternetFacing', false),
    Site = column_ifexists('Site', ''),
    DeviceManualTags = tostring(column_ifexists('DeviceManualTags', '')),
    DeviceDynamicTags = tostring(column_ifexists('DeviceDynamicTags', '')),
    DiscoverySources = tostring(column_ifexists('DiscoverySources', ''))
| order by DeviceName asc
"@

$selectedDevicesQuery = @"
let LatestDeviceIds = DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| extend CanonicalDeviceId = iff(
    isempty(column_ifexists('MergedToDeviceId', '')),
    DeviceId,
    column_ifexists('MergedToDeviceId', ''));
let CanonicalDevices = LatestDeviceIds
| summarize arg_max(Timestamp, DeviceName, DeviceCategory, DeviceType) by CanonicalDeviceId
$categoryFilter
| project CanonicalDeviceId, InventoryDeviceName = DeviceName, DeviceCategory, DeviceType;
let SelectedDevices = LatestDeviceIds
| project SourceDeviceId = DeviceId, CanonicalDeviceId
| join kind=inner CanonicalDevices on CanonicalDeviceId
| project SourceDeviceId, CanonicalDeviceId, InventoryDeviceName, DeviceCategory, DeviceType;
"@

$softwareQuery = @"
$selectedDevicesQuery
DeviceTvmSoftwareInventory
| join kind=inner SelectedDevices on `$left.DeviceId == `$right.SourceDeviceId
| project DeviceId = CanonicalDeviceId, DeviceName = InventoryDeviceName, DeviceCategory, DeviceType,
    OSPlatform, OSVersion, OSArchitecture, SoftwareVendor, SoftwareName,
    SoftwareVersion, EndOfSupportStatus, EndOfSupportDate, ProductCodeCpe
| distinct DeviceId, DeviceName, DeviceCategory, DeviceType, OSPlatform, OSVersion,
    OSArchitecture, SoftwareVendor, SoftwareName, SoftwareVersion,
    EndOfSupportStatus, EndOfSupportDate, ProductCodeCpe
| order by DeviceName asc, SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc
"@

$vulnerabilityQuery = @"
$selectedDevicesQuery
DeviceTvmSoftwareVulnerabilities
| join kind=inner SelectedDevices on `$left.DeviceId == `$right.SourceDeviceId
| project DeviceId = CanonicalDeviceId, DeviceName = InventoryDeviceName, DeviceCategory, DeviceType,
    OSPlatform, OSVersion, OSArchitecture, SoftwareVendor, SoftwareName,
    SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate,
    RecommendedSecurityUpdateId, CveTags = tostring(CveTags)
| distinct DeviceId, DeviceName, DeviceCategory, DeviceType, OSPlatform, OSVersion,
    OSArchitecture, SoftwareVendor, SoftwareName, SoftwareVersion, CveId,
    VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, CveTags
| order by DeviceName asc, SoftwareVendor asc, SoftwareName asc, CveId asc
"@

$token = Get-GraphAccessToken
$script:headers = @{
    Authorization = "Bearer $token"
    Accept        = 'application/json'
}

try {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $deviceRows = @(Invoke-HuntingQuery -Name 'device inventory' -Query $deviceQuery)
    $softwareRows = @(Invoke-HuntingQuery -Name 'software inventory' -Query $softwareQuery)
    $vulnerabilityRows = @()
    if ($IncludeVulnerabilities) {
        $vulnerabilityRows = @(Invoke-HuntingQuery -Name 'vulnerability inventory' -Query $vulnerabilityQuery)
    }

    Write-CsvResult -Rows $deviceRows -Path (Join-Path $OutputDirectory 'devices.csv') `
        -EmptyHeaders @('Timestamp', 'DeviceId', 'DeviceName', 'MergedDeviceIds', 'DeviceCategory', 'DeviceType', 'DeviceSubtype')
    Write-CsvResult -Rows $softwareRows -Path (Join-Path $OutputDirectory 'installed-software.csv') `
        -EmptyHeaders @('DeviceId', 'DeviceName', 'DeviceCategory', 'DeviceType', 'SoftwareVendor', 'SoftwareName', 'SoftwareVersion')

    if ($IncludeVulnerabilities) {
        Write-CsvResult -Rows $vulnerabilityRows -Path (Join-Path $OutputDirectory 'vulnerabilities.csv') `
            -EmptyHeaders @('DeviceId', 'DeviceName', 'DeviceCategory', 'DeviceType', 'SoftwareVendor', 'SoftwareName', 'SoftwareVersion', 'CveId')
    }

    Write-Host "Export complete: $OutputDirectory"
    Write-Host "Devices: $($deviceRows.Count); software records: $($softwareRows.Count); vulnerabilities: $($vulnerabilityRows.Count)"
}
finally {
    $token = $null
    $script:headers.Authorization = $null
}
