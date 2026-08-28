<#
.SYNOPSIS
Exports Microsoft Defender for Endpoint device and software inventory.

.DESCRIPTION
The app registration used by this script requires these WindowsDefenderATP
application permissions, with tenant administrator consent granted:

    Machine.Read.All       Read all machine profiles
    Software.Read.All      Read Threat and Vulnerability Management software information
    Vulnerability.Read.All Read Threat and Vulnerability Management vulnerability information

Vulnerability.Read.All is required only when using -IncludeVulnerabilities.

To use the default authentication method, copy AuthData_sample.json to
AuthData.json in the same directory as this script and replace each placeholder
with the app registration's tenant ID, client ID, and client secret. AuthData.json
is excluded by this repository's .gitignore; do not commit or share it.

.EXAMPLE
Copy-Item .\AuthData_sample.json .\AuthData.json
.\Export-defenderInventory.ps1

.EXAMPLE
.\Export-defenderInventory.ps1 -IncludeVulnerabilities
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

    [switch]$IncludeVulnerabilities,

    [ValidateRange(1, 10)]
    [int]$MaxRetryCount = 5,

    [string]$OutputDirectory = (Join-Path $PWD ('DefenderInventory-{0:yyyyMMdd-HHmmss}' -f (Get-Date)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$apiRoot = 'https://api.security.microsoft.com/api'

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

function Get-OptionalPropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-AccessToken {
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
                scope         = 'https://api.securitycenter.microsoft.com/.default'
                grant_type    = 'client_credentials'
            }
        return $tokenResponse.access_token
    }
    finally {
        $plainClientSecret = $null
        $authData = $null
    }
}

function Invoke-DefenderRequest {
    param([Parameter(Mandatory)][string]$Uri)

    for ($attempt = 0; $attempt -le $MaxRetryCount; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $script:headers
        }
        catch {
            $statusCode = 0
            $retryAfter = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $retryAfter = $_.Exception.Response.Headers['Retry-After']
            }

            $isRetryable = $statusCode -eq 429 -or $statusCode -ge 500
            if (-not $isRetryable -or $attempt -eq $MaxRetryCount) {
                throw
            }

            $delaySeconds = if ($retryAfter) {
                [int]$retryAfter
            }
            else {
                [Math]::Min(60, [Math]::Pow(2, $attempt + 1))
            }
            Write-Warning "Defender API returned HTTP $statusCode. Retrying in $delaySeconds second(s)."
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Get-DefenderPagedCollection {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateRange(1, 10000)][int]$PageSize = 10000
    )

    $items = [Collections.Generic.List[object]]::new()
    $skip = 0
    do {
        $separator = if ($Uri.Contains('?')) { '&' } else { '?' }
        $pageUri = "$Uri${separator}`$top=$PageSize&`$skip=$skip"
        $response = Invoke-DefenderRequest -Uri $pageUri
        $page = @($response.value)
        foreach ($item in $page) {
            $items.Add($item)
        }
        $skip += $page.Count
    } while ($page.Count -eq $PageSize)

    return $items.ToArray()
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

$token = Get-AccessToken
$script:headers = @{
    Authorization = "Bearer $token"
    Accept        = 'application/json'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$errors = [Collections.Generic.List[object]]::new()
$softwareRows = [Collections.Generic.List[object]]::new()
$vulnerabilityRows = [Collections.Generic.List[object]]::new()

Write-Host 'Retrieving Defender devices...'
$machines = @(Get-DefenderPagedCollection -Uri "$apiRoot/machines")
$deviceRows = @($machines | Select-Object `
    id, computerDnsName, aadDeviceId, firstSeen, lastSeen, osPlatform, version, osBuild, osProcessor, `
    healthStatus, onboardingStatus, riskScore, exposureLevel, lastIpAddress, lastExternalIpAddress, `
    rbacGroupId, rbacGroupName, deviceValue, `
    @{ Name = 'machineTags'; Expression = { $_.machineTags -join ';' } })

$deviceNumber = 0
foreach ($machine in $machines) {
    $deviceNumber++
    Write-Progress -Activity 'Retrieving installed software' `
        -Status "$deviceNumber of $($machines.Count): $($machine.computerDnsName)" `
        -PercentComplete (($deviceNumber / [Math]::Max(1, $machines.Count)) * 100)

    $encodedMachineId = [Uri]::EscapeDataString($machine.id)
    try {
        $softwareResponse = Invoke-DefenderRequest -Uri "$apiRoot/machines/$encodedMachineId/software"
        foreach ($software in @($softwareResponse.value)) {
            $softwareRows.Add([PSCustomObject]@{
                MachineId      = $machine.id
                DeviceName     = $machine.computerDnsName
                SoftwareId     = Get-OptionalPropertyValue -InputObject $software -Name 'id'
                Name           = Get-OptionalPropertyValue -InputObject $software -Name 'name'
                Vendor         = Get-OptionalPropertyValue -InputObject $software -Name 'vendor'
                Version        = Get-OptionalPropertyValue -InputObject $software -Name 'version'
                Weaknesses     = Get-OptionalPropertyValue -InputObject $software -Name 'weaknesses'
                PublicExploit  = Get-OptionalPropertyValue -InputObject $software -Name 'publicExploit'
                ActiveAlert    = Get-OptionalPropertyValue -InputObject $software -Name 'activeAlert'
                ExposedMachines = Get-OptionalPropertyValue -InputObject $software -Name 'exposedMachines'
                ImpactScore    = Get-OptionalPropertyValue -InputObject $software -Name 'impactScore'
            })
        }
    }
    catch {
        $errors.Add([PSCustomObject]@{
            MachineId  = $machine.id
            DeviceName = $machine.computerDnsName
            Operation  = 'Software'
            Error      = $_.Exception.Message
        })
        Write-Warning "Could not retrieve software for $($machine.computerDnsName): $($_.Exception.Message)"
    }

    if ($IncludeVulnerabilities) {
        try {
            $vulnerabilityResponse = Invoke-DefenderRequest -Uri "$apiRoot/machines/$encodedMachineId/vulnerabilities"
            foreach ($vulnerability in @($vulnerabilityResponse.value)) {
                $vulnerabilityRows.Add([PSCustomObject]@{
                    MachineId       = $machine.id
                    DeviceName      = $machine.computerDnsName
                    VulnerabilityId = $vulnerability.id
                    Name            = $vulnerability.name
                    Severity        = $vulnerability.severity
                    CvssV3          = $vulnerability.cvssV3
                    Description     = $vulnerability.description
                    PublishedOn     = $vulnerability.publishedOn
                    UpdatedOn       = $vulnerability.updatedOn
                    PublicExploit   = $vulnerability.publicExploit
                    ExploitVerified = $vulnerability.exploitVerified
                    ExploitInKit    = $vulnerability.exploitInKit
                    ExploitTypes    = $vulnerability.exploitTypes -join ';'
                    ExploitUris     = $vulnerability.exploitUris -join ';'
                })
            }
        }
        catch {
            $errors.Add([PSCustomObject]@{
                MachineId  = $machine.id
                DeviceName = $machine.computerDnsName
                Operation  = 'Vulnerabilities'
                Error      = $_.Exception.Message
            })
            Write-Warning "Could not retrieve vulnerabilities for $($machine.computerDnsName): $($_.Exception.Message)"
        }
    }
}
Write-Progress -Activity 'Retrieving installed software' -Completed

Write-CsvResult -Rows $deviceRows -Path (Join-Path $OutputDirectory 'devices.csv') `
    -EmptyHeaders @('id', 'computerDnsName', 'aadDeviceId', 'firstSeen', 'lastSeen', 'osPlatform')
Write-CsvResult -Rows $softwareRows.ToArray() -Path (Join-Path $OutputDirectory 'installed-software.csv') `
    -EmptyHeaders @('MachineId', 'DeviceName', 'SoftwareId', 'Name', 'Vendor', 'Version')

if ($IncludeVulnerabilities) {
    Write-CsvResult -Rows $vulnerabilityRows.ToArray() -Path (Join-Path $OutputDirectory 'vulnerabilities.csv') `
        -EmptyHeaders @('MachineId', 'DeviceName', 'VulnerabilityId', 'Name', 'Severity', 'CvssV3')
}
if ($errors.Count -gt 0) {
    Write-CsvResult -Rows $errors.ToArray() -Path (Join-Path $OutputDirectory 'errors.csv') `
        -EmptyHeaders @('MachineId', 'DeviceName', 'Operation', 'Error')
}

$token = $null
$script:headers.Authorization = $null
Write-Host "Export complete: $OutputDirectory"
Write-Host "Devices: $($deviceRows.Count); software records: $($softwareRows.Count); vulnerabilities: $($vulnerabilityRows.Count); errors: $($errors.Count)"