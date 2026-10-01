<#
.SYNOPSIS
Exports Microsoft Defender and Azure VM/Arc inventory through Advanced Hunting and Azure Resource Graph.

.DESCRIPTION
For Defender inventory, the app registration requires the Microsoft Graph application
permission ThreatHunting.Read.All with tenant administrator consent. For Azure inventory,
the service principal requires Reader access on each subscription to query Azure Resource
Graph. Combined mode joins the sources by AzureResourceId and retains unmatched records.

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

.EXAMPLE
.\Export-DefenderInventoryGraph.ps1 -InventorySource Azure -SubscriptionId '<subscription-id>'

Exports Azure virtual machines and Azure Arc-enabled servers without querying Defender.
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

    [Parameter(ParameterSetName = 'AccessToken')]
    [Security.SecureString]$AccessToken,

    [Parameter(ParameterSetName = 'AccessToken')]
    [Security.SecureString]$AzureAccessToken,

    [Parameter(Mandatory, ParameterSetName = 'ConnectedUser')]
    [switch]$UseConnectedUser,

    [ValidateSet('Defender', 'Azure', 'Combined')]
    [string]$InventorySource = 'Combined',

    [string[]]$SubscriptionId,

    [ValidateSet('All', 'Endpoint', 'IoT')]
    [string]$DeviceCategory = 'All',

    [switch]$IncludeVulnerabilities,

    [ValidatePattern('^P(?!$).+')]
    [string]$Timespan = 'P30D',

    [ValidateRange(1, 10)]
    [int]$MaxRetryCount = 5,

    [string]$OutputDirectory = (Join-Path $PWD ('DefenderGraphInventory-{0:yyyyMMdd-HHmmss}' -f (Get-Date))),

    [string]$ExcelFileName = 'DefenderAssetInventory.xlsx'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graphEndpoint = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery'
$resourceGraphEndpoint = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-06-01-preview'
$resultLimit = 100000
$script:parameterSetName = $PSCmdlet.ParameterSetName

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

function Get-AccessToken {
    param(
        [Parameter(Mandatory)][string]$Scope,
        [AllowNull()][Security.SecureString]$ProvidedToken,
        [Parameter(Mandatory)][string]$TokenName
    )

    if ($script:parameterSetName -eq 'ConnectedUser') {
        if ($Scope -ne 'https://management.azure.com/.default') {
            throw "Connected-user token acquisition is not supported for scope '$Scope'."
        }
        if ($null -eq (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue)) {
            throw 'Get-AzAccessToken was not found. Install and import the Az.Accounts module.'
        }
        $azToken = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/'
        if ($azToken.Token -is [Security.SecureString]) {
            return ConvertFrom-SecureValue -Value $azToken.Token
        }
        return [string]$azToken.Token
    }

    if ($script:parameterSetName -eq 'AccessToken') {
        if ($null -eq $ProvidedToken) {
            throw "$TokenName is required for InventorySource '$InventorySource'."
        }
        return ConvertFrom-SecureValue -Value $ProvidedToken
    }

    if ($script:parameterSetName -eq 'AuthData') {
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
                scope         = $Scope
                grant_type    = 'client_credentials'
            }
        return $tokenResponse.access_token
    }
    finally {
        $plainClientSecret = $null
        $authData = $null
    }
}

function Get-OptionalPropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-HttpErrorDetails {
    param([Parameter(Mandatory)][Management.Automation.ErrorRecord]$ErrorRecord)

    $statusCode = 0
    $retryAfter = $null
    $responseBody = $ErrorRecord.ErrorDetails.Message
    $responseProperty = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
        $response = $responseProperty.Value
        $statusCode = [int]$response.StatusCode
        if ($null -ne $response.Headers.PSObject.Properties['RetryAfter']) {
            $retryAfter = [string]$response.Headers.RetryAfter
        }
        elseif ($response.Headers -is [Collections.IDictionary]) {
            $retryAfter = $response.Headers['Retry-After']
        }

        if ([string]::IsNullOrWhiteSpace($responseBody) -and
            $null -ne $response.PSObject.Properties['Content'] -and $null -ne $response.Content) {
            try { $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
            catch { $responseBody = $null }
        }
        elseif ([string]::IsNullOrWhiteSpace($responseBody) -and
            $null -ne $response.PSObject.Methods['GetResponseStream']) {
            $responseStream = $response.GetResponseStream()
            if ($null -ne $responseStream) {
                $reader = [IO.StreamReader]::new($responseStream)
                try { $responseBody = $reader.ReadToEnd() }
                finally { $reader.Dispose() }
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
            if ($script:parameterSetName -eq 'ConnectedUser') {
                $response = Invoke-MgGraphRequest -Method Post -Uri $graphEndpoint `
                    -ContentType 'application/json; charset=utf-8' -Body $body -OutputType PSObject
            }
            else {
                $response = Invoke-RestMethod -Method Post -Uri $graphEndpoint `
                    -Headers $script:headers -ContentType 'application/json; charset=utf-8' -Body $body
            }
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

function Invoke-ResourceGraphQuery {
    param([Parameter(Mandatory)][string]$Query)

    $rows = [Collections.Generic.List[object]]::new()
    $skipToken = $null
    do {
        $options = @{ resultFormat = 'objectArray'; '$top' = 1000 }
        if (-not [string]::IsNullOrWhiteSpace($skipToken)) {
            $options['$skipToken'] = $skipToken
        }
        $request = @{ query = $Query; options = $options }
        if ($null -ne $SubscriptionId -and $SubscriptionId.Count -gt 0) {
            $request.subscriptions = $SubscriptionId
        }
        $body = $request | ConvertTo-Json -Depth 10

        for ($attempt = 0; $attempt -le $MaxRetryCount; $attempt++) {
            try {
                Write-Host "Querying Azure Resource Graph page $([Math]::Floor($rows.Count / 1000) + 1)..."
                $response = Invoke-RestMethod -Method Post -Uri $resourceGraphEndpoint `
                    -Headers $script:azureHeaders -ContentType 'application/json; charset=utf-8' -Body $body
                break
            }
            catch {
                $httpError = Get-HttpErrorDetails -ErrorRecord $_
                $isRetryable = $httpError.StatusCode -eq 429 -or $httpError.StatusCode -ge 500
                if (-not $isRetryable -or $attempt -eq $MaxRetryCount) {
                    if ($httpError.StatusCode -eq 403) {
                        throw "Azure Resource Graph access denied. Assign the app registration's service principal the Reader role on each target subscription. $($httpError.ResponseBody)"
                    }
                    if (-not [string]::IsNullOrWhiteSpace($httpError.ResponseBody)) {
                        throw "Azure Resource Graph query failed with HTTP $($httpError.StatusCode): $($httpError.ResponseBody)"
                    }
                    throw
                }
                $delaySeconds = if ($httpError.RetryAfter) { [int]$httpError.RetryAfter } else { [Math]::Min(60, [Math]::Pow(2, $attempt + 1)) }
                Write-Warning "Azure Resource Graph returned HTTP $($httpError.StatusCode). Retrying in $delaySeconds second(s)."
                Start-Sleep -Seconds $delaySeconds
            }
        }

        foreach ($row in @($response.data)) { $rows.Add($row) }
        $skipToken = Get-OptionalPropertyValue -InputObject $response -Name '$skipToken'
    } while (-not [string]::IsNullOrWhiteSpace($skipToken))

    return $rows.ToArray()
}

function New-DeviceInventoryRow {
    param(
        [AllowNull()][object]$DefenderDevice,
        [AllowNull()][object]$AzureResource
    )

    $hasDefender = $null -ne $DefenderDevice
    $hasAzure = $null -ne $AzureResource
    [PSCustomObject][ordered]@{
        InventorySources = if ($hasDefender -and $hasAzure) { 'Defender;Azure' } elseif ($hasDefender) { 'Defender' } else { 'Azure' }
        Timestamp = Get-OptionalPropertyValue $DefenderDevice 'Timestamp'
        DeviceId = Get-OptionalPropertyValue $DefenderDevice 'DeviceId'
        DeviceName = if ($hasDefender) { Get-OptionalPropertyValue $DefenderDevice 'DeviceName' } else { Get-OptionalPropertyValue $AzureResource 'ComputerName' }
        AadDeviceId = Get-OptionalPropertyValue $DefenderDevice 'AadDeviceId'
        MergedDeviceIds = Get-OptionalPropertyValue $DefenderDevice 'MergedDeviceIds'
        DeviceCategory = Get-OptionalPropertyValue $DefenderDevice 'DeviceCategory'
        DeviceType = Get-OptionalPropertyValue $DefenderDevice 'DeviceType'
        DeviceSubtype = Get-OptionalPropertyValue $DefenderDevice 'DeviceSubtype'
        Manufacturer = Get-OptionalPropertyValue $DefenderDevice 'Vendor'
        Model = Get-OptionalPropertyValue $DefenderDevice 'Model'
        Site = Get-OptionalPropertyValue $DefenderDevice 'Site'
        OSPlatform = Get-OptionalPropertyValue $DefenderDevice 'OSPlatform'
        OSDistribution = Get-OptionalPropertyValue $DefenderDevice 'OSDistribution'
        OSVersion = Get-OptionalPropertyValue $DefenderDevice 'OSVersion'
        OSArchitecture = Get-OptionalPropertyValue $DefenderDevice 'OSArchitecture'
        PublicIP = Get-OptionalPropertyValue $DefenderDevice 'PublicIP'
        OnboardingStatus = Get-OptionalPropertyValue $DefenderDevice 'OnboardingStatus'
        SensorHealthState = Get-OptionalPropertyValue $DefenderDevice 'SensorHealthState'
        ExposureLevel = Get-OptionalPropertyValue $DefenderDevice 'ExposureLevel'
        AssetValue = Get-OptionalPropertyValue $DefenderDevice 'AssetValue'
        MachineGroup = Get-OptionalPropertyValue $DefenderDevice 'MachineGroup'
        IsInternetFacing = Get-OptionalPropertyValue $DefenderDevice 'IsInternetFacing'
        AzureResourceId = if ($hasAzure) { Get-OptionalPropertyValue $AzureResource 'AzureResourceId' } else { Get-OptionalPropertyValue $DefenderDevice 'AzureResourceId' }
        SubscriptionId = Get-OptionalPropertyValue $AzureResource 'SubscriptionId'
        SubscriptionName = Get-OptionalPropertyValue $AzureResource 'SubscriptionName'
        ResourceGroup = Get-OptionalPropertyValue $AzureResource 'ResourceGroup'
        AzureResourceType = Get-OptionalPropertyValue $AzureResource 'AzureResourceType'
        AzureResourceName = Get-OptionalPropertyValue $AzureResource 'AzureResourceName'
        AzureLocation = Get-OptionalPropertyValue $AzureResource 'AzureLocation'
        AzureComputerName = Get-OptionalPropertyValue $AzureResource 'ComputerName'
        AzureOsType = Get-OptionalPropertyValue $AzureResource 'OsType'
        AzureOsName = Get-OptionalPropertyValue $AzureResource 'OsName'
        AzureOsVersion = Get-OptionalPropertyValue $AzureResource 'OsVersion'
        VmSize = Get-OptionalPropertyValue $AzureResource 'VmSize'
        VmId = Get-OptionalPropertyValue $AzureResource 'VmId'
        HardwareManufacturer = Get-OptionalPropertyValue $AzureResource 'HardwareManufacturer'
        HardwareModel = Get-OptionalPropertyValue $AzureResource 'HardwareModel'
        CpuCount = Get-OptionalPropertyValue $AzureResource 'CpuCount'
        CpuName = Get-OptionalPropertyValue $AzureResource 'CpuName'
        CpuSpeedMhz = Get-OptionalPropertyValue $AzureResource 'CpuSpeedMhz'
        RamGb = Get-OptionalPropertyValue $AzureResource 'RamGb'
        OsDiskSizeGb = Get-OptionalPropertyValue $AzureResource 'OsDiskSizeGb'
        DataDisks = Get-OptionalPropertyValue $AzureResource 'DataDisks'
        ProvisioningState = Get-OptionalPropertyValue $AzureResource 'ProvisioningState'
        PowerState = Get-OptionalPropertyValue $AzureResource 'PowerState'
        SecurityType = Get-OptionalPropertyValue $AzureResource 'SecurityType'
        LicenseType = Get-OptionalPropertyValue $AzureResource 'LicenseType'
        ArcStatus = Get-OptionalPropertyValue $AzureResource 'ArcStatus'
        ArcAgentVersion = Get-OptionalPropertyValue $AzureResource 'ArcAgentVersion'
        ArcLastStatusChange = Get-OptionalPropertyValue $AzureResource 'ArcLastStatusChange'
        ArcMachineFqdn = Get-OptionalPropertyValue $AzureResource 'ArcMachineFqdn'
        ArcDomainName = Get-OptionalPropertyValue $AzureResource 'ArcDomainName'
        ArcCloudProvider = Get-OptionalPropertyValue $AzureResource 'ArcCloudProvider'
        IdentityType = Get-OptionalPropertyValue $AzureResource 'IdentityType'
        IdentityPrincipalId = Get-OptionalPropertyValue $AzureResource 'IdentityPrincipalId'
        AzureTags = Get-OptionalPropertyValue $AzureResource 'AzureTags'
        AzureZones = Get-OptionalPropertyValue $AzureResource 'AzureZones'
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

function Get-FirstPopulatedValue {
    param([AllowNull()][object[]]$Values)

    foreach ($value in $Values) {
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            return $value
        }
    }
    return $null
}

function ConvertFrom-AzureTags {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }
    try { return ([string]$Value | ConvertFrom-Json) }
    catch { return $null }
}

function Get-TagValue {
    param(
        [AllowNull()][object]$Tags,
        [Parameter(Mandatory)][string[]]$Names
    )

    if ($null -eq $Tags) { return $null }
    foreach ($name in $Names) {
        $property = $Tags.PSObject.Properties[$name]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return $property.Value
        }
    }
    return $null
}

function Get-TotalDiskSpaceGb {
    param([Parameter(Mandatory)][object]$Device)

    $total = 0.0
    $hasValue = $false
    $osDiskSize = Get-OptionalPropertyValue $Device 'OsDiskSizeGb'
    if ($null -ne $osDiskSize -and -not [string]::IsNullOrWhiteSpace([string]$osDiskSize)) {
        $total += [double]$osDiskSize
        $hasValue = $true
    }
    $dataDisksJson = Get-OptionalPropertyValue $Device 'DataDisks'
    if (-not [string]::IsNullOrWhiteSpace([string]$dataDisksJson)) {
        try {
            foreach ($disk in @([string]$dataDisksJson | ConvertFrom-Json)) {
                $diskSize = Get-OptionalPropertyValue $disk 'diskSizeGB'
                if ($null -ne $diskSize -and -not [string]::IsNullOrWhiteSpace([string]$diskSize)) {
                    $total += [double]$diskSize
                    $hasValue = $true
                }
            }
        }
        catch { }
    }
    if ($hasValue) { return [Math]::Round($total, 2) }
    return $null
}

function ConvertTo-DeviceAssetRows {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Devices)

    foreach ($device in $Devices) {
        $tags = ConvertFrom-AzureTags (Get-OptionalPropertyValue $device 'AzureTags')
        $assignee = Get-TagValue $tags @('Assignee', 'AssignedTo', 'Assigned to')
        $resourceType = [string](Get-OptionalPropertyValue $device 'AzureResourceType')
        $deviceType = Get-OptionalPropertyValue $device 'DeviceType'
        if ([string]::IsNullOrWhiteSpace([string]$deviceType)) {
            $deviceType = if ($resourceType -eq 'microsoft.hybridcompute/machines') { 'Server' } elseif ($resourceType -eq 'microsoft.compute/virtualmachines') { 'Virtual Machine' } else { 'Device' }
        }
        $manufacturer = Get-FirstPopulatedValue @(
            Get-OptionalPropertyValue $device 'Manufacturer'
            Get-OptionalPropertyValue $device 'HardwareManufacturer'
            if (-not [string]::IsNullOrWhiteSpace($resourceType)) { 'Microsoft' }
        )
        $model = Get-FirstPopulatedValue @(
            Get-OptionalPropertyValue $device 'Model'
            Get-OptionalPropertyValue $device 'HardwareModel'
            Get-OptionalPropertyValue $device 'VmSize'
        )
        $code = Get-FirstPopulatedValue @(
            Get-OptionalPropertyValue $device 'DeviceId'
            Get-OptionalPropertyValue $device 'AzureResourceId'
        )

        [PSCustomObject][ordered]@{
            Code = $code
            Name = Get-OptionalPropertyValue $device 'DeviceName'
            SerialNumber = Get-OptionalPropertyValue $device 'VmId'
            'Brand/Manufacturer' = $manufacturer
            Model = $model
            Version = $null
            Type = $deviceType
            Company = Get-FirstPopulatedValue @((Get-TagValue $tags @('Company', 'Azienda')), (Get-OptionalPropertyValue $device 'SubscriptionName'))
            Department = Get-TagValue $tags @('Department', 'Dipartimento')
            'Acquisition method' = Get-TagValue $tags @('AcquisitionMethod', 'Acquisition method', 'Acquisto/Noleggio')
            'Asset owner' = Get-TagValue $tags @('AssetOwner', 'Asset owner', 'Owner')
            'Assigned date' = Get-TagValue $tags @('AssignedDate', 'Assigned date')
            Assignee = $assignee
            'Installed date' = Get-TagValue $tags @('InstalledDate', 'Installed date')
            Building = Get-FirstPopulatedValue @((Get-TagValue $tags @('Building', 'Sede')), (Get-OptionalPropertyValue $device 'Site'), (Get-OptionalPropertyValue $device 'AzureLocation'))
            Floor = Get-TagValue $tags @('Floor', 'Piano')
            Room = Get-TagValue $tags @('Room', 'Stanza')
            PurchasePrice = Get-TagValue $tags @('PurchasePrice', 'Purchase price', 'Prezzo acquisto')
            Supplier = Get-TagValue $tags @('Supplier', 'Fornitore')
            'Delivery date' = Get-TagValue $tags @('DeliveryDate', 'Delivery date')
            OS = Get-FirstPopulatedValue @((Get-OptionalPropertyValue $device 'OSPlatform'), (Get-OptionalPropertyValue $device 'AzureOsName'), (Get-OptionalPropertyValue $device 'AzureOsType'))
            'OS version' = Get-FirstPopulatedValue @((Get-OptionalPropertyValue $device 'OSVersion'), (Get-OptionalPropertyValue $device 'AzureOsVersion'))
            'CPU count' = Get-OptionalPropertyValue $device 'CpuCount'
            'CPU name' = Get-OptionalPropertyValue $device 'CpuName'
            'CPU speed' = Get-OptionalPropertyValue $device 'CpuSpeedMhz'
            RAM = Get-OptionalPropertyValue $device 'RamGb'
            'Disk space' = Get-TotalDiskSpaceGb $device
            State = if ([string]::IsNullOrWhiteSpace([string]$assignee)) { 'Disponibile' } else { 'In uso' }
            'Warranty end date' = Get-TagValue $tags @('WarrantyEndDate', 'Warranty end date')
            Parent = $null
        }
    }
}

function ConvertTo-SoftwareAssetRows {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$SoftwareRows)

    foreach ($software in $SoftwareRows) {
        $parent = Get-OptionalPropertyValue $software 'DeviceId'
        $vendor = Get-OptionalPropertyValue $software 'SoftwareVendor'
        $name = Get-OptionalPropertyValue $software 'SoftwareName'
        $version = Get-OptionalPropertyValue $software 'SoftwareVersion'
        $productCode = Get-OptionalPropertyValue $software 'ProductCodeCpe'
        if ([string]::IsNullOrWhiteSpace([string]$productCode) -or $productCode -eq 'Not Available') {
            $productCode = @($vendor, $name, $version) -join ':'
        }
        [PSCustomObject][ordered]@{
            Code = "$parent|$productCode"
            Name = $name
            SerialNumber = $null
            'Brand/Manufacturer' = $vendor
            Model = $null
            Version = $version
            Type = 'Software'
            Company = $null
            Department = $null
            'Acquisition method' = $null
            'Asset owner' = $null
            'Assigned date' = $null
            Assignee = $null
            'Installed date' = $null
            Building = $null
            Floor = $null
            Room = $null
            PurchasePrice = $null
            Supplier = $null
            'Delivery date' = $null
            OS = Get-OptionalPropertyValue $software 'OSPlatform'
            'OS version' = Get-OptionalPropertyValue $software 'OSVersion'
            'CPU count' = $null
            'CPU name' = $null
            'CPU speed' = $null
            RAM = $null
            'Disk space' = $null
            State = 'In uso'
            'Warranty end date' = $null
            Parent = $parent
        }
    }
}

function Set-ExcelWorksheetData {
    param(
        [Parameter(Mandatory)][object]$Worksheet,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows
    )

    $Worksheet.Name = $Name
    $values = [object[,]]::new($Rows.Count + 1, $Headers.Count)
    for ($columnIndex = 0; $columnIndex -lt $Headers.Count; $columnIndex++) {
        $values[0, $columnIndex] = $Headers[$columnIndex]
    }
    for ($rowIndex = 0; $rowIndex -lt $Rows.Count; $rowIndex++) {
        for ($columnIndex = 0; $columnIndex -lt $Headers.Count; $columnIndex++) {
            $value = Get-OptionalPropertyValue $Rows[$rowIndex] $Headers[$columnIndex]
            if ($value -is [string] -and $value -match '^[=+@]') { $value = "'$value" }
            $values[($rowIndex + 1), $columnIndex] = $value
        }
    }

    $lastCell = $Worksheet.Cells.Item($Rows.Count + 1, $Headers.Count)
    $range = $Worksheet.Range($Worksheet.Cells.Item(1, 1), $lastCell)
    $range.Value2 = $values
    $headerRange = $Worksheet.Range($Worksheet.Cells.Item(1, 1), $Worksheet.Cells.Item(1, $Headers.Count))
    $headerRange.Font.Bold = $true
    $headerRange.Interior.Color = 15773696
    [void]$headerRange.AutoFilter()
    [void]$range.Columns.AutoFit()
    foreach ($excelColumn in @($range.Columns)) {
        if ($excelColumn.ColumnWidth -gt 50) { $excelColumn.ColumnWidth = 50 }
    }
    $Worksheet.Activate()
    $Worksheet.Application.ActiveWindow.SplitRow = 1
    $Worksheet.Application.ActiveWindow.FreezePanes = $true

    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($headerRange)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($range)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($lastCell)
}

function Write-ExcelInventory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$DeviceRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$SoftwareRows
    )

    $excel = $null
    $workbook = $null
    $deviceSheet = $null
    $softwareSheet = $null
    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $workbook = $excel.Workbooks.Add()
        $deviceSheet = $workbook.Worksheets.Item(1)
        $softwareSheet = $workbook.Worksheets.Add()
        while ($workbook.Worksheets.Count -gt 2) {
            $workbook.Worksheets.Item($workbook.Worksheets.Count).Delete()
        }
        $headers = @('Code', 'Name', 'SerialNumber', 'Brand/Manufacturer', 'Model', 'Version', 'Type', 'Company',
            'Department', 'Acquisition method', 'Asset owner', 'Assigned date', 'Assignee', 'Installed date',
            'Building', 'Floor', 'Room', 'PurchasePrice', 'Supplier', 'Delivery date', 'OS', 'OS version',
            'CPU count', 'CPU name', 'CPU speed', 'RAM', 'Disk space', 'State', 'Warranty end date', 'Parent')
        Set-ExcelWorksheetData $deviceSheet 'Devices' $headers $DeviceRows
        Set-ExcelWorksheetData $softwareSheet 'Software' $headers $SoftwareRows
        $deviceSheet.Activate()
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $workbook.SaveAs($fullPath, 51)
    }
    finally {
        if ($null -ne $workbook) { $workbook.Close($false) }
        if ($null -ne $excel) { $excel.Quit() }
        foreach ($comObject in @($softwareSheet, $deviceSheet, $workbook, $excel)) {
            if ($null -ne $comObject) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($comObject) }
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
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
    AzureResourceId = column_ifexists('AzureResourceId', ''),
    AadDeviceId = column_ifexists('AadDeviceId', ''),
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

$azureResourceQuery = @"
resources
| where type in~ ('microsoft.compute/virtualmachines', 'microsoft.hybridcompute/machines')
| extend NormalizedType = tolower(type)
| extend ComputerName = case(
    NormalizedType == 'microsoft.compute/virtualmachines', tostring(properties.osProfile.computerName),
    tostring(properties.displayName))
| extend OsType = case(
    NormalizedType == 'microsoft.compute/virtualmachines', tostring(properties.storageProfile.osDisk.osType),
    tostring(properties.osType))
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, SubscriptionName = name
) on subscriptionId
| project AzureResourceId = tolower(id), SubscriptionId = subscriptionId, SubscriptionName,
    ResourceGroup = resourceGroup, AzureResourceType = NormalizedType,
    AzureResourceName = name, AzureLocation = location, ComputerName, OsType,
    OsName = tostring(properties.osName), OsVersion = tostring(properties.osVersion),
    VmSize = tostring(properties.hardwareProfile.vmSize), VmId = tostring(properties.vmId),
    HardwareManufacturer = tostring(properties.detectedProperties.manufacturer),
    HardwareModel = tostring(properties.detectedProperties.model),
    CpuCount = toint(coalesce(properties.processorCount, properties.detectedProperties.logicalCoreCount)),
    CpuName = tostring(properties.detectedProperties.processorName),
    CpuSpeedMhz = todouble(properties.detectedProperties.processorSpeedInMHz),
    RamGb = round(todouble(properties.totalPhysicalMemoryInBytes) / 1073741824.0, 2),
    OsDiskSizeGb = toint(properties.storageProfile.osDisk.diskSizeGB),
    DataDisks = tostring(properties.storageProfile.dataDisks),
    ProvisioningState = tostring(properties.provisioningState),
    PowerState = tostring(properties.extended.instanceView.powerState.code),
    SecurityType = tostring(properties.securityProfile.securityType), LicenseType = tostring(properties.licenseType),
    ArcStatus = tostring(properties.status), ArcAgentVersion = tostring(properties.agentVersion),
    ArcLastStatusChange = tostring(properties.lastStatusChange), ArcMachineFqdn = tostring(properties.machineFqdn),
    ArcDomainName = tostring(properties.domainName), ArcCloudProvider = tostring(properties.cloudMetadata.provider),
    IdentityType = tostring(identity.type), IdentityPrincipalId = tostring(identity.principalId),
    AzureTags = tostring(tags), AzureZones = tostring(zones)
| order by SubscriptionName asc, ResourceGroup asc, AzureResourceName asc
"@

$useDefender = $InventorySource -in @('Defender', 'Combined')
$useAzure = $InventorySource -in @('Azure', 'Combined')
if ($IncludeVulnerabilities -and -not $useDefender) {
    throw 'IncludeVulnerabilities requires InventorySource Defender or Combined.'
}

$graphToken = $null
$azureToken = $null
$script:headers = $null
$script:azureHeaders = $null

try {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $defenderDeviceRows = @()
    $softwareRows = @()
    $vulnerabilityRows = @()
    if ($useDefender) {
        if ($script:parameterSetName -eq 'ConnectedUser') {
            if ($null -eq (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) -or $null -eq (Get-MgContext)) {
                throw 'No Microsoft Graph user session was found. Run Connect-MgGraph -Scopes ThreatHunting.Read.All first.'
            }
        }
        else {
            $graphToken = Get-AccessToken -Scope 'https://graph.microsoft.com/.default' `
                -ProvidedToken $AccessToken -TokenName 'AccessToken'
            $script:headers = @{ Authorization = "Bearer $graphToken"; Accept = 'application/json' }
        }
        $defenderDeviceRows = @(Invoke-HuntingQuery -Name 'device inventory' -Query $deviceQuery)
        $softwareRows = @(Invoke-HuntingQuery -Name 'software inventory' -Query $softwareQuery)
        if ($IncludeVulnerabilities) {
            $vulnerabilityRows = @(Invoke-HuntingQuery -Name 'vulnerability inventory' -Query $vulnerabilityQuery)
        }
    }

    $azureRows = @()
    if ($useAzure) {
        $azureToken = Get-AccessToken -Scope 'https://management.azure.com/.default' `
            -ProvidedToken $AzureAccessToken -TokenName 'AzureAccessToken'
        $script:azureHeaders = @{ Authorization = "Bearer $azureToken"; Accept = 'application/json' }
        $azureRows = @(Invoke-ResourceGraphQuery -Query $azureResourceQuery)
        Write-CsvResult -Rows $azureRows -Path (Join-Path $OutputDirectory 'azure-resources.csv') `
            -EmptyHeaders @('AzureResourceId', 'SubscriptionId', 'SubscriptionName', 'ResourceGroup', 'AzureResourceType', 'AzureResourceName')
    }

    $azureByResourceId = @{}
    foreach ($azureRow in $azureRows) {
        $resourceId = [string](Get-OptionalPropertyValue $azureRow 'AzureResourceId')
        if (-not [string]::IsNullOrWhiteSpace($resourceId)) {
            $azureByResourceId[$resourceId.ToLowerInvariant()] = $azureRow
        }
    }
    $matchedAzureIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $deviceRows = [Collections.Generic.List[object]]::new()
    foreach ($defenderDevice in $defenderDeviceRows) {
        $resourceId = [string](Get-OptionalPropertyValue $defenderDevice 'AzureResourceId')
        $azureResource = $null
        if (-not [string]::IsNullOrWhiteSpace($resourceId)) {
            $normalizedId = $resourceId.ToLowerInvariant()
            if ($azureByResourceId.ContainsKey($normalizedId)) {
                $azureResource = $azureByResourceId[$normalizedId]
                [void]$matchedAzureIds.Add($normalizedId)
            }
        }
        $deviceRows.Add((New-DeviceInventoryRow -DefenderDevice $defenderDevice -AzureResource $azureResource))
    }
    foreach ($azureRow in $azureRows) {
        $resourceId = [string](Get-OptionalPropertyValue $azureRow 'AzureResourceId')
        if (-not $matchedAzureIds.Contains($resourceId)) {
            $deviceRows.Add((New-DeviceInventoryRow -DefenderDevice $null -AzureResource $azureRow))
        }
    }

    $deviceArray = $deviceRows.ToArray()
    Write-CsvResult -Rows $deviceArray -Path (Join-Path $OutputDirectory 'devices.csv') `
        -EmptyHeaders @('InventorySources', 'Timestamp', 'DeviceId', 'DeviceName', 'AzureResourceId', 'SubscriptionId', 'ResourceGroup', 'AzureResourceType')
    Write-CsvResult -Rows $softwareRows -Path (Join-Path $OutputDirectory 'installed-software.csv') `
        -EmptyHeaders @('DeviceId', 'DeviceName', 'DeviceCategory', 'DeviceType', 'SoftwareVendor', 'SoftwareName', 'SoftwareVersion')

    $deviceAssetRows = @(ConvertTo-DeviceAssetRows $deviceArray)
    $softwareAssetRows = @(ConvertTo-SoftwareAssetRows $softwareRows)
    $excelPath = Join-Path $OutputDirectory $ExcelFileName
    Write-Host "Writing Excel asset inventory: $excelPath"
    Write-ExcelInventory -Path $excelPath -DeviceRows $deviceAssetRows -SoftwareRows $softwareAssetRows

    if ($IncludeVulnerabilities) {
        Write-CsvResult -Rows $vulnerabilityRows -Path (Join-Path $OutputDirectory 'vulnerabilities.csv') `
            -EmptyHeaders @('DeviceId', 'DeviceName', 'DeviceCategory', 'DeviceType', 'SoftwareVendor', 'SoftwareName', 'SoftwareVersion', 'CveId')
    }

    Write-Host "Export complete: $OutputDirectory"
    Write-Host "Devices: $($deviceArray.Count); Azure resources: $($azureRows.Count); software records: $($softwareRows.Count); vulnerabilities: $($vulnerabilityRows.Count)"
    Write-Host "Excel workbook: $excelPath"
}
finally {
    $graphToken = $null
    $azureToken = $null
    if ($null -ne $script:headers) { $script:headers.Authorization = $null }
    if ($null -ne $script:azureHeaders) { $script:azureHeaders.Authorization = $null }
}
