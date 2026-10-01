<#
.SYNOPSIS
Tests Defender Advanced Hunting and Azure Resource Graph inventory using an interactive user account.

.DESCRIPTION
Connects interactively to Microsoft Graph with the delegated ThreatHunting.Read.All
permission and to Azure Resource Manager with the signed-in user's RBAC permissions.
It then runs Export-DefenderInventoryGraph.ps1 with the same query, paging, merge,
CSV, and Excel output logic used by the service-principal workflow.

Required PowerShell modules:

    Microsoft.Graph.Authentication
    Az.Accounts

The signed-in user must have access to Defender Advanced Hunting and Reader access
on the Azure subscriptions being queried. Microsoft Graph and Azure Resource Manager
use different token audiences, so Combined mode establishes both user sessions.

.EXAMPLE
.\Test-DefenderInventoryGraphUser.ps1

Prompts for Microsoft Graph and Azure sign-in, then produces combined inventory.

.EXAMPLE
.\Test-DefenderInventoryGraphUser.ps1 -InventorySource Defender -Timespan P7D

Tests only Defender Advanced Hunting using the connected Microsoft Graph user.

.EXAMPLE
.\Test-DefenderInventoryGraphUser.ps1 -InventorySource Azure -SubscriptionId '<subscription-id>'

Tests only Azure Resource Graph using the connected Azure user.
#>
[CmdletBinding()]
param(
    [string]$TenantId,

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

    [string]$OutputDirectory = (Join-Path $PWD ('DefenderUserInventory-{0:yyyyMMdd-HHmmss}' -f (Get-Date))),

    [string]$ExcelFileName = 'DefenderAssetInventory-UserTest.xlsx',

    [switch]$KeepSession
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-RequiredModule {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$InstallCommand
    )

    if ($null -eq (Get-Module -ListAvailable -Name $Name)) {
        throw "Required module '$Name' is not installed. Run: $InstallCommand"
    }
    Import-Module $Name -ErrorAction Stop
}

function Assert-AzureSdkCompatibility {
    $azAccounts = Get-Module Az.Accounts
    $bundledCorePath = Join-Path $azAccounts.ModuleBase 'lib\netstandard2.0\Azure.Core.dll'
    if (-not (Test-Path -LiteralPath $bundledCorePath -PathType Leaf)) { return }

    $requiredVersion = [Reflection.AssemblyName]::GetAssemblyName($bundledCorePath).Version
    $loadedCore = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GetName().Name -eq 'Azure.Core' } |
        Select-Object -First 1
    if ($null -ne $loadedCore -and $loadedCore.GetName().Version -lt $requiredVersion) {
        throw "This PowerShell process already loaded Azure.Core $($loadedCore.GetName().Version), but Az.Accounts $($azAccounts.Version) requires $requiredVersion. Close this PowerShell terminal, open a new one, and run this script before importing other Azure modules. Az.Identity is not required."
    }
}

$useDefender = $InventorySource -in @('Defender', 'Combined')
$useAzure = $InventorySource -in @('Azure', 'Combined')
if ($IncludeVulnerabilities -and -not $useDefender) {
    throw 'IncludeVulnerabilities requires InventorySource Defender or Combined.'
}

$graphConnected = $false
$azureConnected = $false
try {
    # Az.Accounts must load first because Graph Authentication also bundles Azure SDK assemblies.
    if ($useAzure) {
        Assert-RequiredModule -Name 'Az.Accounts' `
            -InstallCommand "Install-Module Az.Accounts -Scope CurrentUser"
        Assert-AzureSdkCompatibility
    }
    if ($useDefender) {
        Assert-RequiredModule -Name 'Microsoft.Graph.Authentication' `
            -InstallCommand "Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }

    if ($useDefender) {
        $graphParameters = @{ Scopes = @('ThreatHunting.Read.All'); NoWelcome = $true }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $graphParameters.TenantId = $TenantId
        }
        Write-Host 'Connecting to Microsoft Graph for Defender Advanced Hunting...'
        Connect-MgGraph @graphParameters | Out-Null
        $graphConnected = $true
        $context = Get-MgContext
        Write-Host "Microsoft Graph connected as $($context.Account) in tenant $($context.TenantId)."
    }

    if ($useAzure) {
        $azureParameters = @{}
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $azureParameters.Tenant = $TenantId
        }
        Write-Host 'Connecting to Azure Resource Manager for Azure VM and Arc inventory...'
        $azureContext = Connect-AzAccount @azureParameters
        $azureConnected = $true
        Write-Host "Azure connected as $($azureContext.Context.Account.Id) in tenant $($azureContext.Context.Tenant.Id)."
    }

    $exportParameters = @{
        UseConnectedUser       = $true
        InventorySource        = $InventorySource
        DeviceCategory         = $DeviceCategory
        IncludeVulnerabilities = $IncludeVulnerabilities
        Timespan               = $Timespan
        MaxRetryCount          = $MaxRetryCount
        OutputDirectory        = $OutputDirectory
        ExcelFileName          = $ExcelFileName
    }
    if ($null -ne $SubscriptionId -and $SubscriptionId.Count -gt 0) {
        $exportParameters.SubscriptionId = $SubscriptionId
    }

    & (Join-Path $PSScriptRoot 'Export-DefenderInventoryGraph.ps1') @exportParameters
}
finally {
    if (-not $KeepSession) {
        if ($azureConnected) {
            Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null
        }
        if ($graphConnected) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
