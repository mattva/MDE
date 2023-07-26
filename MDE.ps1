<#
    .SYNOPSIS
    Example use of Defender API to access MDE data
    .DESCRIPTION
    1. register an application and give access to the required WindowsDefenderATP API https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/management-apis?view=o365-worldwide
    2. configure AuthData_sample.json file with the SP authentication details
    3. rename AuthData_sample.json to AuthData.json
    4. run the script .\MDE.ps1
    
    Note: requires PS 7
    .INPUTS
    .OUTPUTS
    .EXAMPLE
    #>

#$apiversion="2015-06-01-preview" #supports 2015-06-01-preview and 2020-01-01
$settings=get-content -Path .\AuthData.json | ConvertFrom-Json
$tenantID=$settings.tenantid
$clientID=$settings.clientID
$clientSecret=$settings.clientSecret

Function Write-Log {
    <#
        .SYNOPSIS
            Write a log line with timestamp and verbosity level (INOF by default)
        .DESCRIPTION
            Write a log line with timestamp and verbosity level (INOF by default)
        .INPUTS
            Message: string with the message to append (mandatory)
            Level: verbosity Level (optional)
            Logfile: output log file (optional)
        .OUTPUTS
            None
        .EXAMPLE
            Write-Log INFO "Some message with $var" $logFile
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
    [String]
    $Level = "INFO",
    [Parameter(Mandatory=$True)]
    [string]
    $Message,
    [Parameter(Mandatory=$False)]
    [string]
    $logfile
    )
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If($logfile) {
        Add-Content $logfile -Value $Line
    }
    switch ($Level) {
        "INFO" {Write-host $line}
        "WARN" {Write-Host -ForegroundColor Yellow $Line}
        "ERROR" {Write-Host -ForegroundColor Magenta $line}
        "FATAL" {write-host -ForegroundColor Red $line}
        "DEBUG" {write-host -ForegroundColor Cyan $line}
    }
}
    
Function Authenticate {
    <#
    .SYNOPSIS
    OAuth 2.0 authentication with client_credentials flow
    .DESCRIPTION
    .INPUTS
    clientID, clientSecret, tenantID
    .OUTPUTS
    Authentication token
    .EXAMPLE
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [String]
    $clientID = "$clientID",
    [Parameter(Mandatory=$False)]
    [string]
    $clientSecret = "$clientSecret",
    [Parameter(Mandatory=$False)]
    [string]
    $tenantID = "$tenantID"
    )
    $sourceAppIdUri = 'https://api.securitycenter.microsoft.com/.default'
    $tokenBody = @{  
        source = "$sourceAppIdUri"
        Grant_Type    = "client_credentials"  
        Scope         = "https://api.securitycenter.microsoft.com/.default"  
        Client_Id     = $clientId  
        Client_Secret = $clientSecret  
    }  

    try {
        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenantid/oauth2/v2.0/token" -Method POST -Body $tokenBody        
    }
    catch {
        Write-Log ERROR "Cannot authenticate to tenant $tenantID"
        exit
    }
    return $tokenResponse
}


Function OffboardMachine() {
    <#
    .SYNOPSIS
    Get all Adaptive Application Control groups defined for the susbscription
    .DESCRIPTION
    .INPUTS
    access token object, subscriptionid, apiversion
    .OUTPUTS
    list of groups defined
    .EXAMPLE
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]
        $vmid,
        [Parameter(Mandatory=$True)]
        [PSCustomObject]
        $tk
    )

    $headers = @{ 
         Accept = 'application/json'
        "Authorization" = "Bearer $($tk.access_token)" 
        "Content-type" = "application/json" 
    }

    $url = "https://api.securitycenter.microsoft.com/api/machines/${vmid}/offboard"
    $body = @{"Comment"="offboarding machine";}|ConvertTo-Json

    $response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body "$body" -ErrorAction Stop
    return $response
}

Function Get-RunningMachineActions() {
        <#
    .SYNOPSIS
    Get all Adaptive Application Control groups defined for the susbscription
    .DESCRIPTION
    .INPUTS
    access token object, subscriptionid, apiversion
    .OUTPUTS
    list of groups defined
    .EXAMPLE
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [PSCustomObject]
        $tk
    )
    $headers = @{ 
        Accept = 'application/json'
       "Authorization" = "Bearer $($tk.access_token)" 
       "Content-type" = "application/json" 
   }
   $url = "https://api.securitycenter.microsoft.com/api/machineactions"
   #get all running actions
    $response = Invoke-WebRequest -Headers $headers -Method Get -Uri $url
    return $response.Content
}

