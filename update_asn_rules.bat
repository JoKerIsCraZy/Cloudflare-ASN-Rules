@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content '%~f0' | Select-Object -Skip 5 | Out-String | Invoke-Expression"
goto :eof

# Cloudflare ASN Rules Updater (PowerShell)

$API_BASE = "https://api.cloudflare.com/client/v4"
$ASN_LIST_FILENAME = "ASN List"
$LIST_NAME = "managed_bad_asns"
$RULE_DESCRIPTION = "Block Bad ASNs"

Write-Host "Cloudflare ASN Rules Updater" -ForegroundColor Cyan
Write-Host "----------------------------" -ForegroundColor Cyan

# Inputs
$ZoneID = Read-Host "Enter Cloudflare Zone ID"
$ApiToken = Read-Host "Enter Cloudflare API Token"

if ([string]::IsNullOrWhiteSpace($ZoneID) -or [string]::IsNullOrWhiteSpace($ApiToken)) {
    Write-Error "Zone ID and API Token are required."
    exit 1
}

$Headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type"  = "application/json"
}

# 1. Read ASNs
if (-not (Test-Path $ASN_LIST_FILENAME)) {
    Write-Error "File '$ASN_LIST_FILENAME' not found."
    exit 1
}

Write-Host "Reading ASNs from '$ASN_LIST_FILENAME'..."
$RawContent = Get-Content $ASN_LIST_FILENAME
$ASNs = @()

foreach ($Line in $RawContent) {
    $Line = $Line.Trim()
    if (-not [string]::IsNullOrWhiteSpace($Line)) {
        # Remove 'AS' prefix if present
        if ($Line.StartsWith("AS", [System.StringComparison]::OrdinalIgnoreCase)) {
            $Line = $Line.Substring(2)
        }
        if ($Line -match "^\d+$") {
            $ASNs += [int]$Line
        }
    }
}
$ASNs = $ASNs | Select-Object -Unique
Write-Host "Found $($ASNs.Count) unique ASNs."

# 2. Get Account ID
Write-Host "Fetching Account ID..."
try {
    $Response = Invoke-RestMethod -Uri "$API_BASE/zones/$ZoneID" -Headers $Headers -Method Get
    if (-not $Response.success) {
        throw $Response.errors[0].message
    }
    $AccountID = $Response.result.account.id
    Write-Host "Account ID: $AccountID"
}
catch {
    Write-Error "Error fetching zone info: $_"
    exit 1
}

# 3. Manage ASN List
Write-Host "Checking for existing ASN list..."
try {
    $Response = Invoke-RestMethod -Uri "$API_BASE/accounts/$AccountID/rules/lists" -Headers $Headers -Method Get
    $ExistingList = $Response.result | Where-Object { $_.name -eq $LIST_NAME -and $_.kind -eq "asn" }
    
    $Items = $ASNs | ForEach-Object { @{ value = $_ } }

    if ($ExistingList) {
        $ListID = $ExistingList.id
        Write-Host "Updating ASN list '$ListID'..."
        # PUT /items replaces all items
        $Response = Invoke-RestMethod -Uri "$API_BASE/accounts/$AccountID/rules/lists/$ListID/items" `
            -Headers $Headers -Method Put -Body ($Items | ConvertTo-Json -Depth 10)
    }
    else {
        Write-Host "Creating new ASN list '$LIST_NAME'..."
        $Payload = @{
            name = $LIST_NAME
            kind = "asn"
            description = "List of bad ASNs managed by script"
            items = $Items
        }
        $Response = Invoke-RestMethod -Uri "$API_BASE/accounts/$AccountID/rules/lists" `
            -Headers $Headers -Method Post -Body ($Payload | ConvertTo-Json -Depth 10)
        $ListID = $Response.result.id
    }
    Write-Host "ASN List managed successfully."
}
catch {
    Write-Error "Error managing list: $_"
    exit 1
}

# 4. Manage WAF Rule
Write-Host "Configuring WAF Rule..."
try {
    # Get Ruleset ID
    $Response = Invoke-RestMethod -Uri "$API_BASE/zones/$ZoneID/rulesets/phases/http_request_firewall_custom/entrypoint" -Headers $Headers -Method Get
    $RulesetID = $Response.result.id
    
    $RulePayload = @{
        action = "managed_challenge"
        expression = "ip.asn in `$$LIST_NAME"
        description = $RULE_DESCRIPTION
        enabled = $true
    }

    if (-not $RulesetID) {
        Write-Host "Creating new Ruleset..."
        $Payload = @{
            name = "default"
            kind = "zone"
            phase = "http_request_firewall_custom"
            rules = @($RulePayload)
        }
        $Response = Invoke-RestMethod -Uri "$API_BASE/zones/$ZoneID/rulesets" `
            -Headers $Headers -Method Post -Body ($Payload | ConvertTo-Json -Depth 10)
    }
    else {
        # Check for existing rule
        $ExistingRule = $Response.result.rules | Where-Object { $_.description -eq $RULE_DESCRIPTION }
        
        if ($ExistingRule) {
            Write-Host "Updating existing WAF rule..."
            $RuleID = $ExistingRule.id
            $Response = Invoke-RestMethod -Uri "$API_BASE/zones/$ZoneID/rulesets/$RulesetID/rules/$RuleID" `
                -Headers $Headers -Method Patch -Body ($RulePayload | ConvertTo-Json -Depth 10)
        }
        else {
            Write-Host "Creating new WAF rule..."
            $Response = Invoke-RestMethod -Uri "$API_BASE/zones/$ZoneID/rulesets/$RulesetID/rules" `
                -Headers $Headers -Method Post -Body ($RulePayload | ConvertTo-Json -Depth 10)
        }
    }
    Write-Host "Done! Your Cloudflare protection has been updated." -ForegroundColor Green
}
catch {
    Write-Error "Error configuring WAF rule: $_"
    exit 1
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
