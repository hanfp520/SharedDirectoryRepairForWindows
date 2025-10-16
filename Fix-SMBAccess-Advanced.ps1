# Windows 11 Home SMB Share Access Advanced Fix Tool
# This script requires administrator privileges
# Version: 1.0
# Author: SMB Advanced Fix Tool
# Specifically designed to handle error 0x80004005 and credential issues

param(
    [switch]$AutoFix,
    [string]$TargetIP,
    [string]$Username,
    [string]$Password
)

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Global variables
$LogPath = "$env:TEMP\SMB-Advanced-Fix-Log.txt"
$ScriptVersion = "1.0"

# Check administrator rights
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Write to log
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8
    Write-Host "[$Level] $Message" -ForegroundColor $(if($Level -eq "ERROR"){"Red"}elseif($Level -eq "WARN"){"Yellow"}else{"Green"})
}

# Show title
function Show-Title {
    Clear-Host
    $separator = "=" * 70
    Write-Host $separator -ForegroundColor Blue
    Write-Host "    Windows 11 Home SMB Advanced Fix Tool v$ScriptVersion" -ForegroundColor Green
    Write-Host "    Designed for Error 0x80004005 and Credential Issues" -ForegroundColor Yellow
    Write-Host $separator -ForegroundColor Blue
    Write-Host ""
}

# Test network connectivity
function Test-NetworkConnectivity {
    param([string]$TargetIP)
    
    Write-Log "Testing network connectivity to $TargetIP..."
    
    try {
        $pingResult = Test-Connection -ComputerName $TargetIP -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($pingResult) {
            Write-Log "Network connectivity to ${TargetIP}: OK"
            return $true
        } else {
            Write-Log "Network connectivity to ${TargetIP}: FAILED" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Network connectivity test failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Clear cached credentials
function Clear-CachedCredentials {
    Write-Log "Clearing cached credentials..."
    
    try {
        # Clear Windows credential manager
        $credentials = cmdkey /list | Select-String "Target:" | ForEach-Object { ($_ -split "Target: ")[1] }
        foreach ($cred in $credentials) {
            if ($cred -like "*$TargetIP*" -or $cred -like "*192.168.*" -or $cred -like "*10.*" -or $cred -like "*172.*") {
                cmdkey /delete:$cred 2>$null
                Write-Log "Deleted cached credential: $cred"
            }
        }
        
        # Clear SMB client cache
        Get-SmbConnection -ErrorAction SilentlyContinue | Remove-SmbConnection -Force -ErrorAction SilentlyContinue
        
        # Clear NetBIOS name cache
        nbtstat -R 2>$null
        nbtstat -RR 2>$null
        
        Write-Log "Cached credentials cleared successfully"
        return $true
    } catch {
        Write-Log "Failed to clear cached credentials: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Configure advanced SMB settings
function Set-AdvancedSMBSettings {
    Write-Log "Configuring advanced SMB settings..."
    
    try {
        # Enable SMB1 for compatibility (if needed)
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart -ErrorAction SilentlyContinue
        
        # Configure SMB client settings
        Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force -ErrorAction SilentlyContinue
        Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force -ErrorAction SilentlyContinue
        
        # Configure registry settings for SMB
        $regPaths = @(
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="AllowInsecureGuestAuth"; Value=1},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Value=0},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RequireSecuritySignature"; Value=0},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Value=1}
        )
        
        foreach ($reg in $regPaths) {
            if (Test-Path $reg.Path) {
                Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type DWord -ErrorAction SilentlyContinue
                Write-Log "Set registry: $($reg.Path)\$($reg.Name) = $($reg.Value)"
            }
        }
        
        Write-Log "Advanced SMB settings configured successfully"
        return $true
    } catch {
        Write-Log "Failed to configure advanced SMB settings: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Configure network security policies
function Set-NetworkSecurityPolicies {
    Write-Log "Configuring network security policies..."
    
    try {
        # Configure local security policies via registry
        $securityPolicies = @(
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="everyoneincludesanonymous"; Value=1},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Value=0},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Value=0}
        )
        
        foreach ($policy in $securityPolicies) {
            if (Test-Path $policy.Path) {
                Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.Value -Type DWord -ErrorAction SilentlyContinue
                Write-Log "Set security policy: $($policy.Name) = $($policy.Value)"
            }
        }
        
        Write-Log "Network security policies configured successfully"
        return $true
    } catch {
        Write-Log "Failed to configure network security policies: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Add credentials to Windows Credential Manager
function Add-CredentialToManager {
    param(
        [string]$TargetIP,
        [string]$Username,
        [string]$Password
    )
    
    Write-Log "Adding credentials to Windows Credential Manager..."
    
    try {
        # Add credential using cmdkey
        $result = cmdkey /add:$TargetIP /user:$Username /pass:$Password 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Credential added successfully for $TargetIP"
        } else {
            Write-Log "Failed to add credential: $result" "WARN"
        }
        
        # Also add with computer name format
        $result2 = cmdkey /add:"\\$TargetIP" /user:$Username /pass:$Password 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "UNC credential added successfully for \\$TargetIP"
        }
        
        return $true
    } catch {
        Write-Log "Failed to add credentials: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Test SMB connection
function Test-SMBConnection {
    param([string]$TargetIP)
    
    Write-Log "Testing SMB connection to $TargetIP..."
    
    try {
        # Test SMB connection
        $smbTest = Test-NetConnection -ComputerName $TargetIP -Port 445 -ErrorAction SilentlyContinue
        if ($smbTest.TcpTestSucceeded) {
            Write-Log "SMB port 445 is accessible on $TargetIP"
        } else {
            Write-Log "SMB port 445 is not accessible on $TargetIP" "ERROR"
            return $false
        }
        
        # Try to list shares
        $shares = net view \\$TargetIP 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully listed shares on $TargetIP"
            Write-Log "Available shares: $shares"
            return $true
        } else {
            Write-Log "Failed to list shares: $shares" "ERROR"
            return $false
        }
    } catch {
        Write-Log "SMB connection test failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Restart network services
function Restart-NetworkServices {
    Write-Log "Restarting network services..."
    
    $services = @("LanmanWorkstation", "LanmanServer", "Browser", "Dnscache")
    
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Restart-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                $newStatus = (Get-Service -Name $serviceName).Status
                Write-Log "Service $serviceName restarted, status: $newStatus"
            }
        } catch {
            Write-Log "Failed to restart service $serviceName : $($_.Exception.Message)" "ERROR"
        }
    }
}

# Main repair function
function Start-AdvancedRepair {
    param(
        [string]$TargetIP,
        [string]$Username,
        [string]$Password
    )
    
    Write-Log "Starting advanced SMB repair process..."
    
    $results = @()
    
    # Step 1: Test network connectivity
    if ($TargetIP) {
        $results += Test-NetworkConnectivity -TargetIP $TargetIP
    }
    
    # Step 2: Clear cached credentials
    $results += Clear-CachedCredentials
    
    # Step 3: Configure advanced SMB settings
    $results += Set-AdvancedSMBSettings
    
    # Step 4: Configure network security policies
    $results += Set-NetworkSecurityPolicies
    
    # Step 5: Restart network services
    Restart-NetworkServices
    
    # Step 6: Add credentials if provided
    if ($TargetIP -and $Username -and $Password) {
        $results += Add-CredentialToManager -TargetIP $TargetIP -Username $Username -Password $Password
    }
    
    # Step 7: Test SMB connection
    if ($TargetIP) {
        Start-Sleep -Seconds 5  # Wait for services to stabilize
        $results += Test-SMBConnection -TargetIP $TargetIP
    }
    
    # Calculate results
    $successCount = ($results | Where-Object { $_ -eq $true }).Count
    $totalCount = $results.Count
    
    Write-Log "Advanced repair completed! Success rate: $successCount/$totalCount"
    
    if ($successCount -eq $totalCount) {
        Write-Host "\n✅ All repair steps completed successfully!" -ForegroundColor Green
        Write-Host "Try accessing the shared folder now." -ForegroundColor Green
    } else {
        Write-Host "\n⚠️  Some repair steps failed. Check the log for details." -ForegroundColor Yellow
        Write-Host "You may need to manually configure some settings." -ForegroundColor Yellow
    }
    
    return ($successCount -eq $totalCount)
}

# Interactive mode for getting user input
function Get-UserInput {
    Show-Title
    
    Write-Host "This tool will help fix SMB access issues (Error 0x80004005)" -ForegroundColor Yellow
    Write-Host "Please provide the following information:\n" -ForegroundColor White
    
    # Get target IP
    do {
        $targetIP = Read-Host "Enter the IP address of the shared folder (e.g., 192.168.1.100)"
    } while (-not $targetIP -or $targetIP -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    
    # Get username
    $username = Read-Host "Enter username (leave empty for guest access)"
    
    # Get password
    if ($username) {
        $securePassword = Read-Host "Enter password" -AsSecureString
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
    } else {
        $password = ""
    }
    
    return @{
        TargetIP = $targetIP
        Username = $username
        Password = $password
    }
}

# Main program
function Main {
    # Check administrator rights
    if (-not (Test-AdminRights)) {
        Write-Host "Error: This script requires administrator privileges!" -ForegroundColor Red
        Write-Host "Please right-click PowerShell and select 'Run as administrator'" -ForegroundColor Yellow
        Read-Host "Press any key to exit"
        exit 1
    }
    
    # Create log file
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType File -Force | Out-Null
    }
    
    Write-Log "Advanced SMB Fix Tool started" "INFO"
    
    # If parameters are provided, use them directly
    if ($TargetIP) {
        Show-Title
        Write-Host "Auto-fix mode with provided parameters" -ForegroundColor Green
        Write-Host ""
        
        $success = Start-AdvancedRepair -TargetIP $TargetIP -Username $Username -Password $Password
        
        Write-Host "\nRecommendations:" -ForegroundColor Yellow
        Write-Host "1. Restart your computer to ensure all changes take effect" -ForegroundColor White
        Write-Host "2. Try accessing \\$TargetIP in File Explorer" -ForegroundColor White
        Write-Host "3. If still failing, check the target computer's sharing settings" -ForegroundColor White
        
        Write-Log "Auto-fix completed, success: $success"
        return
    }
    
    # Interactive mode
    $userInput = Get-UserInput
    
    Write-Host "\nStarting repair process..." -ForegroundColor Green
    Write-Host ""
    
    $success = Start-AdvancedRepair -TargetIP $userInput.TargetIP -Username $userInput.Username -Password $userInput.Password
    
    Write-Host "\nRecommendations:" -ForegroundColor Yellow
    Write-Host "1. Restart your computer to ensure all changes take effect" -ForegroundColor White
    Write-Host "2. Try accessing \\$($userInput.TargetIP) in File Explorer" -ForegroundColor White
    Write-Host "3. If still failing, check the target computer's sharing settings" -ForegroundColor White
    Write-Host "\nLog file location: $LogPath" -ForegroundColor Cyan
    
    Read-Host "\nPress any key to exit"
}

# Start main program
Main
