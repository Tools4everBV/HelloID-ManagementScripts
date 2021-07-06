##########-------------------- Script parameters --------------------##########
$portalBaseUrl = "https://<customer>.helloid.com"
$HelloIDApiKey = "<Enter API Key>"
$HelloIDApiSecret = "<Enter API Secret>"
# Value to use in wildcard filter for HelloID Users
$HelloIDUserExclusionFilter = "admin"
$HelloIDUserInclusionFilter = "youruserfilter"
$deleteErrorsCritical = $false
############################################################## Global Functions ##############################################################
function Write-HidStatus{​
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Message,
        [Parameter(Mandatory=$true)]
        [String]
        $Event
    )
    if([String]::IsNullOrEmpty($portalBaseUrl) -eq $true){​
        Write-Output ($Message)
    }​else{​
        #Hid-Write-Status -Message $Message -Event $Event
        Write-Output ($Message)
    }​
}​
function Write-HidSummary{​
    [cmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Message,
        [Parameter(Mandatory=$true)]
        [String]
        $Event
    )
    if([String]::IsNullOrEmpty($portalBaseUrl) -eq $true){​
        Write-Output ($Message)
    }​else{​
        #Hid-Write-Summary -Message $Message -Event $Event
        Write-Output ($Message)
    }​
}​
############################################################## HelloID Functions ##############################################################
# Create function to create new web request key
function New-WebRequestKey{​
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] 
        [String] 
        $ApiKey,
        [Parameter(Mandatory=$true)] 
        [String] 
        $ApiSecret,
        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{​
        Write-HidStatus -Message "Creating HelloID API key..." -Event Information
        $Response.Value = $null
        $pair = "${​ApiKey}​:${​ApiSecret}​"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $key = "Basic $base64"
        $Response.Value = $key
        Write-HidStatus -Message "Successfully created HelloID API key" -Event Success
    }​catch{​
        throw "Could not create HelloID API key, errorcode: 0x$('{​0:X8}​' -f $_.Exception.HResult), message: $($_.Exception.Message)"
    }​
}​
# Create function for Rest method
function Invoke-HidRestMethod{​
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] 
        [String] 
        $Method,
        [Parameter(Mandatory=$true)] 
        [String] 
        $Uri,
        [Parameter(Mandatory=$false)] 
        [String] 
        $ContentType,
        [Parameter(Mandatory=$false)] 
        [String] 
        $Key,
        [Parameter(Mandatory=$false)] 
        $Body,
        [Parameter(Mandatory=$true)]
        [Ref]
        $Response,
        [Parameter(Mandatory=$false)] 
        $Credential,
        [Parameter(Mandatory=$false)]
        $Headers,
        [Parameter(Mandatory=$false)]
        $PageSize
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    $parameters = @{​}​
    if($Body){​
        $parameters += @{​
            Body = $Body
        }​
    }​
    if($ContentType){​
        $parameters += @{​
            ContentType = $ContentType
        }​
    }​
    if($Key){​
        $header = @{​}​
        $header.Add("authorization",$Key)
        $parameters += @{​
            Headers = $header
        }​
    }​
    if($Credential){​
        $parameters += @{​
            Credential = $Credential
        }​
    }​
    if($Headers -and !$key){​
        $parameters += @{​
            Headers = $Headers
        }​
    }​
    $Response.Value = $null
    try{​
        if($Uri.EndsWith("/") -eq $true){​
            Write-HidStatus -Message ("Failed::Get::$Uri::Uri invalid") -Event Error
            return
        }​
        if($PageSize -ne $null){​
            $take = $PageSize
            $skip = 0
            if($Uri -match '\?'){​
                $uriFirstPage = $Uri + "&skip=$skip&take=$take"
            }​else{​
                $uriFirstPage = $Uri + "?skip=$skip&take=$take"
            }​
            $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($uriFirstPage)
            $dataset = Invoke-RestMethod -Method $Method -Uri $uriFirstPage @parameters
            if($dataset.pageData -ne $null){​
                $dataset = $dataset.pageData
            }​
            $result = $servicePoint.CloseConnectionGroup("")
            $Response.Value += $dataset
            Write-HidStatus -Message ("Successfully retrieved data from $uriFirstPage") -Event Information
            $skip += $take
            while($dataset.Count -eq $take){​
                if($Uri -match '\?'){​
                    $uriPage = $Uri + "&skip=$skip&take=$take"
                }​else{​
                    $uriPage = $Uri + "?skip=$skip&take=$take"
                }​
                $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($uriPage)
                $dataset = Invoke-RestMethod -Method $Method -Uri $uriPage @parameters
                if($dataset.pageData -ne $null){​
                    $dataset = $dataset.pageData
                }​
                $result = $servicePoint.CloseConnectionGroup("")
                $skip += $take
                $Response.Value += $dataset
                Write-HidStatus -Message "Successfully retrieved data from $uriPage" -Event Information
            }​
        }​else{​
            $Response.Value = $null
            $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($Uri)
            $Response.Value = Invoke-RestMethod -Method Get -Uri $Uri @parameters
            $result = $servicePoint.CloseConnectionGroup("") 
        }​
    }​catch{​
        throw $_
    }​
}​
# Create function for web request
function Invoke-HidWebRequest{​
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] 
        [String] 
        $Method,
        [Parameter(Mandatory=$true)] 
        [String] 
        $Uri,
        [Parameter(Mandatory=$false)] 
        [String] 
        $ContentType,
        [Parameter(Mandatory=$false)] 
        [String] 
        $Key,
        [Parameter(Mandatory=$false)] 
        $Body,
        [Parameter(Mandatory = $true)]
        [Ref]
        $Response,
        [Parameter(Mandatory=$false)] 
        $Credential,
        [Parameter(Mandatory=$false)]
        $Headers
    )  
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls10 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    $parameters = @{​
        Uri = $Uri
        Method = $Method
    }​
    if($Body){​
        $parameters += @{​
            Body = $Body
        }​
    }​
    if($ContentType){​
        $parameters += @{​
            ContentType = $ContentType
        }​
    }​
    if($Key){​
        $header = @{​}​
        $header.Add("authorization",$Key)
        $parameters += @{​
            Headers = $header
        }​
    }​
    if($Credential){​
        $parameters += @{​
            Credential = $Credential
        }​
    }​
    if($Headers -and !$key){​
        $parameters += @{​
            Headers = $Headers
        }​
    }​
    if($PSVersionTable.PSVersion.ToString() -le "6.0"){​
        $parameters += @{​
            UseBasicParsing = $true
        }​
    }​
    try{​
        $Response.Value = $null
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($Uri)
        $webRequest = Invoke-WebRequest @parameters
        $result = $servicePoint.CloseConnectionGroup("")
        $Response.Value = $webRequest
    }​catch{​
        throw $_
    }​
}​
function Get-HIDUsers{​
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] 
        [String] 
        $PortalBaseUrl,
        [Parameter(Mandatory=$true)] 
        $Headers,
        [Parameter(Mandatory=$false)] 
        $InclusionFilter,    
        [Parameter(Mandatory=$false)] 
        $ExclusionFilter,          
        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{​
        $Response.Value = $null
        Write-HidStatus -Message "Gathering users from HelloID..." -Event Information
        if($PortalBaseUrl.EndsWith("/")){​
            $uri = ($PortalBaseUrl +"api/v1/users")
        }​else{​
            $uri = ($PortalBaseUrl +"/api/v1/users")
        }​
        $users = New-Object PSCustomObject
        Invoke-HidRestMethod -Response ([Ref]$users) -Method Get -Uri $uri -Headers $Headers -ContentType "application/json" -PageSize 500
        if(![string]::IsNullOrEmpty($InclusionFilter)){​
            Write-HidStatus -Message "Found [$($users.userName.Count)] users. Filtering out users with [$InclusionFilter] NOT in their username." -Event Warning
            $users = foreach($user in $users){​
                if($user.username -like "*$InclusionFilter*"){​
                    $user
                }​
            }​
        }​
        if(![string]::IsNullOrEmpty($ExclusionFilter)){​
            Write-HidStatus -Message "Found [$($users.userName.Count)] users. Filtering out users with [$ExclusionFilter] in their username." -Event Warning
            $users = foreach($user in $users){​
                if($user.username -notlike "*$ExclusionFilter*"){​
                    $user
                }​
            }​
        }​
        $Response.Value = $users
        Write-HidStatus -Message "Successfully gathered users from HelloID. Found [$($users.userName.Count)] users" -Event Success        
    }​catch{​
        throw "Could not gather users from HelloID, errorcode: 0x$('{​0:X8}​' -f $_.Exception.HResult), message: $($_.Exception.Message)"
    }​
}​
function Remove-HIDUser{​
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] 
        [String] 
        $PortalBaseUrl,
        [Parameter(Mandatory=$true)] 
        $Headers,
        [Parameter(Mandatory=$true)]
        [String]
        $Username,
        [Parameter(Mandatory=$false)]
        $UserGuid,
        [Parameter(Mandatory=$false)]
        [Boolean]
        $Logging,
        [Parameter(Mandatory=$true)]
        [Ref]
        $Response
    )
    try{​
        $Response.Value = $null
        if($Logging){​
            Write-HidStatus -Message "Deleting HelloID user '$Username'..." -Event Information
        }​
        if($PortalBaseUrl.EndsWith("/")){​
            $uri = ($PortalBaseUrl + "api/v1/users/")
        }​else{​
            $uri = ($PortalBaseUrl + "/api/v1/users/")
        }​
        if(![string]::IsNullOrEmpty($UserGuid)){​
            $uri = ($uri + "$UserGuid")
        }​else{​
            $uri = ($uri + "$Username")
        }​
        $user = New-Object PSCustomObject
        Invoke-HidWebRequest -Response ([Ref]$user) -Method Delete -Uri $uri -Headers $Headers -ContentType "application/json"
        $Response.Value = $user
        if($Logging){​
            Write-HidStatus -Message "Successfully deleted HelloID user '$Username'" -Event Success
        }​
    }​catch{​
        if($_.Exception.Message -eq "The remote server returned an error: (400) Bad Request."){​
            $message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
            throw "Could not delete HelloID user '$Username', errorcode: 'x$('{​0:X8}​' -f $_.Exception.HResult), message: $($_.Exception.Message)$message"
        }​else{​
            throw "Could not delete HelloID user '$Username', errorcode: 'x$('{​0:X8}​' -f $_.Exception.HResult), message: $($_.Exception.Message)"
            #Write-HidStatus -Message "Could not delete HelloID user '$Username', errorcode: 'x$('{​0:X8}​' -f $_.Exception.HResult), message: $($_.Exception.Message)" -Event Error
        }​
    }​
}​
##########-------------------- Script --------------------##########
# HelloID API - Get Web request key
try{​
    $key = New-Object PSCustomObject
    New-WebRequestKey -ApiKey $HelloIDApiKey -ApiSecret $HelloIDApiSecret -Response ([Ref]$key)
    $headers = @{​}​
    $headers.Add("authorization",$key)
}​catch{​
    throw $_
}​
# HelloID API - Get HelloID users
try{​
    $hidUsers = New-Object PSCustomObject
    Get-HIDUsers -PortalBaseUrl $portalBaseUrl -Headers $headers -InclusionFilter $HelloIDUserInclusionFilter -ExclusionFilter $HelloIDUserExclusionFilter -Response ([Ref]$hidUsers)
}​catch{​
    throw $_
}​
#-------------------- Delete groups --------------------#
$deleteSuccess = 0
$deleteFailed = 0
foreach($hidUser in $hidUsers){​
    try{​
        $deletedHidUser = New-Object PSCustomObject
        Remove-HIDUser -Username $hidUser.userName -UserGuid $hidUser.UserGuid -PortalBaseUrl $portalBaseUrl -Headers $headers -Response ([Ref]$deletedHidUser) -Logging:$false
        $deleteSuccess++
    }​catch{​
        $deleteFailed++
        if($deleteErrorsCritical){​
            throw $_
        }​else{​
            Write-HidStatus -Message $_ -Event Error
        }​
    }​
}​
if($deleteSuccess -gt 0){​
    Write-HidStatus -Message "Finished deleting [$($deleteSuccess)] HelloID users." -Event Success
    Write-HidSummary -Message "Successfully deleted [$($deleteSuccess)] HelloID users, check the Progress for more details." -Event Success
}​else{​
    Write-HidStatus -Message "No HelloID users to delete." -Event Success
    Write-HidSummary -Message "There were no HelloID users to delete, check the Progress for more details." -Event Success
}​
    
    
  
  

