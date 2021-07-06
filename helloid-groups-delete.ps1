##########-------------------- Script parameters --------------------##########
$portalBaseUrl = "https://<customer>.helloid.com"
$HelloIDApiKey = "<Enter API Key>"
$HelloIDApiSecret = "<Enter API Secret>"
# Value to use in wildcard filter for HelloID Groups
$HelloIDGroupExclusionFilter = "Users"
$HelloIDGroupInclusionFilter = "yourgroupfilter"
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
# Function for retrieving groups
function Get-HIDGroups{​
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
        Write-HidStatus -Message "Gathering groups from HelloID..." -Event Information
        if($PortalBaseUrl.EndsWith("/")){​
            $uri = ($PortalBaseUrl +"api/v1/groups")
        }​else{​
            $uri = ($PortalBaseUrl +"/api/v1/groups")
        }​
        $groups = New-Object PSCustomObject
        Invoke-HidRestMethod -Response ([Ref]$groups) -Method Get -Uri $uri -Headers $Headers -ContentType "application/json" -PageSize 500
        if(![string]::IsNullOrEmpty($InclusionFilter)){​
            Write-HidStatus -Message "Found [$($groups.Count)] groups. Filtering out groups with [$InclusionFilter] NOT in their name." -Event Warning
            $groups = foreach($group in $groups){​
                if($group.name -like "*$InclusionFilter*"){​
                    $group
                }​
            }​
        }​
        if(![string]::IsNullOrEmpty($ExclusionFilter)){​
            Write-HidStatus -Message "Found [$($groups.Count)] groups. Filtering out groups with [$ExclusionFilter] in their name." -Event Warning
            $groups = foreach($group in $groups){​
                if($group.name -notlike "*$ExclusionFilter*"){​
                    $group
                }​
            }​
        }​
        $Response.Value = $groups
        Write-HidStatus -Message "Finished gathering groups from HelloID, found [$($groups.Count)] groups" -Event Success
    }​catch{​
        throw "Could not gather groups from HelloID, errorcode: '0x$('{​0:X8}​' -f $_.Exception.HResult)', message: $($_.Exception.Message)"
    }​
}​
function Remove-HIDGroup{​
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] 
        [String] 
        $PortalBaseUrl,
        [Parameter(Mandatory=$true)] 
        $Headers,
        [Parameter(Mandatory=$true)]
        [String]
        $GroupName,
        [Parameter(Mandatory=$false)]
        $GroupGuid,
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
            Write-HidStatus -Message "Deleting HelloID group '$GroupName'..." -Event Information
        }​
        if($PortalBaseUrl.EndsWith("/")){​
            $uri = ($PortalBaseUrl + "api/v1/groups/")
        }​else{​
            $uri = ($PortalBaseUrl + "/api/v1/groups/")
        }​
        if(![string]::IsNullOrEmpty($GroupGUID)){​
            $uri = ($uri + "$GroupGUID")
        }​else{​
            $uri = ($uri + "$GroupName")
        }​
        $removedGroup = New-Object PSCustomObject
        Invoke-HidWebRequest -Response ([Ref]$removedGroup) -Method Delete -Uri $uri -Headers $Headers -ContentType "application/json"
        $Response.Value = $removedGroup
        if($Logging){​
            Write-HidStatus -Message "Successfully removed HelloID group '$GroupName'" -Event Success
        }​
    }​catch{​
        if($_.Exception.Message -eq "The remote server returned an error: (400) Bad Request."){​
            $message = ($_.ErrorDetails.Message | ConvertFrom-Json).message
            throw "Could not delete HelloID group '$GroupName', errorcode: 'x$('{​0:X8}​' -f $_.Exception.HResult), message: $($_.Exception.Message)$message"
        }​else{​
            throw "Could not  delete HelloID group '$GroupName', errorcode: 'x$('{​0:X8}​' -f $_.Exception.HResult), message: $($_.Exception.Message)"
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
# HelloID API - Get HelloID groups
try{​
    $hidGroups = New-Object PSCustomObject
    Get-HIDGroups -PortalBaseUrl $portalBaseUrl -Headers $headers -Response ([Ref]$hidGroups) -InclusionFilter $HelloIDGroupInclusionFilter -ExclusionFilter $HelloIDGroupExclusionFilter
}​catch{​
    throw $_
}​
#-------------------- Delete groups --------------------#
$deleteSuccess = 0
$deleteFailed = 0
foreach($hidGroup in $hidGroups){​
    try{​
        $deletedHidGroup = New-Object PSCustomObject
        Remove-HIDGroup -GroupName $hidGroup.name -GroupGuid $hidGroup.groupGuid -PortalBaseUrl $portalBaseUrl -Headers $headers -Response ([Ref]$deletedHidGroup) -Logging:$false
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
    Write-HidStatus -Message "Finished deleting [$($deleteSuccess)] HelloID groups." -Event Success
    Write-HidSummary -Message "Successfully deleted [$($deleteSuccess)] HelloID groups, check the Progress for more details." -Event Success
}​else{​
    Write-HidStatus -Message "No HelloID groups to delete." -Event Success
    Write-HidSummary -Message "There were no HelloID groups to delete, check the Progress for more details." -Event Success
}​
