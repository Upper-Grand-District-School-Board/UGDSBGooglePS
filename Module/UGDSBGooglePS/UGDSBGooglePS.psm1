#Region '.\Public\Disable-Chromebook.ps1' 0
function Disable-Chromebook{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$deviceID
  )
  # Ensure that they have a access token
  if(-not $global:googleAccessToken){
    throw "Please ensure that you have called Get-GoogleAccessToken cmdlet"
  }  
  # Confirm we have a valid access token
  if(-not $(Test-GoogleAccessToken)){
    Get-GoogleAccessToken -json $global:googleJSON -customerId $global:googleCustomerId
  }  
  # Generate the final API endppoint URI
  $endpoint = "admin/directory/v1/customer/$($global:googleCustomerId)/devices/chromeos/$($deviceID)/action"
  $body = @{
    "action" = "disable"
  }
  try{
    $result = Get-GoogleAPI -Method "POST" -endpoint $endpoint -Body $body
    if($null -ne ($result.tostring() | COnvertFrom-JSON).error){
      throw ($result.tostring() | COnvertFrom-JSON).error.message
    }
    Write-Verbose "Status Result: $($result.StatusCode)"    
  }
  catch{
    throw $_
  }
}
#EndRegion '.\Public\Disable-Chromebook.ps1' 30
#Region '.\Public\Enable-Chromebook.ps1' 0
function Enable-Chromebook{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$deviceID
  )
  # Ensure that they have a access token
  if(-not $global:googleAccessToken){
    throw "Please ensure that you have called Get-GoogleAccessToken cmdlet"
  }  
  # Confirm we have a valid access token
  if(-not $(Test-GoogleAccessToken)){
    Get-GoogleAccessToken -json $global:googleJSON -customerId $global:googleCustomerId
  }  
  # Generate the final API endppoint URI
  $endpoint = "admin/directory/v1/customer/$($global:googleCustomerId)/devices/chromeos/$($deviceID)/action"
  $body = @{
    "action" = "reenable"
  }
  try{
    $result = Get-GoogleAPI -Method "POST" -endpoint $endpoint -Body $body
    if($null -ne ($result.tostring() | COnvertFrom-JSON).error){
      throw ($result.tostring() | COnvertFrom-JSON).error.message
    }
    Write-Verbose "Status Result: $($result.StatusCode)"    
  }
  catch{
    throw $_
  }
}
#EndRegion '.\Public\Enable-Chromebook.ps1' 30
#Region '.\Public\Get-ChromeDevices.ps1' 0
<#
  .DESCRIPTION
  This cmdlet will retrive chrome OS devices
  https://developers.google.com/admin-sdk/directory/reference/rest/v1/chromeosdevices/list
  https://developers.google.com/admin-sdk/directory/v1/list-query-operators
  .PARAMETER maxResults
  How many results to return per page, maximum per page is 300
  .PARAMETER orderBy
  How the results should be sorted
  .PARAMETER orgUnitPath
  Restrict to a specific organization unit
  .PARAMETER projection
  If we want basic or full data. Default is full.
  .PARAMETER query
  The query to use against the data
  https://developers.google.com/admin-sdk/directory/v1/list-query-operators
  .PARAMETER sortOrder
  Ascending or Descending sort order 
  .PARAMETER includeChildOrgunits
  If we should include child organization in use with orgUnitPath  
  .PARAMETER all
  If we should return all results and not just a single page
#>
function Get-ChromeDevices{
  [CmdletBinding()]
  [OutputType([System.Collections.Generic.List[PSCustomObject]])]
  param(
    [Parameter()][ValidateRange(1, 300)][int]$maxResults = 100,
    [Parameter()][ValidateSet('ANNOTATED_LOCATION','ANNOTATED_USER','LAST_SYNC','NOTES','SERIAL_NUMBER','STATUS')][string]$orderBy,
    [Parameter()][string]$orgUnitPath,
    [Parameter()][ValidateSet('BASIC','FULL')][string]$projection,
    [Parameter()][string]$query,
    [Parameter()][ValidateSet('ASCENDING','DESCENDING')][string]$sortOrder,
    [Parameter()][switch]$includeChildOrgunits,
    [Parameter()][switch]$all
  )
  # Ensure that they have a access token
  if(-not $global:googleAccessToken){
    throw "Please ensure that you have called Get-GoogleAccessToken cmdlet"
  }
  # Confirm we have a valid access token
  if(-not $(Test-GoogleAccessToken)){
    Get-GoogleAccessToken -json $global:googleJSON -customerId $global:googleCustomerId
  } 
  $endpoint = "admin/directory/v1/customer/$($global:googleCustomerId)/devices/chromeos" 
  $uriparts = [System.Collections.Generic.List[PSCustomObject]]@()
  if ($PSBoundParameters.ContainsKey("maxResults")) { $uriparts.add("maxResults=$($maxResults)") }
  if ($PSBoundParameters.ContainsKey("orderBy")) { $uriparts.add("orderBy=$($orderBy)") }
  if ($PSBoundParameters.ContainsKey("orgUnitPath")) { $uriparts.add("orgUnitPath=$($orgUnitPath)") }
  if ($PSBoundParameters.ContainsKey("projection")) { $uriparts.add("projection=$($projection)") }
  if ($PSBoundParameters.ContainsKey("sortOrder")) { $uriparts.add("sortOrder=$($sortOrder)") }
  if ($PSBoundParameters.ContainsKey("includeChildOrgunits")) { $uriparts.add("includeChildOrgunits=$($includeChildOrgunits)") }
  if ($PSBoundParameters.ContainsKey("query")) { $uriparts.add("query=$($query)") }
  # Generate the final API endppoint URI
  $endpoint = "$($endpoint)?$($uriparts -join "&")"   
  $data = [System.Collections.Generic.List[PSCustomObject]]@()
  $uri = $endpoint
    do{
    $result = Get-GoogleAPI -endpoint $uri -Verbose:$VerbosePreference
    foreach($item in $result.results.chromeosdevices){
      $data.add($item) | Out-Null
    }
    Write-Verbose "Returned $($result.Results.chromeosdevices.Count) results. Current result set is $($data.Count) items."     
    if($uriparts.count -eq 0){$uri = "$($endpoint)?"}
    else{$uri = "$($endpoint)&"}   
    $uri = "$($uri)pageToken=$($result.Results.nextPageToken)"
  }while($null -ne $result.results.nextPageToken -and $all)
  return $data
}
#EndRegion '.\Public\Get-ChromeDevices.ps1' 70
#Region '.\Public\Get-GoogleAccessToken.ps1' 0
function Get-GoogleAccessToken{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][SecureString]$private_key,
    [Parameter(Mandatory = $true)][string]$client_email,
    [Parameter(Mandatory = $true)][string]$customerId,
    [Parameter(Mandatory = $true)][string[]]$scopes
  )
  if($Global:googleAccessToken){
    if(Test-GoogleAccessToken){return}
  }
  # COvert Private Key to Byte Stream
  $rsaPrivateKey = [System.Text.Encoding]::UTF8.GetBytes($(ConvertFrom-SecureString -SecureString $private_key -AsPlainText))
  # Get Current Time
  $now = (Get-Date).ToUniversalTime()
  # Expiry Time
  $expiry = (Get-Date).ToUniversalTime().AddHours(1)
  # Convert to Format for JWT
  $createDate = [Math]::Floor([decimal](Get-Date($now) -UFormat "%s"))
  $expiryDate = [Math]::Floor([decimal](Get-Date($expiry) -UFormat "%s"))  
  # Create JWT Payload
  $jwtPayload = @{
    sub = $client_email
    scope = $($scopes -join " ")
    aud = "https://oauth2.googleapis.com/token"
    iat = $createDate
  }
  # Get JWT Payload
  $jwt = New-JWT -Algorithm 'RS256' -Issuer $client_email -SecretKey $rsaPrivateKey -ExpiryTimestamp $expiryDate -PayloadClaims $jwtPayload
  # Request Google API Token
  $tokenVars = @{
    Method = "POST"
    Uri =  "https://oauth2.googleapis.com/token"
    ContentType = "application/x-www-form-urlencoded"
    Body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=$jwt"
  }  
  $token = Invoke-WebRequest @tokenVars
  $global:googleAccessToken = ($token.content | ConvertFrom-JSON).access_token
  $global:googleCustomerId = $customerId
}
#EndRegion '.\Public\Get-GoogleAccessToken.ps1' 41
#Region '.\Public\Get-GoogleAPI.ps1' 0
function Get-GoogleAPI{
  [CmdletBinding()]
  [OutputType([System.Collections.Generic.List[PSCustomObject]])]
  param(
    [Parameter(Mandatory = $true)][string]$endpoint,
    [Parameter()][ValidateSet("Get", "Post", "Patch", "Delete", "Put")][string]$Method = "Get",
    [Parameter()][ValidateNotNullOrEmpty()]$body
  ) 
  $uri = "https://admin.googleapis.com/$($endpoint)" 
  try {
    $Vars = @{
      Method = $Method
      Uri = $uri
      StatusCodeVariable    = 'statusCode'
    }
    $headers = @{
      authorization = "Bearer $($Global:googleAccessToken)"
      "content-type" = "application/json"
    }
    if ($PSBoundParameters.ContainsKey("body")) { 
      $vars.add("body",($body | ConvertTo-JSON))
    }
    Write-Verbose "Calling API endpoint: $($uri)" 
    $results = Invoke-RestMethod @Vars -Headers $headers
  }
  catch {
    $ErrorMsg = $global:Error[0]
    return $ErrorMsg
  }
  return [PSCustomObject]@{
    StatusCode = $statusCode
    Results    = $results
  } 
}
#EndRegion '.\Public\Get-GoogleAPI.ps1' 35
#Region '.\Public\Get-GoogleOU.ps1' 0
function Get-GoogleOU{
  [CmdletBinding()]
  [OutputType([System.Collections.Generic.List[PSCustomObject]])]
  param(
    [Parameter()][ValidateSet('All','Children','All_Including_Parent')][string]$Type,
    [Parameter()][string]$orgUnitPath
  )
  # Ensure that they have a access token
  if(-not $global:googleAccessToken){
    throw "Please ensure that you have called Get-GoogleAccessToken cmdlet"
  }
  # Confirm we have a valid access token
  if(-not $(Test-GoogleAccessToken)){
    Get-GoogleAccessToken -json $global:googleJSON -customerId $global:googleCustomerId
  }
  $endpoint = "admin/directory/v1/customer/$($global:googleCustomerId)/orgunits"
  $uriparts = [System.Collections.Generic.List[PSCustomObject]]@()
  if ($PSBoundParameters.ContainsKey("type")) { $uriparts.add("type=$($type)") }
  if ($PSBoundParameters.ContainsKey("orgUnitPath")) { $uriparts.add("orgUnitPath=$($orgUnitPath)") }
  # Generate the final API endppoint URI
  $endpoint = "$($endpoint)?$($uriparts -join "&")"     
  $OrgList = Get-GoogleAPI -endpoint $endpoint -Verbose:$VerbosePreference
  return $orglist.results.organizationUnits
}
#EndRegion '.\Public\Get-GoogleOU.ps1' 25
#Region '.\Public\Test-GoogleAccessToken.ps1' 0
function Test-GoogleAccessToken{
  [CmdletBinding()]
  param()
  if(-not $global:googleAccessToken){
    throw "Please ensure that you have called Get-GoogleAccessToken cmdlet"
  }
  try{
    $endpoint = "https://oauth2.googleapis.com/tokeninfo?access_token=$($Global:googleAccessToken)"
    $tokenDetails = Invoke-RestMethod -Method "GET" -URI $endpoint -StatusCodeVariable statusCode
    if([int]$tokenDetails.expires_in -gt 900){
      Write-Verbose "Token is valid for more than 15 minutes, not getting new token."
      return $true
    }
    else{
      Write-Verbose "Token is valid for less than 15 minutes, getting new token."
      return $false
    }
  }
  catch{
    Write-Verbose "Unable to check token. Marking as needing refresh."
    return $false
  }  
}
#EndRegion '.\Public\Test-GoogleAccessToken.ps1' 24
