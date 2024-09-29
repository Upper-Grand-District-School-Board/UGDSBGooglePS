function Get-GoogleUser {
  [CmdletBinding()]
  [OutputType([System.Collections.Generic.List[PSCustomObject]])]
  param(
    [Parameter(Mandatory, ParameterSetName = 'userKey')][string]$userKey,
    [Parameter(ParameterSetName = 'userlist')][string]$domain,
    [Parameter(ParameterSetName = 'userlist')][ValidateSet('ADD', 'DELETE', 'MAKE_ADMIN', 'UNDELETE', 'UPDATE')][string]$userevent,
    [Parameter(ParameterSetName = 'userlist')][ValidateRange(1, 300)][int]$maxResults = 100,
    [Parameter(ParameterSetName = 'userlist')][ValidateSet('EMAIL', 'FAMILY_NAME', 'GIVEN_NAME')][string]$orderBy,
    [Parameter(ParameterSetName = 'userlist')][string]$query,
    [Parameter(ParameterSetName = 'userlist')][bool]$showDeleted,
    [Parameter(ParameterSetName = 'userlist')][ValidateSet('ASCENDING', 'DESCENDING')][string]$sortOrder,
    [Parameter()][string]$customFieldMask,
    [Parameter()][ValidateSet('BASIC', 'CUSTOM', 'FULL')][string]$projection,
    [Parameter()][ValidateSet('admin_view', 'domain_public')][string]$viewType,
    [Parameter()][switch]$all
  )
  # Ensure that they have a access token
  if(-not $global:googleAccessToken){
    throw "Please ensure that you have called Get-GoogleAccessToken cmdlet"
  }
  # Confirm we have a valid access token
  if(-not $(Test-GoogleAccessToken)){
    Get-GoogleAccessToken -private_key $global:googlePK -client_email $global:googleClientEmail -customerid  $global:googleCustomerId -scopes $global:googleScopes
  }  
  $uriparts = [System.Collections.Generic.List[PSCustomObject]]@()  
  if ($PSBoundParameters.ContainsKey("userKey")) { 
    $endpoint = "admin/directory/v1/users/$($userKey)"
  }
  else {
    $endpoint = "admin/directory/v1/users"
    $uriparts.add("customer=$($global:googleCustomerId)")
  }
  if ($PSBoundParameters.ContainsKey("domain")) { $uriparts.add("domain=$($domain)") }
  if ($PSBoundParameters.ContainsKey("userevent")) { $uriparts.add("event=$($userevent)") }
  if ($PSBoundParameters.ContainsKey("maxResults")) { $uriparts.add("maxResults=$($maxResults)") }
  if ($PSBoundParameters.ContainsKey("orderBy")) { $uriparts.add("orderBy=$($orderBy)") }
  if ($PSBoundParameters.ContainsKey("query")) { $uriparts.add("query=$($query)") }
  if ($PSBoundParameters.ContainsKey("showDeleted")) { $uriparts.add("showDeleted=$($showDeleted)") }
  if ($PSBoundParameters.ContainsKey("sortOrder")) { $uriparts.add("sortOrder=$($sortOrder)") }
  if ($PSBoundParameters.ContainsKey("customFieldMask")) { $uriparts.add("customFieldMask=$($customFieldMask)") }
  if ($PSBoundParameters.ContainsKey("projection")) { $uriparts.add("projection=$($projection)") }
  if ($PSBoundParameters.ContainsKey("viewType")) { $uriparts.add("viewType=$($viewType)") }
  # Generate the final API endppoint URI
  $endpoint = "$($endpoint)?$($uriparts -join "&")"  
  $data = [System.Collections.Generic.List[PSCustomObject]]@()
  $uri = $endpoint
  do {

    $result = Get-GoogleAPI -endpoint $uri -Verbose:$VerbosePreference
    if ($null -ne $result.results.users) {
      $process = $result.results.users
    }
    else {
      $process = $result.results
    }
    foreach ($item in $process) {
      $data.add($item) | Out-Null
    }
    Write-Verbose "Returned $($process.Count) results. Current result set is $($data.Count) items."     
    if ($uriparts.count -eq 0) { $uri = "$($endpoint)?" }
    else { $uri = "$($endpoint)&" }   
    $uri = "$($uri)pageToken=$($result.Results.nextPageToken)"
  }while ($null -ne $result.results.nextPageToken -and $all)
  return $data
}