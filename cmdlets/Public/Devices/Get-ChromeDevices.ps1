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
    Get-GoogleAccessToken -private_key $global:googlePK -client_email $global:googleClientEmail -customerid  $global:googleCustomerId -scopes $global:googleScopes
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