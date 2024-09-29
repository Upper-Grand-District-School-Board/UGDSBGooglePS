function Enable-GoogleUser {
  [CmdletBinding()]
  [OutputType([System.Collections.Generic.List[PSCustomObject]])]
  param(
    [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$userKey
  )
  # Ensure that they have a access token
  if(-not $global:googleAccessToken){
    throw "Please ensure that you have called Get-GoogleAccessToken cmdlet"
  }
  # Confirm we have a valid access token
  if(-not $(Test-GoogleAccessToken)){
    Get-GoogleAccessToken -private_key $global:googlePK -client_email $global:googleClientEmail -customerid  $global:googleCustomerId -scopes $global:googleScopes
  }
  $endpoint = "admin/directory/v1/users/$($userKey)"
  $body = @{
    suspended = $false
  }
  $results = Get-GoogleAPI -endpoint $endpoint -method Put -Body $Body -Verbose:$VerbosePreference
  return $results.results
}