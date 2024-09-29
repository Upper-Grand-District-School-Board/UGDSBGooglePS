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
    Get-GoogleAccessToken -private_key $global:googlePK -client_email $global:googleClientEmail -customerid  $global:googleCustomerId -scopes $global:googleScopes
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