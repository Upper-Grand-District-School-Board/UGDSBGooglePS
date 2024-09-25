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