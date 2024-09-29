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
  $global:googleClientEmail = $googleClientEmail
  $global:googlePK = $private_key
  $global:googleScopes = $scopes
}