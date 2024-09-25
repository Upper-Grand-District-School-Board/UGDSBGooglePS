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