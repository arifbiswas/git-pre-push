# GitSafty Windows Hello helper.
#
#   check                       -> "ok" if Windows Hello can be used
#   create <name>               -> creates a TPM-backed Hello key (prompts PIN/face/finger)
#   sign <name> <challengeB64>  -> prints base64 signature (prompts PIN/face/finger)
#
# The key is created by Windows Hello (KeyCredentialManager) and lives in the
# TPM: it can't be exported or copied to another PC, and every signature needs
# the person at the keyboard. GitSafty derives the vault secret from the
# signature of a fixed random challenge (RSA PKCS#1 v1.5 signatures are
# deterministic, so the same challenge always gives the same secret).

param(
  [Parameter(Mandatory = $true)][string]$Op,
  [string]$Name = 'GitSafty-Vault',
  [string]$Challenge = ''
)

$ErrorActionPreference = 'Stop'

try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime
  $null = [Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType = WindowsRuntime]
  $null = [Windows.Storage.Streams.IBuffer, Windows.Storage.Streams, ContentType = WindowsRuntime]
} catch {
  [Console]::Error.WriteLine('Windows Hello API not available on this system')
  exit 2
}

$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
} | Select-Object -First 1

function Await($operation, [Type]$resultType) {
  $task = $asTask.MakeGenericMethod($resultType).Invoke($null, @($operation))
  $null = $task.Wait(-1)
  return $task.Result
}

$KCM = [Windows.Security.Credentials.KeyCredentialManager]
$Status = [Windows.Security.Credentials.KeyCredentialStatus]

$supported = Await ($KCM::IsSupportedAsync()) ([bool])
if (-not $supported) {
  [Console]::Error.WriteLine('Windows Hello is not set up. Settings > Accounts > Sign-in options > PIN (Windows Hello)')
  exit 2
}

switch ($Op) {
  'check' {
    Write-Output 'ok'
    exit 0
  }
  'create' {
    $result = Await ($KCM::RequestCreateAsync($Name, [Windows.Security.Credentials.KeyCredentialCreationOption]::ReplaceExisting)) ([Windows.Security.Credentials.KeyCredentialRetrievalResult])
    if ($result.Status -ne $Status::Success) {
      [Console]::Error.WriteLine("Windows Hello refused: $($result.Status)")
      exit 3
    }
    Write-Output 'ok'
    exit 0
  }
  'sign' {
    $opened = Await ($KCM::OpenAsync($Name)) ([Windows.Security.Credentials.KeyCredentialRetrievalResult])
    if ($opened.Status -ne $Status::Success) {
      [Console]::Error.WriteLine("Hello key not found: $($opened.Status)")
      exit 4
    }
    $bytes = [Convert]::FromBase64String($Challenge)
    $buffer = [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer($bytes)
    $signed = Await ($opened.Credential.RequestSignAsync($buffer)) ([Windows.Security.Credentials.KeyCredentialOperationResult])
    if ($signed.Status -ne $Status::Success) {
      [Console]::Error.WriteLine("Windows Hello refused: $($signed.Status)")
      exit 3
    }
    $sig = [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::ToArray($signed.Result)
    Write-Output ([Convert]::ToBase64String($sig))
    exit 0
  }
  default {
    [Console]::Error.WriteLine("unknown op $Op")
    exit 1
  }
}
