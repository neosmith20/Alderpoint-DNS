param(
  [string]$Server = "172.16.43.100",
  [int]$Port = 53,
  [int]$Count = 10000,
  [string]$HotName = "example.com",
  [string]$LocalName = "localhost",
  [string]$BlockedName = "0--0.info",
  [int]$TimeoutMs = 2000
)

$ErrorActionPreference = "Stop"

function New-DnsQuery([string]$Name, [int]$Id) {
  $bytes = [System.Collections.Generic.List[byte]]::new()
  $bytes.Add([byte](($Id -shr 8) -band 255)); $bytes.Add([byte]($Id -band 255))
  $bytes.AddRange([byte[]](1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
  foreach ($label in $Name.TrimEnd(".").Split(".")) {
    if ($label.Length -gt 63) { throw "DNS label too long in $Name" }
    $lb = [Text.Encoding]::ASCII.GetBytes($label)
    $bytes.Add([byte]$lb.Length)
    $bytes.AddRange($lb)
  }
  $bytes.AddRange([byte[]](0, 0, 1, 0, 1))
  return $bytes.ToArray()
}

function Read-Exact([System.IO.Stream]$Stream, [int]$Length) {
  $buffer = [byte[]]::new($Length)
  $offset = 0
  while ($offset -lt $Length) {
    $read = $Stream.Read($buffer, $offset, $Length - $offset)
    if ($read -le 0) { throw "TCP stream closed while reading DNS response" }
    $offset += $read
  }
  return $buffer
}

function Decode-DnsResponse([byte[]]$Response, [int]$ExpectedId, [int]$ExpectedRcode, [bool]$RequireAnswer) {
  if ($Response.Length -lt 12) { return @{ Valid = $false; Reason = "malformed_short"; Rcode = $null } }
  $id = ($Response[0] -shl 8) + $Response[1]
  $flags = ($Response[2] -shl 8) + $Response[3]
  $rcode = $flags -band 15
  $qr = (($flags -band 0x8000) -ne 0)
  $truncated = (($flags -band 0x0200) -ne 0)
  $answers = ($Response[6] -shl 8) + $Response[7]
  if ($id -ne $ExpectedId) { return @{ Valid = $false; Reason = "transaction_id_mismatch"; Rcode = $rcode } }
  if (-not $qr) { return @{ Valid = $false; Reason = "not_a_response"; Rcode = $rcode } }
  if ($truncated) { return @{ Valid = $false; Reason = "truncated"; Rcode = $rcode } }
  if ($rcode -ne $ExpectedRcode) { return @{ Valid = $false; Reason = "unexpected_rcode_$rcode"; Rcode = $rcode } }
  if ($RequireAnswer -and $answers -lt 1) { return @{ Valid = $false; Reason = "no_answer"; Rcode = $rcode } }
  return @{ Valid = $true; Reason = "ok"; Rcode = $rcode }
}

function Percentile([System.Collections.Generic.List[double]]$Values, [double]$Pct) {
  if ($Values.Count -eq 0) { return $null }
  $arr = [double[]]$Values.ToArray()
  [Array]::Sort($arr)
  $idx = [Math]::Min($arr.Length - 1, [Math]::Max(0, [Math]::Ceiling($arr.Length * $Pct / 100.0) - 1))
  return [Math]::Round($arr[$idx], 3)
}

function Format-Ms($Value) {
  if ($null -eq $Value) { return "n/a" }
  return ("{0:N3}" -f $Value)
}

function New-Counters() {
  return @{
    Attempted = 0; Valid = 0; Invalid = 0; Timeouts = 0; Servfail = 0; OtherRcodes = 0
    Errors = 0; InvalidReasons = @{}
    Latencies = [System.Collections.Generic.List[double]]::new()
  }
}

function Add-Invalid($Counters, [string]$Reason, $Rcode) {
  $Counters["Invalid"]++
  if ($Reason -like "unexpected_rcode_*") {
    if ($Rcode -eq 2) { $Counters["Servfail"]++ } else { $Counters["OtherRcodes"]++ }
  }
  if (-not $Counters["InvalidReasons"].ContainsKey($Reason)) { $Counters["InvalidReasons"][$Reason] = 0 }
  $Counters["InvalidReasons"][$Reason]++
}

function Send-UdpQuery([System.Net.Sockets.UdpClient]$Udp, [byte[]]$Query, [int]$Id, [int]$ExpectedRcode, [bool]$RequireAnswer) {
  $remoteEndpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  [void]$Udp.Send($Query, $Query.Length)
  $response = $Udp.Receive([ref]$remoteEndpoint)
  $sw.Stop()
  if ($remoteEndpoint.Address.ToString() -ne $Server) {
    return @{ Valid = $false; Reason = "wrong_server"; Rcode = $null; Ms = $sw.Elapsed.TotalMilliseconds }
  }
  $decoded = Decode-DnsResponse $response $Id $ExpectedRcode $RequireAnswer
  $decoded["Ms"] = $sw.Elapsed.TotalMilliseconds
  return $decoded
}

function Connect-Tcp() {
  $tcp = [Net.Sockets.TcpClient]::new()
  $iar = $tcp.BeginConnect($Server, $Port, $null, $null)
  if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
    $tcp.Close()
    throw "TCP connect timeout"
  }
  $tcp.EndConnect($iar)
  $tcp.ReceiveTimeout = $TimeoutMs
  $tcp.SendTimeout = $TimeoutMs
  return $tcp
}

function Send-TcpQuery([System.IO.Stream]$Stream, [byte[]]$Query, [int]$Id, [int]$ExpectedRcode, [bool]$RequireAnswer) {
  $length = [byte[]]((($Query.Length -shr 8) -band 255), ($Query.Length -band 255))
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $Stream.Write($length, 0, 2)
  $Stream.Write($Query, 0, $Query.Length)
  $header = Read-Exact $Stream 2
  $size = ($header[0] -shl 8) + $header[1]
  if ($size -lt 12) { throw "invalid TCP DNS response length $size" }
  $response = Read-Exact $Stream $size
  $sw.Stop()
  $decoded = Decode-DnsResponse $response $Id $ExpectedRcode $RequireAnswer
  $decoded["Ms"] = $sw.Elapsed.TotalMilliseconds
  return $decoded
}

function Run-UdpTest([string]$Label, [string]$Name, [int]$ExpectedRcode, [bool]$RequireAnswer, [double]$TargetP99) {
  Write-Host "Running $Label ($Count UDP queries to $Server`:$Port)..."
  $udp = [Net.Sockets.UdpClient]::new()
  $udp.Client.ReceiveTimeout = $TimeoutMs
  $udp.Connect($Server, $Port)
  $c = New-Counters
  $testSw = [Diagnostics.Stopwatch]::StartNew()
  try {
    for ($i = 1; $i -le $Count; $i++) {
      $c["Attempted"]++
      $id = Get-Random -Minimum 1 -Maximum 65535
      $query = New-DnsQuery $Name $id
      try {
        $res = Send-UdpQuery $udp $query $id $ExpectedRcode $RequireAnswer
        if ($res["Valid"]) { $c["Valid"]++; $c["Latencies"].Add([double]$res["Ms"]) } else { Add-Invalid $c $res["Reason"] $res["Rcode"] }
      } catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) { $c["Timeouts"]++ } else { $c["Errors"]++ }
      } catch {
        $c["Errors"]++
      }
      if (($i % 1000) -eq 0) { Write-Host "  $Label progress: $i / $Count" }
    }
  } finally {
    $udp.Close()
  }
  $testSw.Stop()
  return Summarize $Label $c $testSw.Elapsed.TotalSeconds $TargetP99
}

function Run-TcpEstablishedTest([string]$Label, [string]$Name, [int]$ExpectedRcode, [bool]$RequireAnswer, [double]$TargetP99) {
  Write-Host "Running $Label ($Count queries over one established persistent TCP connection to $Server`:$Port)..."
  $c = New-Counters
  $testSw = [Diagnostics.Stopwatch]::StartNew()
  $tcp = $null
  try {
    $tcp = Connect-Tcp
    $stream = $tcp.GetStream()
    for ($i = 1; $i -le $Count; $i++) {
      $c["Attempted"]++
      $id = Get-Random -Minimum 1 -Maximum 65535
      $query = New-DnsQuery $Name $id
      try {
        $res = Send-TcpQuery $stream $query $id $ExpectedRcode $RequireAnswer
        if ($res["Valid"]) { $c["Valid"]++; $c["Latencies"].Add([double]$res["Ms"]) } else { Add-Invalid $c $res["Reason"] $res["Rcode"]; $tcp.Close(); $tcp = Connect-Tcp; $stream = $tcp.GetStream() }
      } catch [System.IO.IOException] {
        $c["Timeouts"]++; if ($tcp) { $tcp.Close() }; $tcp = Connect-Tcp; $stream = $tcp.GetStream()
      } catch {
        $c["Errors"]++; if ($tcp) { $tcp.Close() }; $tcp = Connect-Tcp; $stream = $tcp.GetStream()
      }
      if (($i % 1000) -eq 0) { Write-Host "  $Label progress: $i / $Count" }
    }
  } finally {
    if ($tcp) { $tcp.Close() }
  }
  $testSw.Stop()
  return Summarize "$Label (established persistent TCP connection)" $c $testSw.Elapsed.TotalSeconds $TargetP99
}

function Summarize([string]$Label, $Counters, [double]$Seconds, [double]$TargetP99) {
  $p50 = Percentile $Counters["Latencies"] 50
  $p95 = Percentile $Counters["Latencies"] 95
  $p99 = Percentile $Counters["Latencies"] 99
  $max = if ($Counters["Latencies"].Count -gt 0) { Percentile $Counters["Latencies"] 100 } else { $null }
  $qps = if ($Seconds -gt 0) { [Math]::Round($Counters["Valid"] / $Seconds, 1) } else { 0 }
  $pass = ($Counters["Valid"] -ge $Count -and $p99 -ne $null -and $p99 -lt $TargetP99 -and $Counters["Timeouts"] -eq 0 -and $Counters["Invalid"] -eq 0 -and $Counters["Errors"] -eq 0)
  return [pscustomobject]@{
    Test = $Label
    Attempted = $Counters["Attempted"]
    Valid = $Counters["Valid"]
    Invalid = $Counters["Invalid"]
    Timeouts = $Counters["Timeouts"]
    Servfail = $Counters["Servfail"]
    OtherRcodes = $Counters["OtherRcodes"]
    Errors = $Counters["Errors"]
    P50Ms = Format-Ms $p50
    P95Ms = Format-Ms $p95
    P99Ms = Format-Ms $p99
    MaxMs = Format-Ms $max
    DurationSeconds = [Math]::Round($Seconds, 3)
    Qps = $qps
    Target = "p99 < $TargetP99 ms"
    Pass = $pass
  }
}

function Preflight([string]$Label, [string]$Name, [int]$ExpectedRcode, [bool]$RequireAnswer) {
  Write-Host "Preflight: $Label -> $Name"
  $udp = [Net.Sockets.UdpClient]::new()
  $udp.Client.ReceiveTimeout = $TimeoutMs
  $udp.Connect($Server, $Port)
  try {
    $id = Get-Random -Minimum 1 -Maximum 65535
    $res = Send-UdpQuery $udp (New-DnsQuery $Name $id) $id $ExpectedRcode $RequireAnswer
    if (-not $res["Valid"]) { throw "$Label failed preflight: $($res["Reason"])" }
    Write-Host "  ok: rcode=$ExpectedRcode answerRequired=$RequireAnswer"
  } finally {
    $udp.Close()
  }
}

Write-Host "Alderpoint DNS LAN benchmark"
Write-Host "Target: $Server`:$Port"
Write-Host "Default tests produce $($Count * 4) total DNS queries. Warmup/preflight queries are excluded from percentiles."

Preflight "HotName" $HotName 0 $true
Preflight "LocalName" $LocalName 0 $true
Preflight "BlockedName" $BlockedName 3 $false

Write-Host "Warming hot cache..."
for ($i = 0; $i -lt 200; $i++) {
  $udp = [Net.Sockets.UdpClient]::new()
  $udp.Client.ReceiveTimeout = $TimeoutMs
  $udp.Connect($Server, $Port)
  try {
    $id = Get-Random -Minimum 1 -Maximum 65535
    [void](Send-UdpQuery $udp (New-DnsQuery $HotName $id) $id 0 $true)
  } finally {
    $udp.Close()
  }
}

$results = @()
$results += Run-UdpTest "UDP hot-cache" $HotName 0 $true 10
$results += Run-TcpEstablishedTest "TCP hot-cache" $HotName 0 $true 10
$results += Run-UdpTest "Local DNS UDP" $LocalName 0 $true 5
$results += Run-UdpTest "Blocked response UDP" $BlockedName 3 $false 5

Write-Host ""
Write-Host "Copy/paste summary:"
$results | Format-Table -AutoSize | Out-String | Write-Host
