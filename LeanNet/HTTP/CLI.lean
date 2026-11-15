import LeanNet.HTTP.Static
import LeanNet.HTTP2.Server
import LeanNet.Gate

namespace LeanNet.HTTP.CLI

structure Options where
  enablePush : Bool := false
  staticRoot : Option System.FilePath := none
  staticMemoryMiB : Nat := 8
  metrics : Bool := false
  accessLog : Option System.FilePath := none
  accessLogQueueCapacity : Option Nat := none
  logHelper : Option System.FilePath := none
  reloadCertsMs : Option Nat := none
  pingIntervalMs : Option Nat := none
  pingTimeoutMs : Option Nat := none
  workers : Nat := 0
  maxClients : Nat := 32
  /-- Per-peer-IP completed TCP accepts: tokens/period-ms/burst. -/
  connectionRate : Option Reactor.AcceptRateConfig := none
  positional : List String := []
  /-- Listening address; the default stays loopback-only for safety. -/
  host : Option String := none
  securityHeaders : Bool := true
  health : Bool := false
  adminPort : Option Nat := none
  pinWorkers : Bool := false
  websocketOrigin : Option String := none
  /-- TLS only: PEM CA bundle used to verify client certificates (mTLS). -/
  clientCA : Option System.FilePath := none
  /-- TLS executable only: PEM CA roots for outbound HTTPS backends. -/
  upstreamCA : Option System.FilePath := none
  requireClientCert : Bool := false
  /-- TLS only: DER OCSP response stapled for the default certificate. -/
  ocspResponse : Option System.FilePath := none
  /-- Gate policy file (see docs/gateway.md); reloaded on SIGHUP. -/
  gateFile : Option System.FilePath := none
  private memoryExplicit : Bool := false

private def collect (args : List String) (options : Options) : Except String Options :=
  match args with
  | [] => .ok { options with positional := options.positional.reverse }
  | "--" :: rest => .ok { options with positional := options.positional.reverse ++ rest }
  | "--enable-push" :: rest => collect rest { options with enablePush := true }
  | "--no-security-headers" :: rest => collect rest { options with securityHeaders := false }
  | "--health" :: rest => collect rest { options with health := true }
  | "--pin-workers" :: rest => collect rest { options with pinWorkers := true }
  | "--require-client-cert" :: rest => collect rest { options with requireClientCert := true }
  | "--websocket-origin" :: value :: rest =>
    if options.websocketOrigin.isSome then .error "--websocket-origin may be supplied once"
    else if value.isEmpty || value.startsWith "--" || value.any (fun c => c == '\x00' || c == '\r' || c == '\n') then
      .error "--websocket-origin requires one exact Origin"
    else collect rest { options with websocketOrigin := some value }
  | "--websocket-origin" :: [] => .error "--websocket-origin requires one exact Origin"
  | "--host" :: address :: rest =>
    if options.host.isSome then .error "--host may be supplied once"
    else if address.isEmpty || address.startsWith "--" || address.any (· == '\x00') then .error "--host requires an address"
    else collect rest { options with host := some address }
  | "--host" :: [] => .error "--host requires an address"
  | "--admin-port" :: value :: rest =>
    if options.adminPort.isSome then .error "--admin-port may be supplied once"
    else match value.toNat? with
      | some port =>
        if port == 0 || port > 65535 then .error "--admin-port must be between 1 and 65535"
        else collect rest { options with adminPort := some port }
      | none => .error "--admin-port requires a decimal port"
  | "--admin-port" :: [] => .error "--admin-port requires a port"
  | "--client-ca" :: path :: rest =>
    if options.clientCA.isSome then .error "--client-ca may be supplied once"
    else if path.isEmpty || path.startsWith "--" then .error "--client-ca requires a PEM file"
    else collect rest { options with clientCA := some (System.FilePath.mk path) }
  | "--client-ca" :: [] => .error "--client-ca requires a PEM file"
  | "--upstream-ca" :: path :: rest =>
    if options.upstreamCA.isSome then .error "--upstream-ca may be supplied once"
    else if path.isEmpty || path.startsWith "--" || path.any (· == '\x00') then
      .error "--upstream-ca requires a PEM file"
    else collect rest { options with upstreamCA := some (System.FilePath.mk path) }
  | "--upstream-ca" :: [] => .error "--upstream-ca requires a PEM file"
  | "--ocsp-response" :: path :: rest =>
    if options.ocspResponse.isSome then .error "--ocsp-response may be supplied once"
    else if path.isEmpty || path.startsWith "--" then .error "--ocsp-response requires a DER file"
    else collect rest { options with ocspResponse := some (System.FilePath.mk path) }
  | "--ocsp-response" :: [] => .error "--ocsp-response requires a DER file"
  | "--gate" :: path :: rest =>
    if options.gateFile.isSome then .error "--gate may be supplied once"
    else if path.isEmpty || path.startsWith "--" then .error "--gate requires a policy file"
    else collect rest { options with gateFile := some (System.FilePath.mk path) }
  | "--gate" :: [] => .error "--gate requires a policy file"
  | "--metrics" :: rest => collect rest { options with metrics := true }
  | "--http2-ping-ms" :: interval :: rest =>
    if options.pingIntervalMs.isSome then .error "--http2-ping-ms may be supplied once"
    else match interval.toNat? with
      | some value =>
        if value == 0 || value > 3600000 then .error "--http2-ping-ms must be between 1 and 3600000"
        else collect rest { options with pingIntervalMs := some value }
      | none => .error "--http2-ping-ms requires a decimal millisecond interval"
  | "--http2-ping-ms" :: [] => .error "--http2-ping-ms requires a millisecond interval"
  | "--http2-ping-timeout-ms" :: interval :: rest =>
    if options.pingTimeoutMs.isSome then .error "--http2-ping-timeout-ms may be supplied once"
    else match interval.toNat? with
      | some value =>
        if value == 0 || value > 3600000 then .error "--http2-ping-timeout-ms must be between 1 and 3600000"
        else collect rest { options with pingTimeoutMs := some value }
      | none => .error "--http2-ping-timeout-ms requires a decimal millisecond interval"
  | "--http2-ping-timeout-ms" :: [] => .error "--http2-ping-timeout-ms requires a millisecond interval"
  | "--workers" :: count :: rest =>
    match count.toNat? with
    | some value =>
      if value > 256 then .error "--workers must be between 0 (automatic) and 256"
      else collect rest { options with workers := value }
    | none => .error "--workers requires a decimal count"
  | "--workers" :: [] => .error "--workers requires a count"
  | "--max-clients" :: count :: rest =>
    match count.toNat? with
    | some value =>
      if value == 0 || value > 1000000 then .error "--max-clients must be between 1 and 1000000"
      else collect rest { options with maxClients := value }
    | none => .error "--max-clients requires a decimal count"
  | "--max-clients" :: [] => .error "--max-clients requires a count"
  | "--connection-rate" :: value :: rest =>
    if options.connectionRate.isSome then .error "--connection-rate may be supplied once"
    else match value.splitOn "/" with
      | [rawTokens, rawPeriod, rawBurst] =>
        match rawTokens.toNat?, rawPeriod.toNat?, rawBurst.toNat? with
        | some tokens, some periodMs, some burst =>
          if tokens == 0 || tokens > 4294967295 || periodMs == 0 ||
              periodMs > 4294967295 || burst == 0 || burst > 4294967295 then
            .error "--connection-rate values must be between 1 and 4294967295"
          else collect rest { options with connectionRate := some { tokens, periodMs, burst } }
        | _, _, _ => .error "--connection-rate requires TOKENS/PERIOD_MS/BURST"
      | _ => .error "--connection-rate requires TOKENS/PERIOD_MS/BURST"
  | "--connection-rate" :: [] => .error "--connection-rate requires TOKENS/PERIOD_MS/BURST"
  | "--access-log" :: path :: rest =>
    if options.accessLog.isSome then .error "--access-log may be supplied once"
    else if path.isEmpty || path.startsWith "--" then .error "--access-log requires a path"
    else collect rest { options with accessLog := some (System.FilePath.mk path) }
  | "--access-log" :: [] => .error "--access-log requires a path"
  | "--access-log-queue-capacity" :: count :: rest =>
    if options.accessLogQueueCapacity.isSome then .error "--access-log-queue-capacity may be supplied once"
    else match count.toNat? with
      | some value =>
        if value == 0 || value > 65536 || value &&& (value - 1) != 0 then
          .error "--access-log-queue-capacity must be a power of two between 1 and 65536"
        else collect rest { options with accessLogQueueCapacity := some value }
      | none => .error "--access-log-queue-capacity requires a decimal record count"
  | "--access-log-queue-capacity" :: [] => .error "--access-log-queue-capacity requires a record count"
  | "--log-helper" :: path :: rest =>
    if options.logHelper.isSome then .error "--log-helper may be supplied once"
    else if path.isEmpty || path.startsWith "--" then .error "--log-helper requires an executable path"
    else collect rest { options with logHelper := some (System.FilePath.mk path) }
  | "--log-helper" :: [] => .error "--log-helper requires an executable path"
  | "--reload-certs-ms" :: interval :: rest =>
    if options.reloadCertsMs.isSome then .error "--reload-certs-ms may be supplied once"
    else match interval.toNat? with
      | some value =>
        if value == 0 || value > 3600000 then .error "--reload-certs-ms must be between 1 and 3600000"
        else collect rest { options with reloadCertsMs := some value }
      | none => .error "--reload-certs-ms requires a decimal millisecond interval"
  | "--reload-certs-ms" :: [] => .error "--reload-certs-ms requires a millisecond interval"
  | "--static" :: directory :: rest =>
    if options.staticRoot.isSome then .error "--static may be supplied once"
    else if directory.isEmpty || directory.startsWith "--" then .error "--static requires a directory"
    else collect rest { options with staticRoot := some (System.FilePath.mk directory) }
  | "--static" :: [] => .error "--static requires a directory"
  | "--static-memory" :: amount :: rest =>
    match amount.toNat? with
    | some value =>
      if value == 0 || value > 1024 then .error "--static-memory must be between 1 and 1024 MiB"
      else collect rest { options with staticMemoryMiB := value, memoryExplicit := true }
    | none => .error "--static-memory requires a decimal MiB budget"
  | "--static-memory" :: [] => .error "--static-memory requires a MiB budget"
  | arg :: rest =>
    if arg.startsWith "--" then .error s!"unknown option: {arg}"
    else collect rest { options with positional := arg :: options.positional }

def parse (args : List String) : Except String Options := do
  let options ← collect args {}
  if options.memoryExplicit && options.staticRoot.isNone then
    throw "--static-memory requires --static"
  if options.logHelper.isSome && options.accessLog.isNone then
    throw "--log-helper requires --access-log"
  if options.accessLogQueueCapacity.isSome && options.accessLog.isNone then
    throw "--access-log-queue-capacity requires --access-log"
  if options.pingTimeoutMs.isSome && options.pingIntervalMs.isNone then
    throw "--http2-ping-timeout-ms requires --http2-ping-ms"
  if options.requireClientCert && options.clientCA.isNone then
    throw "--require-client-cert requires --client-ca"
  if options.upstreamCA.isSome && options.gateFile.isNone then
    throw "--upstream-ca requires --gate"
  return options

/-- Listening address chosen by `--host`, else the caller's default. -/
def Options.listenHost (options : Options) (fallback : String := "127.0.0.1") : String :=
  options.host.getD fallback

def port (argument : Option String) (fallback : UInt16) : Except String UInt16 := do
  let some text := argument | return fallback
  let some value := text.toNat? | throw "port must be a decimal number"
  if value == 0 || value > 65535 then throw "port must be between 1 and 65535"
  return value.toUInt16

/-- CLI policy lives in the library; the executable only validates positional
    arguments and enters this bracketed server. -/
def Options.httpConfig (options : Options) : IO ReactorServerConfig := do
  let accessLog ← match options.accessLog with
    | none => pure none
    | some path => do
      let helper ← match options.logHelper with
        | some value => pure value
        | none => do
          let executable ← IO.appPath
          let directory := executable.parent.getD (System.FilePath.mk ".")
          pure (directory / (if System.Platform.isWindows then "lean-net-access-log-helper.exe" else "lean-net-access-log-helper"))
      pure (some {
        path, helperBinary := helper,
        queueCapacity := options.accessLogQueueCapacity.getD 1024 : Observability.AccessConfig })
  return {
    workers := options.workers
    server := { maxClients := options.maxClients }
    connectionRate := options.connectionRate
    http2 := {
      enablePush := options.enablePush
      enableConnectProtocol := options.websocketOrigin.isSome
      pingIntervalMs := options.pingIntervalMs.getD 0
      pingTimeoutMs := options.pingTimeoutMs.getD 10000 }
    metricsPath := if options.metrics then some "/metrics".toUTF8 else none
    accessLog
    securityHeaders := { enabled := options.securityHeaders }
    healthPaths := options.health
    adminPort := options.adminPort.map (·.toUInt16)
    pinWorkers := options.pinWorkers
    websocketOrigin := options.websocketOrigin.map (·.toUTF8) }

/-- Install the `--gate` policy, if any: validated at startup (a bad file
    stops the server), reloaded on SIGHUP, with its counters on `/metrics`.
    CLI policies can route to the server's own handlers (`app`), `deny`,
    `redirect` and `websocket`; named handlers need a library program. -/
def Options.withGate (options : Options) (http : ReactorServerConfig)
    (use : ReactorServerConfig → IO Unit) : IO Unit := do
  let some path := options.gateFile | use http
  let text ← IO.FS.readFile path
  let spec ← match Gate.Spec.parse text with
    | .ok spec => pure spec
    | .error error => throw (IO.userError (toString error))
  let workers ← workerCount http.workers http.server.maxClients
  Gate.withLive { spec } workers fun live => do
    let previous := http.onReload
    let metrics := http.extraMetrics
    use { http with
      admission := some live.factory
      gateway := some {}
      onReload := do previous; live.reloadFile path
      extraMetrics := do return (← metrics) ++ (← live.metrics) }

def Options.serve (options : Options) (host : String := "127.0.0.1")
    (port : UInt16 := 8080) : IO Unit := do
  if options.reloadCertsMs.isSome then throw (IO.userError "--reload-certs-ms requires the TLS server")
  if options.clientCA.isSome || options.ocspResponse.isSome || options.upstreamCA.isSome then
    throw (IO.userError "--client-ca, --require-client-cert, --upstream-ca and --ocsp-response require the TLS server")
  let http ← options.httpConfig
  options.withGate http fun http => do
  if let some root := options.staticRoot then
    let bytes := options.staticMemoryMiB * 1024 * 1024
    Static.serveRoot root
      { builder := { maxFileBytes := bytes, maxPackBytes := bytes }, residentBytes := bytes }
      http host port
  else HTTP2.serveWithOptions http host port

end LeanNet.HTTP.CLI
