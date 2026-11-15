import LeanNet.HTTP.CLI

open LeanNet.HTTP

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def parse (args : List String) : IO CLI.Options :=
  match CLI.parse args with
  | .ok options => pure options
  | .error message => throw (IO.userError message)

private def rejected (args : List String) : IO Unit :=
  match CLI.parse args with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"accepted invalid CLI options: {args}")

def main : IO Unit := do
  let plain ← parse []
  check plain.accessLogQueueCapacity.isNone "omitted capacity was marked explicit"
  check (← plain.httpConfig).accessLog.isNone "queue default enabled logging"
  let base := ["--access-log", "access.jsonl", "--log-helper", "helper"]
  let defaultConfig ← (← parse base).httpConfig
  let some access := defaultConfig.accessLog | throw (IO.userError "missing default access configuration")
  check (access.queueCapacity == 1024) "default queue capacity changed"
  for capacity in [1, 2, 1024, 4096, 65536] do
    let options ← parse (base ++ ["--access-log-queue-capacity", toString capacity])
    check (options.accessLogQueueCapacity == some capacity) "explicit capacity was not retained"
    let config ← options.httpConfig
    let some access := config.accessLog | throw (IO.userError "missing configured access log")
    check (access.queueCapacity == capacity && access.path.toString == "access.jsonl" &&
      access.helperBinary.toString == "helper") "queue capacity or existing access fields were not propagated"
  let before ← parse ["--access-log-queue-capacity", "4096", "--access-log", "access.jsonl"]
  check (before.accessLogQueueCapacity == some 4096) "capacity incorrectly depends on option order"
  rejected ["--access-log-queue-capacity"]
  rejected ["--access-log-queue-capacity", "4096"]
  rejected (base ++ ["--access-log-queue-capacity", "1024", "--access-log-queue-capacity", "4096"])
  for value in ["0", "3", "1023", "65537", "-1", "1.5", "abc", ""] do
    rejected (base ++ ["--access-log-queue-capacity", value])
  let upstream ← parse ["--gate", "gateway.gate", "--upstream-ca", "roots.pem"]
  check (upstream.upstreamCA.map (·.toString) == some "roots.pem") "upstream CA path lost"
  rejected ["--upstream-ca", "roots.pem"]
  rejected ["--gate", "gateway.gate", "--upstream-ca"]
  rejected ["--gate", "gateway.gate", "--upstream-ca", "roots.pem", "--upstream-ca", "other.pem"]
  IO.println "HTTP CLI defaults, upstream CA, bounds and rejection cases passed"
