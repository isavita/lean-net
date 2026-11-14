import LeanNet.Echo.ReactorServer

namespace LeanNet.Echo

/-- Run the native-reactor echo server until SIGINT, one dedicated loop per core. -/
def serve (host : String := "127.0.0.1") (port : UInt16 := 8080) (workers : Nat := 0) : IO Unit :=
  ReactorServer.serve host port workers

end LeanNet.Echo
