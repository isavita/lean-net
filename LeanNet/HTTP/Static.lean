import LeanNet.HTTP.Static.Catalog
import LeanNet.HTTP.ReactorServer

namespace LeanNet.HTTP.Static

/-- Prepare immutable representations before listening, then bind one file
    capability and independent handlers on each protocol worker. -/
def serveRoot (root : System.FilePath) (catalogConfig : Catalog.Config := {})
    (http : ReactorServerConfig := {}) (host : String := "127.0.0.1")
    (port : UInt16 := 8080) : IO Unit :=
  Catalog.withCatalog root catalogConfig fun catalog =>
    ReactorServer.serveWorkerFactory
      (fun _ _ reactor use => do
        let bound ← catalog.bind reactor
        use Transport.plain (← bound.handlers)) http host port

end LeanNet.HTTP.Static
