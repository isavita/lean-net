/- Public LeanNet API. Raw FFI declarations are implementation details. -/
import LeanNet.Bytes
import LeanNet.Socket.Handle
import LeanNet.TCP.Listener
import LeanNet.TCP.Connection
import LeanNet.Echo.Server
import LeanNet.HTTP1.Request
import LeanNet.HTTP1.Parser
import LeanNet.HTTP1.Date
import LeanNet.HTTP1.Response
import LeanNet.HTTP1.Protocol
import LeanNet.HTTP1.Encoding
import LeanNet.HTTP1.Streaming
import LeanNet.HTTP1.ClientResponse
import LeanNet.HTTP1.Config
import LeanNet.HTTP1.Router
import LeanNet.HTTP1.Machine
import LeanNet.HTTP1.Handlers
import LeanNet.HTTP1.Server
import LeanNet.HTTP.Transport
import LeanNet.HTTP.Admission
import LeanNet.HTTP.ReactorServer
import LeanNet.Gate
import LeanNet.Gateway.Transport
import LeanNet.Gateway.Resolve
import LeanNet.Gateway.Wire
import LeanNet.Gateway.Pool
import LeanNet.Gateway.Engine
import LeanNet.HTTP.SecureHeaders
import LeanNet.HTTP.Admin
import LeanNet.HTTP.TraceContext
import LeanNet.HTTP2.Preface
import LeanNet.HTTP2.Frame
import LeanNet.HTTP2.HPACK
import LeanNet.HTTP2.Request
import LeanNet.HTTP2.Stream
import LeanNet.HTTP2.Priority
import LeanNet.HTTP2.Push
import LeanNet.HTTP2.Machine
import LeanNet.HTTP2.Upgrade
import LeanNet.HTTP2.Connection
import LeanNet.HTTP2.Server
import LeanNet.WebSocket.Frame
import LeanNet.WebSocket.Connection
import LeanNet.WebSocket.Handshake
import LeanNet.WebSocket.Application
import LeanNet.WebSocket.Server
import LeanNet.HTTP.Static
import LeanNet.HTTP.Observability

import LeanNet.Socket.State
import LeanNet.Reactor.Basic
import LeanNet.Echo.ReactorServer

/-!
# lean-net

Import `LeanNet` for TCP, HTTP/1, HTTP/2, WebSocket, static-file and gateway APIs.
Start an HTTP server with
[`HTTP.ReactorServer.serveFactory`](LeanNet/HTTP/ReactorServer.html#LeanNet.HTTP.ReactorServer.serveFactory).
[`HTTP.ReactorServerConfig`](LeanNet/HTTP/ReactorServer.html#LeanNet.HTTP.ReactorServerConfig)
holds HTTP/1 settings in `machine` and HTTP/2 settings in `http2`; one listener
selects the protocol per client and uses the same application handlers.

See the [API overview](LeanNetDocs.html) and
[server configuration guide](https://github.com/isavita/lean-net/blob/main/docs/server.md).
-/
