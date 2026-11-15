import LeanNet.HTTP.Transport
import LeanNet.HTTP1.Encoding

/-! Server-level request admission hook.

`ReactorServerConfig.admission` is `none` by default: the core server then
behaves exactly as before, paying one `Option` branch per request. When set,
the hook decides every request head on its owning worker *before* any body
intake, `100 Continue`, h2c upgrade, WebSocket or tunnel selection, metrics or
health endpoint, or application callback. HTTP/2 streams are paused at their
validated head until the decision (see `HTTP2.Connection.Config.headGate`).

`LeanNet.Gate` implements this hook from a declarative policy; applications
can also supply their own. -/

namespace LeanNet.HTTP.Admission

inductive Protocol where
  | http10 | http11 | http2
  deriving BEq, Repr, Inhabited

/-- What the head will turn into if accepted. -/
inductive Kind where
  /-- An ordinary request. -/
  | request
  /-- HTTP/1.1 `Upgrade` (h2c, WebSocket or an application raw pipe). -/
  | upgrade
  /-- HTTP/2 extended CONNECT (RFC 8441). -/
  | tunnel
  /-- A server-owned endpoint (metrics or health); no application handler. -/
  | internal
  deriving BEq, Repr, Inhabited

/-- Protocol-neutral view of a head the core parser already validated
    (framing, header syntax, size limits, unique Host / `:authority`). -/
structure Head where
  protocol : Protocol
  method : String
  target : ByteArray
  /-- HTTP/1 `Host` or HTTP/2 `:authority` (agreeing `host` already checked). -/
  authority : ByteArray
  /-- HTTP/2 `:scheme`; `none` for HTTP/1. -/
  scheme : Option ByteArray := none
  headers : Array HTTP1.Header
  /-- Declared body length, when framed by Content-Length. -/
  contentLength : Option Nat := none
  /-- True when no body can follow this head. -/
  bodyless : Bool := false
  kind : Kind := .request
  deriving Inhabited

/-- A typed refusal. HTTP/1 sends `body` and closes the connection (unread body
    bytes are never reinterpreted); HTTP/2 sends a bodyless final response on
    that stream only and stops its upload with RST_STREAM(NO_ERROR). Header
    names are lowercase; values must not echo untrusted request bytes. -/
structure Rejection where
  status : Nat
  headers : Array HTTP1.Header := #[]
  body : ByteArray := ByteArray.empty
  /-- Close without any response (HTTP/1) or refuse the stream (HTTP/2),
      e.g. for unknown hosts probed by scanners. -/
  drop : Bool := false
  /-- Fixed reason label for access logs (never request bytes). -/
  label : String := ""
  deriving Inhabited

def Rejection.reply (rejection : Rejection) : HTTP1.Reply :=
  let headers := if rejection.body.isEmpty then rejection.headers
    else rejection.headers.push { name := "content-type", value := "text/plain; charset=utf-8".toUTF8 }
  { response := { status := rejection.status, headers, body := rejection.body },
    options := { forceClose := true } }

/-- `dispatch`, when present, replaces `Handlers.onRequest` for this request;
    it typically closes over the admitted, policy-bound request. `rewrite`
    (e.g. stripping headers) is applied before whichever handler runs. -/
inductive Verdict where
  | accept (bodyLimit : Option Nat := none) (dispatch : Option (HTTP1.Request → IO HTTP1.Reply) := none)
      (rewrite : Option (HTTP1.Request → HTTP1.Request) := none)
      -- label: matched route pattern for access logs (configuration only).
      (label : Option String := none)
  | reject (rejection : Rejection)

/-- Runs synchronously on the worker; must not block. Exceptions are treated
    as a 500 rejection by the server. -/
structure Hook where
  decide : Transport.Facts → Head → IO Verdict

/-- Builds a hook on each worker's own thread (argument: worker index), so
    per-worker state such as a compiled policy or rate-limit leases is never
    shared across cores (shared Lean objects use atomic reference counts). -/
abbrev Factory := Nat → IO Hook

def Factory.shared (hook : Hook) : Factory := fun _ => pure hook

end LeanNet.HTTP.Admission
