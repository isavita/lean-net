import LeanNet.HTTP1.Handlers

namespace LeanNet.HTTP

open HTTP1

/-- OWASP secure response headers added to application responses that do not
    already set them. Applications override a value by supplying the header
    themselves, or disable one by setting its field to `none`/`false`.
    Strict-Transport-Security is sent only on TLS connections (RFC 6797 §7.2
    forbids it over cleartext). Header names are lowercase so the same values
    are valid for HTTP/1 and HTTP/2. -/
structure SecurityHeaders where
  enabled : Bool := true
  strictTransportSecurity : Option String := some "max-age=31536000; includeSubDomains"
  contentTypeOptions : Bool := true
  frameOptions : Option String := some "SAMEORIGIN"
  contentSecurityPolicy : Option String :=
    some "default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'"
  referrerPolicy : Option String := some "strict-origin-when-cross-origin"
  deriving Repr, Inhabited

/-- The fields applicable to one transport, computed once per worker. -/
def SecurityHeaders.fields (config : SecurityHeaders) (secure : Bool) : Array Header := Id.run do
  if !config.enabled then return #[]
  let mut fields : Array Header := #[]
  if secure then
    if let some value := config.strictTransportSecurity then
      fields := fields.push { name := "strict-transport-security", value := value.toUTF8 }
  if config.contentTypeOptions then
    fields := fields.push { name := "x-content-type-options", value := "nosniff".toUTF8 }
  if let some value := config.frameOptions then
    fields := fields.push { name := "x-frame-options", value := value.toUTF8 }
  if let some value := config.contentSecurityPolicy then
    fields := fields.push { name := "content-security-policy", value := value.toUTF8 }
  if let some value := config.referrerPolicy then
    fields := fields.push { name := "referrer-policy", value := value.toUTF8 }
  return fields

/-- Append each default whose name the response does not already carry.
    Informational (1xx) responses are left unchanged. -/
def applySecurityHeaders (fields : Array Header) (response : Response) : Response := Id.run do
  if fields.isEmpty || response.status < 200 then return response
  let mut headers := response.headers
  for field in fields do
    unless response.headers.any (fun h => h.name.toLower == field.name) do
      headers := headers.push field
  return { response with headers }

/-- Wrap per-worker callbacks so every final application response, including
    head-stage rejections, carries the configured defaults. -/
def SecurityHeaders.wrap (config : SecurityHeaders) (secure : Bool) (handlers : Handlers) : Handlers :=
  let fields := config.fields secure
  if fields.isEmpty then handlers else
  { handlers with
    onRequest := fun request => do
      let reply ← handlers.onRequest request
      return { reply with response := applySecurityHeaders fields reply.response }
    onHeaders := fun head framing => do
      match ← handlers.onHeaders head framing with
      | .reject reply => return .reject { reply with response := applySecurityHeaders fields reply.response }
      | other => return other }

end LeanNet.HTTP
