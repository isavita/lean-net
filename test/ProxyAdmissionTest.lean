import LeanNet.Proxy.Admission

open LeanNet.Proxy

private def check (condition : Bool) (label : String) : IO Unit :=
  unless condition do throw (IO.userError label)

private def ok (result : Except ε α) (label : String) : IO α :=
  match result with
  | .ok value => pure value
  | .error _ => throw (IO.userError label)

private def rejected (expected : ProxyError) (result : Except ProxyError ValidatedRequest)
    (label : String) : IO Unit :=
  match result with
  | .error actual => check (actual == expected) label
  | .ok _ => throw (IO.userError label)

private def host (value : ByteArray) : Header :=
  { name := "host".toUTF8, value }

private def route (authority backend : String) : Route :=
  { authority := authority.toUTF8,
    backend := { address := backend.toUTF8, port := 8443, transport := .tls backend.toUTF8 },
    allowedMethods := #["GET".toUTF8, "POST".toUTF8],
    requiredHeaders := #["x-api-version".toUTF8], maxBodyBytes := 1024 }

private def baseHead : ParsedHead :=
  { protocol := .http1, method := "GET".toUTF8, target := "/v1/items".toUTF8,
    authority := "example.com".toUTF8,
    headers := #[host "example.com".toUTF8,
      { name := "x-api-version".toUTF8, value := "1".toUTF8 }] }

def main : IO Unit := do
  let policy ← ok (Policy.compile #[route "example.com" "backend-a.internal",
    route "other.com" "backend-b.internal"] {} 7) "valid routes rejected"
  let admitted ← ok (admit policy {} baseHead) "valid request rejected"
  check (admitted.policyGeneration == 7) "policy generation not retained"
  check (admitted.backend.address == "backend-a.internal".toUTF8) "wrong route selected"
  match admitted.checkBodySize 1024 with
  | .ok () => pure ()
  | .error _ => throw (IO.userError "body bound rejected")
  match admitted.checkBodySize 1025 with
  | .error .bodyTooLarge => pure ()
  | _ => throw (IO.userError "oversized body accepted")
  let mixedHeaders := #[host "EXAMPLE.COM".toUTF8,
    { name := "x-api-version".toUTF8, value := "1".toUTF8 }]
  let mixed := { baseHead with authority := "ExAmPlE.CoM".toUTF8, headers := mixedHeaders }
  let mixedRoute ← ok (admit policy {} mixed) "case-insensitive DNS rejected"
  check (mixedRoute.backend.address == "backend-a.internal".toUTF8) "case-fold route changed"
  let unknownHeaders := #[host "unknown.com".toUTF8,
    { name := "x-api-version".toUTF8, value := "1".toUTF8 }]
  rejected .unknownHost (admit policy {} { baseHead with authority := "unknown.com".toUTF8, headers := unknownHeaders })
    "unknown host accepted"
  rejected .badAuthority (admit policy {} { baseHead with headers := baseHead.headers.push (host "other.com".toUTF8) })
    "duplicate Host accepted"
  rejected .badAuthority (admit policy {} { baseHead with authority := "other.com".toUTF8 })
    "caller authority disagreed with Host"
  rejected .badAuthority (admit policy {} { baseHead with authority := "example.com.".toUTF8, headers := #[host "example.com.".toUTF8] })
    "trailing dot accepted"
  rejected .unknownHost (admit policy {} { baseHead with authority := "example.com:443".toUTF8, headers := #[host "example.com:443".toUTF8] })
    "unconfigured port accepted"
  rejected .badHeaders (admit policy {} { baseHead with headers := #[host "example.com".toUTF8,
    { name := "x-api-version".toUTF8, value := "1\r\nX-Injected: yes".toUTF8 }] })
    "CRLF header accepted"
  rejected .badHeaders (admit policy {} { baseHead with headers := #[host "example.com".toUTF8,
    { name := "x api version".toUTF8, value := "1".toUTF8 }] })
    "invalid header name accepted"
  rejected .tooManyHeaders (admit policy {} { baseHead with headers := Array.replicate 101 (host "example.com".toUTF8) })
    "header count not bounded"
  rejected .missingRequiredHeader (admit policy {} { baseHead with headers := #[host "example.com".toUTF8] })
    "required header absent"
  rejected .forbiddenMethod (admit policy {} { baseHead with method := "DELETE".toUTF8 })
    "forbidden method accepted"
  rejected .badTarget (admit policy {} { baseHead with target := "http://other.com/v1".toUTF8 })
    "absolute-form target accepted"
  rejected .badTarget (admit policy {} { baseHead with target := "/bad%0Z".toUTF8 })
    "bad percent escape accepted"
  rejected .misdirected (admit policy { secure := true } baseHead) "missing TLS SNI accepted"
  let secure : TransportFacts := { secure := true, sni := some "example.com".toUTF8 }
  let tls ← ok (admit policy secure baseHead)
    "matching TLS SNI rejected"
  check (tls.backend.address == "backend-a.internal".toUTF8) "TLS route changed"
  rejected .misdirected (admit policy { secure := true, sni := some "other.com".toUTF8 } baseHead)
    "mismatched SNI accepted"
  let h2Base := { baseHead with protocol := .http2, scheme := some "https".toUTF8 }
  let h2Headers := #[{ name := "x-api-version".toUTF8, value := "1".toUTF8 }]
  let h2 := { h2Base with headers := h2Headers }
  let h2Route ← ok (admit policy secure h2) "HTTP/2 authority rejected"
  check (h2Route.backend.address == "backend-a.internal".toUTF8) "HTTP/2 wrong route"
  rejected .badHeaders (admit policy secure { h2 with headers := #[
    { name := "x-api-version".toUTF8, value := " 1".toUTF8 }] })
    "HTTP/2 leading whitespace accepted"
  rejected .misdirected (admit policy secure { h2 with scheme := some "http".toUTF8 })
    "HTTP/2 scheme/transport mismatch accepted"
  rejected .badAuthority (admit policy secure { h2 with headers := #[host "other.com".toUTF8] })
    "HTTP/2 Host/:authority disagreement accepted"
  match Policy.compile #[route "example.com" "backend-a.internal",
      route "example.com" "backend-b.internal"] with
  | .error .duplicateAuthority => pure ()
  | _ => throw (IO.userError "duplicate configured authority accepted")
  let tight ← ok (Policy.compile #[route "example.com" "backend-a.internal"]
    { maxHeaderBytes := 20 }) "tight policy rejected"
  rejected .tooManyHeaders (admit tight {} baseHead) "header byte limit ignored"
  let badBackend : Backend := { address := "backend-a.internal".toUTF8, port := 443, transport := .tls "bad name".toUTF8 }
  match Policy.compile #[{ (route "example.com" "backend-a.internal") with backend := badBackend }] with
  | .error .invalidBackend => pure ()
  | _ => throw (IO.userError "invalid upstream TLS name accepted")
  check ((ProxyError.rateLimited 2).status == 429) "incorrect rate-limit response status"
