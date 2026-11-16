namespace LeanNet.HTTP1

/-- Header names are validated ASCII tokens and normalized to lowercase.
    Header values remain wire bytes (with surrounding optional whitespace removed). -/
structure Header where
  name : String
  value : ByteArray
  deriving Inhabited

/-- Validated request metadata available as soon as its headers are complete. -/
structure RequestHead where
  method : String
  version : String := "HTTP/1.1"
  target : ByteArray
  headers : Array Header

/-- A client certificate that the TLS layer verified against the configured
    client CA (mTLS). Subject is a complete RFC 2253 DN; SANs are separate,
    exact typed entries such as `DNS:example.com`, `URI:spiffe://...`,
    `email:a@b` or `IP:10.0.0.1`. Malformed or oversized identity metadata
    fails the connection before reaching a handler. -/
structure ClientCertificate where
  subject : String
  subjectAltNames : Array String := #[]
  deriving Repr, Inhabited, BEq

/-- Owned socket-free facts established by the transport, never parsed from
Forwarded/X-Forwarded-* or any other request header. Plain connections have no
SNI/ALPN. The binary peer IP has 4 or 16 bytes, or is empty when unknown. -/
structure TransportInfo where
  secure : Bool
  peer : ByteArray
  sni : Option ByteArray := none
  alpn : ByteArray := ByteArray.empty
  deriving Inhabited

/-- The request target and body remain uninterpreted wire bytes. -/
structure Request where
  method : String
  version : String := "HTTP/1.1"
  target : ByteArray
  headers : Array Header
  body : ByteArray
  trailers : Array Header := #[]
  /-- Set by the server for TLS connections with a verified client certificate. -/
  clientCertificate : Option ClientCertificate := none
  /-- Populated by ReactorServer from the accepted socket/TLS handshake. -/
  transport : Option TransportInfo := none

/-- Limits apply independently to the request head, decoded body, and trailers. -/
structure Limits where
  maxHeaderBytes : Nat := 16384
  maxHeaderCount : Nat := 100
  maxBodyBytes : Nat := 1048576
  maxTrailerBytes : Nat := 16384
  maxTrailerCount : Nat := 100
  maxBodyWireBytes : Nat := 2097152
  maxChunkLineBytes : Nat := 1024
  deriving Repr

end LeanNet.HTTP1
