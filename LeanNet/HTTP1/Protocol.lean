import LeanNet.HTTP1.Request

namespace LeanNet.HTTP1

/-- The two HTTP/1 versions supported on the wire. Request metadata retains its
    existing String field for compatibility with HTTP/2 application requests. -/
inductive Version where
  | http10 | http11
  deriving BEq, DecidableEq, Repr, Inhabited

def Version.wire : Version → String
  | .http10 => "HTTP/1.0"
  | .http11 => "HTTP/1.1"

def Version.parse? : String → Option Version
  | "HTTP/1.0" => some .http10
  | "HTTP/1.1" => some .http11
  | _ => none

/-- Message framing, independent of whether the application consumes content.
    `none` is a bodyless message, not an unframed ordinary response. -/
inductive BodyFraming where
  | none
  | contentLength (length : Nat)
  | chunked
  | closeDelimited
  deriving BEq, DecidableEq, Repr, Inhabited

inductive KeepAliveAction where
  | keepAlive | close
  deriving BEq, DecidableEq, Repr, Inhabited

private def tokenByte (b : UInt8) : Bool :=
  let n := b.toNat
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122) ||
    [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains n

private def ows (b : UInt8) : Bool := b == 32 || b == 9

private def splitCommas (bytes : List UInt8) : List (List UInt8) := go bytes [] []
where
  go (remaining current : List UInt8) (out : List (List UInt8)) : List (List UInt8) :=
    match remaining with
    | [] => (current.reverse :: out).reverse
    | 44 :: rest => go rest [] (current.reverse :: out)
    | b :: rest => go rest (b :: current) out

/-- Parse all Connection fields into lowercase ASCII options. Invalid or empty
    list members are rejected; `connAction` conservatively closes on failure. -/
def connectionTokens (headers : Array Header) : Except String (Array String) := do
  let mut result := #[]
  for header in headers do
    if header.name.toLower == "connection" then
      for item in splitCommas header.value.toList do
        let token := ((item.dropWhile ows).reverse.dropWhile ows).reverse
        if token.isEmpty || !token.all tokenByte then throw "invalid Connection option"
        let some text := String.fromUTF8? (ByteArray.mk token.toArray)
          | throw "invalid Connection option"
        result := result.push text.toLower
  return result

/-- Framing, routing, authentication and content-processing fields cannot be
    supplied after the body. Callers also reject Connection-nominated fields.
    Parsed names are lowercase ASCII; mixed-case application names are folded. -/
def forbiddenTrailerName (name : String) : Bool :=
  ["content-length", "transfer-encoding", "host", "trailer", "connection",
   "te", "upgrade", "keep-alive", "proxy-connection", "content-encoding", "content-type",
   "content-range", "authorization", "proxy-authorization", "proxy-authenticate",
   "www-authenticate", "cookie", "set-cookie", "expect"].contains name.toLower

/-- Connection persistence after a final response. Informational responses and
    accepted upgrades have separate state transitions. Close always wins; a
    legacy HTTP/1.0 persistent response must have explicit length framing. -/
def connAction (version : Version) (requestHeaders : Array Header)
    (responseFraming : BodyFraming) : KeepAliveAction :=
  match connectionTokens requestHeaders with
  | .error _ => .close
  | .ok tokens =>
    if responseFraming == .closeDelimited || tokens.contains "close" then .close
    else match version with
      | .http11 => .keepAlive
      | .http10 =>
        match responseFraming with
        | .contentLength _ => if tokens.contains "keep-alive" then .keepAlive else .close
        | _ => .close

end LeanNet.HTTP1
