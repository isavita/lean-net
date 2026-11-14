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

/-- The request target and body remain uninterpreted wire bytes. -/
structure Request where
  method : String
  version : String := "HTTP/1.1"
  target : ByteArray
  headers : Array Header
  body : ByteArray
  trailers : Array Header := #[]

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
