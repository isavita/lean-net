import LeanNet.HTTP1.Response

namespace LeanNet.HTTP2

/-- An optional cacheable GET response promised on the parent's origin. The
    connection validates the target and headers, and the peer can disable push. -/
structure Push where
  target : ByteArray
  response : HTTP1.Response
  headers : Array HTTP1.Header := #[]

end LeanNet.HTTP2
