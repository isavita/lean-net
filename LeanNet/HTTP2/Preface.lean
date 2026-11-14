namespace LeanNet.HTTP2

/-- Classify prior-knowledge HTTP/2 without consuming HTTP/1 bytes. -/
structure PrefaceDetector where
  private matched : ByteArray := ByteArray.empty

inductive PrefaceResult where
  | needMore (detector : PrefaceDetector)
  | http1 (wire : ByteArray)
  | http2 (remaining : ByteArray)

private def preface : ByteArray := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8

def PrefaceDetector.new : PrefaceDetector := {}

/-- Retains at most the preface length while the protocol is undecided. -/
def PrefaceDetector.feed (detector : PrefaceDetector) (input : ByteArray) : PrefaceResult := Id.run do
  let mut matched := detector.matched
  for i in [:input.size] do
    let b := input[i]!
    if b != preface[matched.size]! then
      return .http1 (matched.append (input.extract i input.size))
    matched := matched.push b
    if matched.size == preface.size then
      return .http2 (input.extract (i + 1) input.size)
  return .needMore { matched }

end LeanNet.HTTP2
