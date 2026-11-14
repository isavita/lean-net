import LeanNet.HTTP2.Preface
open LeanNet.HTTP2

private def check (ok : Bool) (message : String) : IO Unit := do
  unless ok do throw (IO.userError message)

def main : IO Unit := do
  let preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toUTF8
  let tail := ByteArray.mk #[0, 1, 2, 255]
  let wire := preface.append tail
  for i in [:preface.size + 1] do
    let first := PrefaceDetector.new.feed (wire.extract 0 i)
    match first with
    | .needMore detector =>
      match detector.feed (wire.extract i wire.size) with
      | .http2 rest => check (rest == tail) "HTTP/2 remainder changed"
      | _ => throw (IO.userError "HTTP/2 preface was not recognized")
    | .http2 rest => check (rest.append (wire.extract i wire.size) == tail) "HTTP/2 remainder changed"
    | .http1 _ => throw (IO.userError "HTTP/2 preface was misclassified")
  let ordinary := "POST / HTTP/1.1\r\nHost: localhost\r\n\r\n".toUTF8
  for i in [:ordinary.size + 1] do
    let first := PrefaceDetector.new.feed (ordinary.extract 0 i)
    match first with
    | .needMore detector =>
      match detector.feed (ordinary.extract i ordinary.size) with
      | .http1 bytes => check (bytes == ordinary) "HTTP/1 bytes changed"
      | _ => throw (IO.userError "HTTP/1 request was misclassified")
    | .http1 bytes => check (bytes.append (ordinary.extract i ordinary.size) == ordinary) "HTTP/1 bytes changed"
    | .http2 _ => throw (IO.userError "HTTP/1 request was misclassified")
  IO.println "HTTP/2 preface tests passed"
