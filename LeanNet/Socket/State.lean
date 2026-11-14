namespace LeanNet

/-- Lifecycle states are phantom indices; proofs do not enter the wire/runtime ABI. -/
inductive SocketState where
  | fresh | bound | listening | connected | tls_handshaking | tls_ready | closed
  deriving DecidableEq, BEq, Repr

end LeanNet
