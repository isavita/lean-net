import Std.Data.HashMap
import LeanNet.Gateway.Transport
import LeanNetTLS.Gateway

/-! Reactor adapter for the optional upstream TLS engine. The socket is
    claimed before a session is handed to the core gateway. All ciphertext
    writes use the claimed Wire, and plaintext aliases cannot write to it. -/

namespace LeanNetTLS.GatewayProvider

open LeanNet

private def makeSession (reactor : Reactor.Reactor) (context : Gateway.Context)
    (registry : IO.Ref (Std.HashMap Reactor.SocketId LeanNet.Gateway.TLSSession))
    (socket : Reactor.Socket .connected) (verifyName : ByteArray) : IO LeanNet.Gateway.TLSSession := do
  let some name := String.fromUTF8? verifyName
    | throw (IO.userError "upstream TLS verification name is not UTF-8")
  let tls ← context.openSession name
  let claimed ← try socket.claim catch error => do
    tls.close
    throw error
  let id := claimed.id
  let handshaking ← IO.mkRef (some claimed)
  let ready ← IO.mkRef (none : Option (Reactor.Wire .tls_ready))
  let verified ← IO.mkRef false
  let alive ← IO.mkRef true
  let ensure := do
    unless ← alive.get do throw (IO.userError "upstream TLS adapter is closed")
  let close := do
    if ← alive.get then
      alive.set false
      let current ← ready.get
      let pending ← handshaking.get
      if let some wire := current then
        try wire.close (by decide) catch _ => pure ()
      else if let some wire := pending then
        try wire.close (by decide) catch _ => pure ()
      tls.close
      registry.modify (·.erase id)
  let result : LeanNet.Gateway.TLSSession := {
    id
    handshake := do
      ensure
      match ← tls.handshake with
      | .ready => verified.set true; return true
      | .pending => return false
    feedCipher := fun bytes => do ensure; tls.feedCipher bytes
    drainCipher := do ensure; tls.drainCipher
    submitCipher := fun bytes => do
      ensure
      if bytes.isEmpty || bytes.size > 65536 then
        throw (IO.userError "upstream TLS ciphertext slice is out of range")
      let some buffer ← reactor.tryAcquire bytes.size.toUInt32 | return .wouldBlock
      try
        buffer.copyFrom bytes
        if let some wire ← ready.get then
          wire.tryWrite buffer 0 bytes.size.toUInt32
        else if let some wire ← handshaking.get then
          wire.tryWrite buffer 0 bytes.size.toUInt32
        else throw (IO.userError "upstream TLS wire is unavailable")
      finally buffer.release
    setReadEnabled := fun enabled => do
      ensure
      if let some wire ← ready.get then wire.setReadEnabled enabled
      else if let some wire ← handshaking.get then wire.setReadEnabled enabled
      else throw (IO.userError "upstream TLS wire is unavailable")
    armTimer := fun kind deadline => do
      ensure
      if let some wire ← ready.get then wire.armTimer kind deadline
      else if let some wire ← handshaking.get then wire.armTimer kind deadline
      else throw (IO.userError "upstream TLS wire is unavailable")
    cancelTimer := fun kind => do
      ensure
      if let some wire ← ready.get then wire.cancelTimer kind
      else if let some wire ← handshaking.get then wire.cancelTimer kind
      else throw (IO.userError "upstream TLS wire is unavailable")
    markWireReady := do
      ensure
      unless ← verified.get do throw (IO.userError "upstream TLS peer is not verified")
      if (← tls.pendingCipherBytes) != 0 then
        throw (IO.userError "upstream TLS handshake ciphertext is not drained")
      if (← ready.get).isSome then throw (IO.userError "upstream TLS wire is already ready")
      let some wire ← handshaking.get
        | throw (IO.userError "upstream TLS handshaking wire is unavailable")
      let readyWire ← wire.ready
      handshaking.set none
      ready.set (some readyWire)
    writePlain := fun bytes => do
      ensure
      unless (← ready.get).isSome do throw (IO.userError "upstream TLS wire is not ready")
      tls.writePlain bytes
    readPlain := do
      ensure
      unless (← ready.get).isSome do throw (IO.userError "upstream TLS wire is not ready")
      match ← tls.readPlain with
      | .pending => return .pending
      | .eof => return .eof
      | .data bytes => return .data bytes
    cleanForReuse := do
      ensure
      if !(← ready.get).isSome then return false
      tls.cleanForReuse
    close
  }
  registry.modify (·.insert id result)
  return result

/-- Create one upstream TLS provider on each owner worker. `caFile = none`
    uses OpenSSL's configured trust store; supply a PEM CA bundle for private
    backends. `TLSProvider.close` closes all sessions before freeing roots. -/
def new (reactor : Reactor.Reactor) (caFile : Option String := none) :
    IO LeanNet.Gateway.TLSProvider := do
  let context ← Gateway.Context.open caFile
  let registry ← IO.mkRef ({} : Std.HashMap Reactor.SocketId LeanNet.Gateway.TLSSession)
  let alive ← IO.mkRef true
  return {
    start := fun socket verifyName => do
      unless ← alive.get do throw (IO.userError "upstream TLS provider is closed")
      makeSession reactor context registry socket verifyName
    close := do
      if ← alive.get then
        alive.set false
        let mut failure : Option IO.Error := none
        for (_, session) in (← registry.get).toList do
          try session.close catch error => if failure.isNone then failure := some error
        try context.close catch error => if failure.isNone then failure := some error
        if let some error := failure then throw error
  }

def withProvider (reactor : Reactor.Reactor) (caFile : Option String)
    (use : LeanNet.Gateway.TLSProvider → IO α) : IO α := do
  let provider ← new reactor caFile
  try use provider finally provider.close

end LeanNetTLS.GatewayProvider
