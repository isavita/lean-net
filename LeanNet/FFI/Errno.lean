import LeanNet.FFI.Raw

namespace LeanNet.Errno

/-- Interpret the two's-complement bit pattern returned by the C shim. -/
def decode (value : UInt64) : Int :=
  let n := value.toNat
  if n < 9223372036854775808 then Int.ofNat n
  else Int.ofNat n - 18446744073709551616

/-- Test a negative syscall result against the platform's EINTR value. -/
def isInterrupted (result : Int) : IO Bool := do
  return result == -(Int.ofNat (← FFI.errnoEintr).toNat)

/-- Test a negative syscall result against both native would-block values. -/
def isWouldBlock (result : Int) : IO Bool := do
  let a ← FFI.errnoEagain
  let b ← FFI.errnoEwouldblock
  return result == -(Int.ofNat a.toNat) || result == -(Int.ofNat b.toNat)

/-- Include the native error number in exceptions without losing address errors. -/
def error (operation : String) (result : Int) : IO IO.Error := do
  if (operation == "listen" || operation == "reactor listen" || operation == "reactor bind") && result ≤ -90000 then
    let code := -result - 100000
    return IO.userError s!"{operation}: getaddrinfo error {code}"
  else if result < 0 then
    let number := (-result).toNat
    let description ← FFI.rawErrnoName (Int32.ofInt (Int.ofNat number))
    let badFd ← FFI.errnoEbadf
    let bug := if number == badFd.toNat && operation == "close" then " (library bug)" else ""
    let details := s!"{operation}: {description} (errno {number}){bug}"
    if operation == "recv" || operation == "send" then
      let peerErrors ← [FFI.errnoEpipe, FFI.errnoEconnreset, FFI.errnoEconnaborted,
        FFI.errnoEtimedout, FFI.errnoEnetreset, FFI.errnoEnetdown,
        FFI.errnoEnetunreach, FFI.errnoEhostunreach, FFI.errnoEconnrefused,
        FFI.errnoEnotconn].mapM id
      if peerErrors.any (fun code => code.toNat == number) then
        return .resourceVanished (UInt32.ofNat number) details
    return IO.userError details
  else
    return IO.userError s!"{operation}: unexpected result {result}"

end LeanNet.Errno
