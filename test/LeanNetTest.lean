import LeanNet.Socket.Handle

open LeanNet

-- The C ABI returns signed Int64 values as their UInt64 bit patterns.
#guard Errno.decode (0 : UInt64) == 0
#guard Errno.decode (42 : UInt64) == 42
#guard Errno.decode (9223372036854775807 : UInt64) == 9223372036854775807
#guard Errno.decode (9223372036854775808 : UInt64) == -9223372036854775808
#guard Errno.decode (18446744073709551615 : UInt64) == -1
#guard Errno.decode (18446744073709451618 : UInt64) == -99998

-- Listener and connection handles cannot be interchanged or fabricated by
-- library clients.  These tests succeed only when the invalid terms fail.
example (_listener : Listener) : True := by
  fail_if_success exact (show Connection from _listener)
  trivial

example : True := by
  fail_if_success exact (Socket.mk 0 : Listener)
  trivial
