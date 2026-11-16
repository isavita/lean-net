namespace LeanNet

private opaque AtomicFlagType : NonemptyType

/-- A GC-owned, shared monotone flag. `new` allocates during setup. `isSet` and
`set` use a single lock-free native atomic load/store, without a mutex, spin
loop, task or callback. Supported targets require `ATOMIC_BOOL_LOCK_FREE = 2`.
The flag can only transition from false to true; dropping its final Lean
reference reclaims its native storage. -/
def AtomicFlag : Type := AtomicFlagType.type

instance : Nonempty AtomicFlag := AtomicFlagType.property

/-- Allocate an unset flag. Create outside request callbacks. -/
@[extern "lean_net_atomic_flag_new"]
opaque AtomicFlag.new : IO AtomicFlag

/-- One acquire load; observing true never regresses to false. -/
@[extern "lean_net_atomic_flag_is_set"]
opaque AtomicFlag.isSet (flag : @& AtomicFlag) : IO Bool

/-- One release store. Setting an already set flag is harmless. -/
@[extern "lean_net_atomic_flag_set"]
opaque AtomicFlag.set (flag : @& AtomicFlag) : IO Unit

end LeanNet
