namespace LeanNet.HTTP.Deferred

/-- Why an owner worker retired unfinished application work. -/
inductive CancelReason where
  | disconnected | streamReset | timeout | shutdown | overloaded | failed
  deriving BEq, Repr, Inhabited

end LeanNet.HTTP.Deferred
