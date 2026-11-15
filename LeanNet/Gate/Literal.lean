import Lean
import LeanNet.Gate.Policy

/-! `gate% "…"`: a policy literal checked while the program is compiled.

The elaborator parses the text and runs `Policy.compile` at build time, so a
syntax error, unknown backend or rate limit, invalid host or CIDR, or an
overlapping route fails the build. Names supplied by the application
(`app NAME`, `check NAME`, the forwarder and limiter) are verified at startup
by `Gate.factory`. The result is an ordinary `Spec`, identical to one parsed
from a runtime file, so both forms share one code path. -/

namespace LeanNet.Gate

open Lean Elab Term

/-- Runtime parse used by `gate%`; the literal was already validated. -/
def Spec.parseChecked (text : String) : Spec :=
  match Spec.parse text with
  | .ok spec => spec
  | .error _ => default

syntax (name := gateLiteral) "gate% " str : term

@[term_elab gateLiteral] def elabGateLiteral : TermElab := fun stx _ => do
  let some text := stx[1].isStrLit? | throwUnsupportedSyntax
  match Spec.parse text with
  | .error error => throwErrorAt stx[1] (toString error)
  | .ok spec =>
    match Policy.compile spec with
    | .error error => throwErrorAt stx[1] (toString error)
    | .ok _ => elabTerm (← `(LeanNet.Gate.Spec.parseChecked $(quote text))) (some (mkConst ``Spec))

end LeanNet.Gate
