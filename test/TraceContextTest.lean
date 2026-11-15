import LeanNet.HTTP.TraceContext

open LeanNet.HTTP

private def check (condition : Bool) (label : String) : IO Unit :=
  unless condition do throw (IO.userError s!"trace context: {label}")

def main : IO Unit := do
  let valid := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".toUTF8
  let some context := TraceContext.parse valid | throw (IO.userError "valid traceparent rejected")
  check (TraceContext.hex context.traceId == "4bf92f3577b34da6a3ce929d0e0e4736".toUTF8) "trace id"
  check (TraceContext.hex context.parentId == "00f067aa0ba902b7".toUTF8 && context.flags == 1) "parent id and flags"
  check (context.format == valid) "round trip"
  for invalid in ["00-00000000000000000000000000000000-00f067aa0ba902b7-01",
      "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
      "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
      "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
      "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"] do
    check (TraceContext.parse invalid.toUTF8).isNone s!"accepted {invalid}"
  -- Future versions may append fields.
  check (TraceContext.parse "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-future".toUTF8).isSome "future version"
  let generator ← TraceContext.Generator.seeded
  let (kept, headers, generator) := TraceContext.ensure #[{ name := "traceparent", value := valid }] generator
  check (kept.traceId == context.traceId && headers.size == 1) "valid context retained"
  let (fresh, headers, generator) := TraceContext.ensure #[{ name := "traceparent", value := "garbage".toUTF8 }] generator
  check (headers.size == 1 && headers[0]!.value == fresh.format) "invalid context replaced"
  check ((TraceContext.parse headers[0]!.value).isSome) "generated context is valid"
  let (other, _, _) := TraceContext.ensure #[] generator
  check (other.traceId != fresh.traceId && other.traceId.size == 16 && other.parentId.size == 8) "unique ids"
  IO.println "W3C trace context tests passed"
