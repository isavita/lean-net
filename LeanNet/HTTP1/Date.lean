import Std.Time

namespace LeanNet.HTTP1

open Std.Time

private def httpDateFormat : GenericFormat .any := datespec("EEE, dd MMM uuuu HH:mm:ss 'GMT'")

/-- RFC 9110 IMF-fixdate, rendered in UTC using English weekday/month names. -/
def formatDate (timestamp : Std.Time.Timestamp) : String :=
  let date := Std.Time.DateTime.ofTimestamp timestamp Std.Time.TimeZone.ZoneRules.UTC
  httpDateFormat.format date

/-- Current UTC Date field as ASCII wire bytes. -/
def currentDate : IO ByteArray := do
  return (formatDate (← Std.Time.Timestamp.now)).toUTF8

end LeanNet.HTTP1
