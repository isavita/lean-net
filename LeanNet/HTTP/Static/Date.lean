import LeanNet.HTTP1.Date

namespace LeanNet.HTTP.Static

def formatHttpDate (seconds : Int) : ByteArray :=
  (HTTP1.formatDate (Std.Time.Timestamp.ofSecondsSinceUnixEpoch
    (Std.Time.Second.Offset.ofInt seconds))).toUTF8

private def months : Array String :=
  #["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

private def weekdays : Array String := #["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
private def fullWeekdays : Array String :=
  #["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

private def text (bytes : ByteArray) (start length : Nat) : String :=
  String.fromUTF8! (bytes.extract start (start + length))

private def number? (bytes : ByteArray) (start length : Nat) : Option Nat := do
  if start + length > bytes.size || length == 0 then none else
    let mut result := 0
    for index in [start:start + length] do
      let digit := bytes[index]!.toNat
      if digit < 48 || digit > 57 then failure
      result := result * 10 + digit - 48
    return result

private def leap (year : Nat) : Bool := year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)

private def daysInMonth (year month : Nat) : Nat :=
  if month == 2 then if leap year then 29 else 28
  else if [4, 6, 9, 11].contains month then 30 else 31

/-- Proleptic Gregorian civil date to Unix days. Inputs are validated first. -/
private def civilDays (year month day : Nat) : Int :=
  let year : Int := year - if month <= 2 then 1 else 0
  let era := year / 400
  let within := year - era * 400
  let shifted : Int := if month > 2 then month - 3 else month + 9
  let ordinal := (153 * shifted + 2) / 5 + day - 1
  era * 146097 + within * 365 + within / 4 - within / 100 + ordinal - 719468

private def stamp? (weekday year month day hour minute second : Nat) : Option Int := do
  if year == 0 || year > 9999 || month == 0 || month > 12 || day == 0 ||
      day > daysInMonth year month || hour > 23 || minute > 59 || second > 60 ||
      second == 60 && (hour != 23 || minute != 59) then failure
  let days := civilDays year month day
  if (days + 4) % 7 != Int.ofNat weekday then failure
  -- Even ticks represent ordinary Unix seconds. The odd tick after23:59:59
  -- keeps a leap second strictly before the next second without aliasing
  -- either adjacent Last-Modified timestamp.
  return (days * 86400 + hour * 3600 + minute * 60 + min second 59) * 2 +
    if second == 60 then 1 else 0

private def clock? (bytes : ByteArray) (start : Nat) : Option (Nat × Nat × Nat) := do
  if start + 8 > bytes.size || bytes[start + 2]! != 58 || bytes[start + 5]! != 58 then failure
  return (← number? bytes start 2, ← number? bytes (start + 3) 2, ← number? bytes (start + 6) 2)

private def lookup? (values : Array String) (value : String) : Option Nat :=
  (values.toList.zipIdx.find? (fun item => item.1 == value)).map (·.2)

private def imf? (bytes : ByteArray) : Option Int := do
  if bytes.size != 29 || text bytes 3 2 != ", " || text bytes 7 1 != " " ||
      text bytes 11 1 != " " || text bytes 16 1 != " " || text bytes 25 4 != " GMT" then failure
  let weekday ← lookup? weekdays (text bytes 0 3)
  let month ← lookup? months (text bytes 8 3)
  let (hour, minute, second) ← clock? bytes 17
  stamp? weekday (← number? bytes 12 4) (month + 1) (← number? bytes 5 2) hour minute second

private def rfc850? (bytes : ByteArray) (nowSeconds : Int) : Option Int := do
  let value ← String.fromUTF8? bytes
  let [weekdayText, rest] := value.splitOn ", " | none
  let weekday ← lookup? fullWeekdays weekdayText
  let bytes := rest.toUTF8
  if bytes.size != 22 || bytes[2]! != 45 || bytes[6]! != 45 || bytes[9]! != 32 ||
      text bytes 18 4 != " GMT" then failure
  let month ← lookup? months (text bytes 3 3)
  let shortYear ← number? bytes 7 2
  let day ← number? bytes 0 2
  let (hour, minute, second) ← clock? bytes 10
  let current := formatHttpDate nowSeconds
  let nowYear ← number? current 12 4
  let nowMonth ← lookup? months (text current 8 3)
  let nowDay ← number? current 5 2
  let (nowHour, nowMinute, nowSecond) ← clock? current 17
  let candidate := nowYear / 100 * 100 + shortYear
  let order := fun month day hour minute second : Nat =>
    month * 100000000 + day * 1000000 + hour * 10000 + minute * 100 + second
  let exceeds := candidate > nowYear + 50 || candidate == nowYear + 50 &&
    order month day hour minute second > order nowMonth nowDay nowHour nowMinute nowSecond
  let year := if exceeds then candidate - 100 else candidate
  stamp? weekday year (month + 1) day hour minute second

private def asctime? (bytes : ByteArray) : Option Int := do
  if bytes.size != 24 || bytes[3]! != 32 || bytes[7]! != 32 || bytes[10]! != 32 || bytes[19]! != 32 then failure
  let weekday ← lookup? weekdays (text bytes 0 3)
  let month ← lookup? months (text bytes 4 3)
  let day ← if bytes[8]! == 32 then number? bytes 9 1 else number? bytes 8 2
  let (hour, minute, second) ← clock? bytes 11
  stamp? weekday (← number? bytes 20 4) (month + 1) day hour minute second

/-- All three HTTP-date formats, with RFC850's two-digit year interpreted using
    an explicit clock input. Invalid or non-ASCII values have no validator. -/
def parseHttpDateTicks? (bytes : ByteArray) (nowSeconds : Int) : Option Int :=
  if !bytes.toList.all (fun byte => byte.toNat < 128) then none
  else (imf? bytes).orElse (fun _ => (rfc850? bytes nowSeconds).orElse (fun _ => asctime? bytes))

/-- Unix-second projection for callers needing a conventional epoch value.
    Conditional comparisons use parseHttpDateTicks? so a leap second cannot
    accidentally validate either neighboring file timestamp. -/
def parseHttpDate? (bytes : ByteArray) (nowSeconds : Int) : Option Int :=
  (parseHttpDateTicks? bytes nowSeconds).map (· / 2)

end LeanNet.HTTP.Static
