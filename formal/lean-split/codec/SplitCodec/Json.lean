import Lean.Data.Json

/-!
# Strict JSON codec shared by the split-line oracles

Every capability oracle of `formal/lean-split` decodes its requests with these
helpers, so the unproved part of the oracles exists once (formal plugin,
practice 63). The decoder accepts one form of each value and refuses the rest:

* a line is at most 8 MiB;
* numbers are integers: a fraction or an exponent is refused before the parse;
* an integer is a JSON integer or a canonical decimal string (`0`, or digits
  with no leading zero, with an optional `-` for `Int`); `"05"` and `"1_000"`
  are refused; values of 2^63 and above are written as strings;
* every object has exactly its keys: an unknown, a missing or a duplicate key
  is refused (the duplicate scan reads the raw text, because the Lean parser
  keeps the last of two duplicate keys);
* enumerations are JSON strings spelled as the spec spells them.

A decode error is an `Except.error`. The default mode exits 2 on it and
`--step` answers `{"error": TEXT}`. A decoded value outside a spec's domain is
not a decode error: the capability's `Spec` refuses it with a code.
-/

namespace SplitCodec

open Lean

def maxLine : Nat := 8 * 1024 * 1024

/-- Refuse a fraction or an exponent in any number outside a string. -/
def integerNumbersOnly (t : String) : Except String Unit := Id.run do
  let mut inStr := false
  let mut esc := false
  let mut inNum := false
  for c in t.toList do
    if inStr then
      if esc then esc := false
      else if c == '\\' then esc := true
      else if c == '"' then inStr := false
    else if c == '"' then inStr := true; inNum := false
    else if c.isDigit || c == '-' then inNum := true
    else if inNum && (c == '.' || c == 'e' || c == 'E' || c == '+') then
      return .error "numbers must be integers (no fraction or exponent)"
    else inNum := false
  return .ok ()

/-- Refuse a duplicate key in any object of the raw text. -/
def noDupKeys (t : String) : Except String Unit := Id.run do
  let mut stack : List (Option (List String)) := []
  let mut inStr := false
  let mut esc := false
  let mut cur : String := ""
  let mut lastStr : Option String := none
  for c in t.toList do
    if inStr then
      if esc then esc := false; cur := cur.push c
      else if c == '\\' then esc := true; cur := cur.push c
      else if c == '"' then inStr := false; lastStr := some cur
      else cur := cur.push c
    else if c == '"' then inStr := true; cur := ""
    else if c == '{' then stack := some [] :: stack; lastStr := none
    else if c == '[' then stack := none :: stack; lastStr := none
    else if c == '}' || c == ']' then stack := stack.drop 1; lastStr := none
    else if c == ':' then
      match stack, lastStr with
      | some ks :: rest, some k =>
        if ks.contains k then return .error s!"duplicate key {k}"
        stack := some (k :: ks) :: rest
      | _, _ => pure ()
      lastStr := none
    else if c == ',' then lastStr := none
  return .ok ()

def parseLine (t : String) : Except String Json := do
  if t.utf8ByteSize > maxLine then throw s!"line longer than {maxLine} bytes"
  integerNumbersOnly t
  noDupKeys t
  Json.parse t

def canonicalNat (t : String) : Bool :=
  !t.isEmpty && t.all Char.isDigit && (t == "0" || !t.startsWith "0")

def canonicalInt (t : String) : Bool :=
  if t.startsWith "-" then
    let d := t.drop 1
    canonicalNat d.toString && d.toString != "0"
  else canonicalNat t

/-- An integer of either sign as JSON. -/
def jInt (i : Int) : Json :=
  if -(2 ^ 63 : Int) ≤ i ∧ i < 2 ^ 63 then toJson i else toJson (toString i)

def jNat (n : Nat) : Json := jInt (n : Int)

def asNat (k : String) : Json → Except String Nat
  | .str t => if canonicalNat t then pure t.toNat! else throw s!"{k}: not a canonical decimal: {t}"
  | .num n =>
    if n.exponent != 0 || n.mantissa < 0 then throw s!"{k}: not a non-negative integer"
    else pure n.mantissa.toNat
  | v => throw s!"{k}: not an integer: {v.compress}"

def asInt (k : String) : Json → Except String Int
  | .str t =>
    if !canonicalInt t then throw s!"{k}: not a canonical decimal: {t}"
    else match t.toInt? with
      | some i => pure i
      | none => throw s!"{k}: not a decimal: {t}"
  | .num n => if n.exponent != 0 then throw s!"{k}: not an integer" else pure n.mantissa
  | v => throw s!"{k}: not an integer: {v.compress}"

def asBool (k : String) : Json → Except String Bool
  | .bool b => pure b
  | v => throw s!"{k}: not a boolean: {v.compress}"

def asStr (k : String) : Json → Except String String
  | .str s => pure s
  | v => throw s!"{k}: not a string: {v.compress}"

/-- The object has exactly these keys. -/
def exactKeys (j : Json) (what : String) (keys : List String) : Except String Unit := do
  let obj ← j.getObj?
  let got := (obj.toArray.map (·.1)).toList
  if got.length != keys.length || !(got.all keys.contains) then
    throw s!"{what}: keys must be exactly {keys}, got {got}"

def field (j : Json) (k : String) : Except String Json := j.getObjVal? k

def gN (j : Json) (k : String) : Except String Nat := do asNat k (← field j k)
def gI (j : Json) (k : String) : Except String Int := do asInt k (← field j k)
def gB (j : Json) (k : String) : Except String Bool := do asBool k (← field j k)
def gS (j : Json) (k : String) : Except String String := do asStr k (← field j k)

def asList {α : Type} (k : String) (f : Json → Except String α) : Json → Except String (List α)
  | .arr a => a.toList.mapM f
  | v => throw s!"{k}: not a list: {v.compress}"

def gL {α : Type} (j : Json) (k : String) (f : Json → Except String α) : Except String (List α) := do
  asList k f (← field j k)

/-- `null` is `none`; any other value is `some`. -/
def asOpt {α : Type} (f : Json → Except String α) : Json → Except String (Option α)
  | .null => pure none
  | v => some <$> f v

def gO {α : Type} (j : Json) (k : String) (f : Json → Except String α) : Except String (Option α) := do
  asOpt f (← field j k)

def jOpt {α : Type} (f : α → Json) : Option α → Json
  | none => .null
  | some a => f a

def jList {α : Type} (f : α → Json) (xs : List α) : Json := .arr (xs.map f).toArray

/-- An enumeration value: the JSON string must be one of the names. -/
def asEnum {α : Type} (k : String) (names : List (String × α)) : Json → Except String α
  | .str s => match names.find? (·.1 == s) with
    | some (_, a) => pure a
    | none => throw s!"{k}: unknown value {s}"
  | v => throw s!"{k}: not a string: {v.compress}"

def gE {α : Type} (j : Json) (k : String) (names : List (String × α)) : Except String α := do
  asEnum k names (← field j k)

/-- The name of an enumeration value, from the same table the decoder reads. -/
def enumName {α : Type} [BEq α] (names : List (String × α)) (a : α) : String :=
  match names.find? (·.2 == a) with
  | some (s, _) => s
  | none => "?"

/-- A pair `[a, b]`. -/
def asPair {α β : Type} (k : String) (f : Json → Except String α) (g : Json → Except String β) :
    Json → Except String (α × β)
  | .arr a => if h : a.size = 2 then do pure (← f a[0], ← g a[1]) else throw s!"{k}: not a pair"
  | v => throw s!"{k}: not a pair: {v.compress}"

def jPair {α β : Type} (f : α → Json) (g : β → Json) (p : α × β) : Json := .arr #[f p.1, g p.2]

/-- The `reason` of a refused run: the codes, sorted and joined by `|`. -/
def joinCodes (cs : List String) : String := "|".intercalate cs

/-! ## The two modes

A capability supplies the request decoder, the answer of a run and the answer
of one `--step` line. The driver holds no spec logic. -/

structure Oracle where
  /-- `inputs` of a kink-implementation/1 request to the answer object. -/
  answer : Json → Except String Json
  /-- one decoded `--step` line `{"state", "op"}` to its answer object. -/
  step : Json → Except String Json

def runRequest (o : Oracle) (req : Json) : Except String Json := do
  exactKeys req "request" ["protocol", "program", "inputs"]
  let proto ← gS req "protocol"
  if proto != "kink-implementation/1" then throw s!"unsupported protocol {proto}"
  let _ ← gS req "program"
  o.answer (← field req "inputs")

def stepLine (o : Oracle) (line : String) : Json :=
  match parseLine line >>= o.step with
  | .ok j => j
  | .error e => Json.mkObj [("error", toJson e)]

partial def stepLoop (o : Oracle) (stdin : IO.FS.Stream) (stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  if line.trimAscii.isEmpty then return (← stepLoop o stdin stdout)
  stdout.putStrLn (stepLine o line).compress
  stdout.flush
  stepLoop o stdin stdout

def main (o : Oracle) (args : List String) : IO UInt32 := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  if args == ["--step"] then
    stepLoop o stdin stdout
    return 0
  if args != [] then
    IO.eprintln s!"oracle: unknown arguments {args}"
    return 2
  let input ← stdin.readToEnd
  match parseLine input >>= runRequest o with
  | .ok out => stdout.putStrLn out.compress; return 0
  | .error e => IO.eprintln s!"oracle: {e}"; return 2

/-- `{"end": "final", "cells": cells}` -/
def finalAnswer (cells : Json) : Json := Json.mkObj [("end", "final"), ("cells", cells)]

/-- `{"end": "could-not-apply", "reason": codes}` -/
def refusedAnswer (codes : List String) : Json :=
  Json.mkObj [("end", "could-not-apply"), ("reason", toJson (joinCodes codes))]

end SplitCodec
