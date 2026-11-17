# Ambiguity ledger: split-envelope

One ledger for the capability, shared by the Lean oracle (this package) and the
Quint model of LOOP item 14. Each entry is a sentence of
`openspec/changes/add-split-line-dealing/specs/split-envelope/spec.md` that
admits more than one reading, or a case the oracle must answer and the spec
does not state. Where the spec is silent, the oracle refuses and the entry
says with which code.

- **Status.** `open`: no ruling yet. `ruled`: the spec owner chose a reading.
  `held`: a reading is applied until a ruling replaces it.
- **Gate.** `gates.sh oracle envelope` fails while any entry is `open`.
- **Spec version.** The commit the entry was read at.

| # | ID | Sentence | Readings | Found by | Status | Ruling | Spec version |
|---|---|---|---|---|---|---|---|
| 1 | EN-004 to EN-008 | the five public checks, each "refuse to accept it with the code ..." | when several fail, (a) one code by some order; (b) every code | oracle author | held | Reading (b): the spec gives no precedence, so `publicRefusals` returns every code that applies, sorted (`bad_epoch`, `bad_proof`, `bad_shape`, `dd_reused`, `expired`). An implementation that returns one member of the set agrees until a ruling. | 93ec63b |
| 2 | EN-008 | "If an envelope has the outer-dealing digest `dd` of an earlier envelope of the same epoch" | (a) an earlier accepted envelope; (b) any earlier envelope, refused ones included | oracle author | held | Reading (a): a refused envelope is not ordered (EN-004), so the node keeps no trace of it; `seen` holds the `(epoch, dd)` of accepted envelopes only. | 93ec63b |
| 3 | EN-002 | "and 18 reserved bytes" | (a) a node refuses nonzero reserved bytes; (b) no check reads them | oracle author | held | Reading (b): EN-004 to EN-008 name no check of the reserved bytes, so the oracle carries `reserved` and reads it nowhere. | 93ec63b |
| 4 | none | the board height of the node | a height below the current one | oracle author | held | No requirement defines a board height that goes down; `tick` to a lower height is refused with the harness code `no-rule` and changes nothing. | 93ec63b |
| 5 | EN-009, EN-010, EN-014; RQ-067 | domains of a header, an epoch list and a combination | a header with `K ∉ 1..8` or `L ∉ 1..2`, a layout without 15 body and 8 capsule entries, more than 8 capsules; an epoch list that names an epoch twice; `t = 0` or a sender twice among the partials | oracle author | held | Outside the domain sentences (RQ-067 `K ∈ 1..8`, `L ∈ 1..2`; EN-009 "24 big-endian 2-byte lengths: `body_0`, 15 body regions and 8 capsule regions"): refused with `outside-capability`, state unchanged. The spec does not say whether such a header is malformed; the oracle does not decide it. | 93ec63b |
| 6 | EN-010 | "does not hold ... `K·L` tickets on ECDSA, or does not name one committee slot `ℓ(g, j)` for every `g ≤ G` and `j ≤ L` on Schnorr suites" | on ECDSA, (a) only the ticket count is checked; (b) the ECDSA slots `R_ℓ` are counted too | oracle author | held | Reading (a): the sentence names a slot check for Schnorr suites only. `countBad` checks `K·L` tickets on ECDSA and no slot count. | 93ec63b |
| 7 | EN-009 | "a nonzero unused entry" | which layout entries are unused | oracle author | held | The used body regions are the variant bodies of EN-016 (`bodyLabels`: 15 at `K = 8` on Schnorr, `K` on ECDSA), in order; the used capsule regions are the first `n_capsules`. Every later entry must be zero. | 93ec63b |
| 8 | EN-014 | "drop each partial whose proof fails against the outer commitments and combine again" | fewer than `t` proved partials after the drop | oracle author | held | The spec gives no response; `combine` answers `need_more` (no open, no fault) and the node waits for more partials. RQ-015 applies only when `t` proved partials fail. | 93ec63b |
| 10 | EN-023 | "the board height `b` at which an envelope would be ordered" | at acceptance the ordering height is not known: (a) the current board height; (b) the next block, `height + 1` | oracle author | held | Reading (b): an envelope accepted at board height `h` is ordered at the earliest by the next block, so `submit` refuses with `exp_c_not_below_exp` when `h + 1 + Δ_c ≥ exp` (`windowBad`). The ordering block is checked again by `order_check (exp, b)` with the block's height. Since `h + 1 + Δ_c ≥ exp` holds whenever EN-006 refuses (`exp < h`), an expired envelope gets both codes (entry 1). | 04a3c4f |
