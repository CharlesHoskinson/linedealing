# Lane: Quint model of the line-dealing committee protocol

The design is design/SCHEME.md (line dealing). Read it in full, plus design/FINDINGS-LEDGER.md and experiments/line-dealing/checks.py (a pure-Python reference of the algebra and attacks, 36 passing assertions). Treat SCHEME.md as the specification. Do not edit SCHEME.md or anything outside your own folder. Do not commit or push. Run every build or test through heavy-run, e.g. `heavy-run --mem 16G --name <name> -- <cmd>`; if heavy-run is unavailable in your sandbox, run the command directly with low parallelism. No network installs.

Your folder: formal/quint/ . Use the quint-modeling and quint-lang skills (in ~/.gemini/skills).

Write linedealing.qnt: a Quint model of the committee protocol of SCHEME.md sections 3.3-3.9, 4 and 5 for open mode (and sealed mode where cheap), with n = 4, f = 1 (and parameters so n=7,f=2 can be run). Model: nodes with a Byzantine set of size <= f (Byzantine nodes may post anything, equivocate, stay silent); the board as a totally ordered log; owner message accepted/armed (ACK quorum); height reports and the anchor rule; NACK/attempt failure and anchor replacement; PREVOTE at most once per (rid, g) by honest nodes; lock certificate 2f+1; PARTIAL only after the lock and only for the node's own digest; durable slot ledger and restart replay (rule 4) including a node rollback action; generations and fee bumps; ROTATE freeze and resharing to a new committee; FINAL/VOID/EXPIRED tombstones; target chain where every transaction spends the pin.

Invariants (each a named val): 
- NoNonceReuse: no slot (rid, g) has honest partials released for two different digests (this is what prevents key recovery).
- AtMostOneExecution: at most one transaction of a request executes on the target chain.
- LockBeforeShare: no honest partial exists for a digest without a 2f+1 lock certificate on the board.
- NoTransientTombstone: a request is tombstoned only by FINAL, VOID or EXPIRED, never by an ineligible anchor.
- FreezeSafety: no generation is both signed by the old committee after ROTATE and reshared to the new committee.
Also a witness/liveness-style check (e.g. a val that becomes true when a spend executes, used with --invariant on its negation to show reachability).

Add unit tests (run blocks) for the anchor rule (the (f, f, 1) split), the vote rules, and rollback with/without rule 4. Also add one deliberately broken variant (e.g. a flag that disables the one-PREVOTE rule or rule 4) and show the simulator finds a NoNonceReuse counterexample.

Run: quint typecheck, quint test, quint run --max-steps=30 --max-samples=10000 --invariant=<each>, and quint verify if Apalache is available. Write REPORT.md in your folder: what is modeled, abstractions, each invariant's result with the exact command and output summary, counterexample for the broken variant, and what is not modeled. REPORT.md must be at least 600 words.
