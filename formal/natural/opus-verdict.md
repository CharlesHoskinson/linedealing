# Opus install review: Natural Lean port (INSTALL-LIST.md)

Reviewer: independent Opus agent, 2026-11-13. I did not install anything and did not read `codex-verdict.md`.

## Host and upstream facts I checked (read-only)

- `elan toolchain list`: `v4.33.1`, `v4.35.0` (the default resolves from `stable`). `~/.elan/toolchains` has the same two directories, 3.0 GB and 3.1 GB on disk.
- `formal/lean/lean-toolchain` = `leanprover/lean4:v4.35.0`. Its lakefile has Mathlib as a **path** dependency on `/home/hoskinson/Projects/Moriarty-wt/mca-lean/formal/mca-lean/.lake/packages/mathlib` (6.9 GB, built locally). It is a v4.35 build and other Moriarty work also uses it.
- `/home` has 2.7 TB free. Disk space is not a constraint.
- `medovina/natural_lean` HEAD is `089bcf9e265f1da685464e874fdca37d4f285888` (pushed 2026-11-13T13:38Z; five commits on that day, including two reverts). The project is active and changes every day.
- Its `lean-toolchain` = `v4.36.0-rc2`. The lakefile requires `aesop@master` and `batteries@main`. The manifest pins batteries `6d971e7e…` and aesop `7d11bfa8…`, and **both of those commits have `lean-toolchain` = v4.36.0-rc2**. The aesop pin is exactly the aesop `v4.36.0-rc2` tag.
- The `lean-toolchain` history follows each Lean release closely: 4.34.0, then 4.35.0-rc2/rc3/rc4, then 4.35.0 (commit `c9768172f2`, 2026-10-14), then 4.36.0-rc1 (2026-10-17), then 4.36.0-rc2 (2026-10-29). The two 4.36 bump commits changed only `lean-toolchain` and `lake-manifest.json`, with no `.lean` source changes. So at bump time the library needed no 4.36-only API. Since the 4.35.0 commit, 89 commits have changed 25 files. A static read cannot show whether those commits now use 4.36-only API. Only a build can show that.
- The library is pure metaprogramming. `Natural/*.lean` uses the `module` / `public import` / `public section` system and `Lean.Elab`, `Lean.Parser`, `Lean.PrettyPrinter`, environment extensions and an LSP layer. These are internal Lean APIs, and they change between releases with no deprecation period. This is the code most likely to break when the toolchain is changed.
- `leanprover/lean4` release `v4.36.0-rc2` (2026-10-27) ships `linux_aarch64` assets. Mathlib, batteries and aesop all have a `v4.36.0-rc2` tag (mathlib4 `9d581dff…`). There is no `v4.36.0` final tag yet.

## Item 1: Lean toolchain v4.36.0-rc2. NEEDED

Reasons:
1. The upstream pins and dependency pins all require rc2, not only the top-level file. On v4.35.0 we would have to downgrade batteries and aesop to their `v4.35.0` tags and also run natural_lean HEAD against internal elaborator and parser APIs it was not written for. If that fails, the only option is the 2026-10-14 commit `c9768172`. That commit is 89 commits behind and has none of the elaboration fixes the owner is getting now. The owner asked for proofs in natural_lean, which means the current library.
2. The "try 4.35.0 first" fallback is not a real saving. It costs one build attempt plus debugging time in metaprogramming code. A toolchain is a self-contained, user-scope directory that elan can uninstall, and the disk has terabytes free.
3. elan installs the toolchain automatically the first time `lake` or `lean` runs in a directory whose `lean-toolchain` says rc2. An explicit, reviewed install is better than a side effect.

Corrections to the list: the size is about **3 GB** on disk (the existing toolchains are 3.0 to 3.1 GB), not 0.5 to 1 GB.

Safer form:
- `elan toolchain install leanprover/lean4:v4.36.0-rc2` only. Do **not** run `elan default` or `elan override` anywhere. Select the toolchain only through `formal/natural/lean-toolchain`. The default stays `stable` (4.35.0), so `formal/lean` and the Moriarty Mathlib path dependency do not change.
- Do not edit `formal/lean/lean-toolchain`. If a v4.35 lake runs against that shared Mathlib path while a v4.36 lake also touches it, the shared build is corrupted. Keep the two projects apart.
- Run the build as a heavy job (heavy-slot / heavy.slice), as the memory rules say.

## Item 2: natural_lean as a Lake git dependency. NEEDED

Reasons: there is no other way to get the library. It is small (Natural/*.lean is about 150 KB of source; batteries and aesop sources are tens of MB).

Safer form:
- Pin the full SHA `rev = "089bcf9e265f1da685464e874fdca37d4f285888"`, not `main`. The upstream changed five times today and reverted twice. A floating rev would make our build depend on the upstream's work in progress.
- Commit `formal/natural/lake-manifest.json` so that batteries `6d971e7e…` and aesop `7d11bfa8…` stay fixed. Lake follows the inherited pins from natural_lean's manifest. Do not run a bare `lake update` again later. To move forward, change the SHA on purpose and update only `natural`.
- Use scope `project` (`formal/natural/.lake/packages`) only. Do not use a path dependency into another worktree.

## Item 3a: Mathlib at v4.36.0-rc2 (+ cache). REJECT

Reasons:
1. The tag exists (`9d581dff…`), but the existing Mathlib on this host was **built locally**. On aarch64 `lake exe cache get` may not have prebuilt oleans for an rc tag. In that case the real cost is a second multi-hour local Mathlib build of about 7 GB, which uses the shared memory that the heavy-slot rules protect. The list does not name this risk.
2. natural_lean is designed for developments built from first principles with its own grammar and notation (its examples build ℕ, ℤ and sets from nothing). Mathlib under it brings a large notation and instance space, with possible parser and notation conflicts that are hard to fix in an rc-tracking metaprogramming library.
3. Each upstream toolchain bump (4.36.0 final will come soon) would force a new Mathlib fetch or build each time.

## Item 3b: no Mathlib, self-contained algebra base. CHOOSE

Reasons: no download. The port stays inside natural_lean's own dependency set (Lean core + batteries + aesop). This matches how the library is meant to be used.

Safer form and scope controls:
- Make the base minimal, and only as large as the 48 LineDealing theorems need: a field class (or a concrete prime field as `Fin p` / a subtype of ℕ with proven field laws), vectors as functions `Fin n → F`, and Lagrange basis and interpolation over a `List` or `Finset` of distinct points. Take `Finset` and `List` lemmas from batteries and Lean core before you write new ones.
- Keep `formal/lean` (Mathlib, v4.35) as the reference oracle that does not change. Map each Natural Lean theorem to its Mathlib counterpart by name, so that the port can be checked statement by statement against the 48 proven theorems.
- Run `#print axioms` on each ported theorem (expect only `propext`, `Classical.choice`, `Quot.sound`) and grep for no `sorry`, the same gate as `formal/lean`.

VERDICT: item1=NEEDED, item2=NEEDED, item3a=REJECT, item3b=CHOOSE
