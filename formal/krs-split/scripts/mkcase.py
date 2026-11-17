#!/usr/bin/env python3
"""Write kink case documents from oracle-form inputs.

Usage: mkcase.py SCHEMA CASES_DIR < specs.json

specs.json is a list of {"name", "why", "inputs"}, where `inputs` is in the Lean
oracle's own JSON form (as in formal/lean-split/<cap>/cases.json). Each spec
becomes CASES_DIR/<name>/case.toml with the inputs in the KRS typed encoding
(through oracle_adapter.py's schema) and `why` as a comment: the requirement the
case exists for, so a `krs kink prune` report cannot remove it unnoticed.
"""
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import oracle_adapter as ad  # noqa: E402


def key(k):
    return k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else json.dumps(k)


def toml(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(toml(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{key(k)} = {toml(x)}" for k, x in v.items()) + " }" if v else "{}"
    raise SystemExit(f"mkcase: no TOML for {v!r}")


def main():
    schema = json.loads(pathlib.Path(sys.argv[1]).read_text())
    out = pathlib.Path(sys.argv[2])
    for spec in json.load(sys.stdin):
        inputs = ad.inputs_from_oracle(schema, spec["inputs"])
        lines = [f"# {l}" for l in spec["why"].splitlines()] + ["[inputs]"]
        for k, v in inputs.items():
            if isinstance(v, list) and v and k == "ops":
                lines.append(f"{k} = [")
                lines += [f"  {toml(x)}," for x in v]
                lines.append("]")
            else:
                lines.append(f"{k} = {toml(v)}")
        d = out / spec["name"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "case.toml").write_text("\n".join(lines) + "\n")
        print(f"mkcase: {d / 'case.toml'}")


if __name__ == "__main__":
    main()
