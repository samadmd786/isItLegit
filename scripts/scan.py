#!/usr/bin/env python3
"""Run Layer 1 over the sample corpus and print a scorecard.

    python3 scripts/scan.py            # scorecard
    python3 scripts/scan.py -v         # plus every finding
    python3 scripts/scan.py --holdout  # messages written after the rules froze
    echo "some message" | python3 scripts/scan.py -   # check stdin
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.checks import analyze_text  # noqa: E402


def main(argv: list[str]) -> int:
    if "-" in argv:
        print(json.dumps(analyze_text(sys.stdin.read()), indent=2, ensure_ascii=False))
        return 0
    verbose = "-v" in argv
    name = "holdout2.json" if "--holdout2" in argv else "holdout.json" if "--holdout" in argv else "corpus.json"
    cases = json.loads((ROOT / "samples" / name).read_text())
    exact = safe_side = 0
    missed_scams: list[str] = []
    false_alarms: list[str] = []
    for c in cases:
        r = analyze_text(c["text"])
        ok = r["verdict"] == c["expect"]
        exact += ok
        if c["label"] == "scam" and r["verdict"] == "looks_ok":
            missed_scams.append(c["id"])
        if c["label"] == "legit" and r["verdict"] == "dont_click":
            false_alarms.append(c["id"])
        mark = "ok " if ok else "XX "
        print(f"{mark} {c['id']:<24} expect={c['expect']:<11} got={r['verdict']:<11} score={r['score']}")
        if verbose or not ok:
            for f in r["findings"]:
                print(f"      [{f['severity']}] {f['rule_id']}: {f['evidence']}")
    n = len(cases)
    scams = sum(c["label"] == "scam" for c in cases)
    legit = n - scams
    print()
    print(f"exact verdict match: {exact}/{n}")
    print(f"scams caught (not 'looks ok'): {scams - len(missed_scams)}/{scams}  missed: {missed_scams or 'none'}")
    print(f"legit messages not blocked:    {legit - len(false_alarms)}/{legit}  false alarms: {false_alarms or 'none'}")
    return 0 if exact == n else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
