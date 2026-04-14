#!/usr/bin/env python3
"""
recount_controls.py — Canonical source for control/check statistics.

Reads config/nist_800_53_controls.json and config/checks/*.json and prints
the canonical counts displayed in docs, README, and the methodology page.

Definition of "automated" used here:
    A base control is automated if EITHER the control itself OR any of its
    enhancements has at least one cloud-specific check defined in
    config/checks/*.json (across AWS, Azure, or GCP).

This is the "recompute" definition agreed in CHG-00001.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROLS_FILE = ROOT / "config" / "nist_800_53_controls.json"
CHECKS_DIR = ROOT / "config" / "checks"

BASE_ID = re.compile(r"^([A-Z]{2}-\d+)(?:\(\d+\))?$")


def base_of(control_id: str) -> str:
    m = BASE_ID.match(control_id)
    return m.group(1) if m else control_id


def load_catalog() -> tuple[set[str], set[str], int]:
    """Return (base_control_ids, all_ids_including_enhancements, families_count)."""
    data = json.loads(CONTROLS_FILE.read_text())
    base, all_ids = set(), set()
    for fam in data["families"].values():
        for cid, ctrl in fam.get("controls", {}).items():
            base.add(cid)
            all_ids.add(cid)
            for eid in (ctrl.get("enhancements") or {}).keys():
                all_ids.add(eid)
    return base, all_ids, len(data["families"])


def load_checks() -> tuple[dict[str, set[str]], int, int, int]:
    """Return (control_id -> set of clouds with checks, aws_n, azure_n, gcp_n)."""
    coverage: dict[str, set[str]] = {}
    aws_n = azure_n = gcp_n = 0
    for f in sorted(CHECKS_DIR.glob("*.json")):
        d = json.loads(f.read_text())
        for cid, ch in d.get("checks", {}).items():
            for cloud in ("aws", "azure", "gcp"):
                v = ch.get(cloud) or []
                if isinstance(v, list) and v:
                    coverage.setdefault(cid, set()).add(cloud)
                    n = len(v)
                    if cloud == "aws":
                        aws_n += n
                    elif cloud == "azure":
                        azure_n += n
                    else:
                        gcp_n += n
    return coverage, aws_n, azure_n, gcp_n


def count_objectives() -> int:
    data = json.loads(CONTROLS_FILE.read_text())
    n = 0
    for fam in data["families"].values():
        for ctrl in fam.get("controls", {}).values():
            objs = ctrl.get("objectives") or []
            n += len(objs) if isinstance(objs, (list, dict)) else 0
    return n


def compute() -> dict[str, int]:
    base_ids, all_ids, families = load_catalog()
    coverage, aws_n, azure_n, gcp_n = load_checks()

    automated_bases = {base_of(cid) for cid in coverage.keys()}
    automated_bases &= base_ids  # safety

    return {
        "families": families,
        "controls": len(base_ids),
        "objectives": count_objectives(),
        "automated": len(automated_bases),
        "manual": len(base_ids) - len(automated_bases),
        "aws_checks": aws_n,
        "azure_checks": azure_n,
        "gcp_checks": gcp_n,
        "total_checks": aws_n + azure_n + gcp_n,
        "covered_control_ids_incl_enhancements": len(coverage),
    }


def main() -> None:
    s = compute()
    print("FedRAMP Scanner — canonical counts")
    print("=" * 40)
    for k, v in s.items():
        print(f"{k:>40} : {v}")


if __name__ == "__main__":
    main()
