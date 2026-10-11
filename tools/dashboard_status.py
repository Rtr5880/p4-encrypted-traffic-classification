#!/usr/bin/env python3
"""Read-only dashboard evidence preflight; never launches a switch or experiment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.evidence import EvidenceStore  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, help="Explicit pinned JSON registry")
    parser.add_argument("--project-root", type=Path, help="Relocated project evidence root")
    parser.add_argument("--json", action="store_true", help="Print structured status rows")
    args = parser.parse_args(argv)
    store = EvidenceStore(args.registry, args.project_root)
    rows = store.status_rows()
    if args.json:
        print(json.dumps({"schema_version": "dashboard-evidence-status-v1",
                          "read_only": True, "registry": str(store.registry_path),
                          "project_root": str(store.project_root), "evidence": rows}, indent=2))
    else:
        print("DASHBOARD EVIDENCE PREFLIGHT — read-only; no traffic, training or benchmark")
        print(f"Registry: {store.registry_path}")
        for row in rows:
            print(f"{row['role']:<31} {row['status'].upper():<12} {row['path'] or '-'}")
            if row["status"] != "verified":
                print(f"  {row['message']}")
        print(f"Verified file/schema evidence: {sum(r['status'] == 'verified' for r in rows)}/{len(rows)}")
        print("VERIFIED means pinned bytes/schema, not scientific PASS. Saved metric gates remain authoritative.")
    return 0 if rows and all(row["status"] == "verified" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
