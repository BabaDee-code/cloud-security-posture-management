from __future__ import annotations

import json
import sys
from pathlib import Path

from .scanner import scan_snapshot


def main(snapshot_path: str) -> None:
    snapshot = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
    findings = scan_snapshot(snapshot)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m cspm.scan data/aws_snapshot.json")
    main(sys.argv[1])
