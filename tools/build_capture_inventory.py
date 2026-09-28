#!/usr/bin/env python3
"""Inventory the student's 31 ISCX VPN captures without changing them.

Uses Python's standard library only. Reads each capture in small chunks to
calculate SHA-256. It does NOT decode, relabel, reorder or repair packets.
The output JSON is exclusively created: existing inventories are not replaced.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys


SOURCE_URL = (
    "https://github.com/gfraysse/NOMS2024_Encrypted_Traffic_Classification/"
    "blob/main/iscxvpn2016-vpn-classifier.py"
)
FOLDERS = ("VPN-PCAPS-01", "VPN-PCAPs-02")
FILES_BY_CLASS = {
    "CHAT": (
        "vpn_aim_chat1a.pcap", "vpn_aim_chat1b.pcap",
        "vpn_facebook_chat1a.pcap", "vpn_facebook_chat1b.pcap",
        "vpn_hangouts_chat1a.pcap", "vpn_hangouts_chat1b.pcap",
        "vpn_icq_chat1a.pcap", "vpn_icq_chat1b.pcap",
        "vpn_skype_chat1a.pcap", "vpn_skype_chat1b.pcap",
    ),
    "VOIP": (
        "vpn_facebook_audio2.pcap", "vpn_hangouts_audio1.pcap",
        "vpn_hangouts_audio2.pcap", "vpn_skype_audio1.pcap",
        "vpn_skype_audio2.pcap",
    ),
    "STREAMING": (
        "vpn_netflix_A.pcap", "vpn_spotify_A.pcap", "vpn_vimeo_A.pcap",
        "vpn_vimeo_B.pcap", "vpn_youtube_A.pcap",
    ),
    "FT": (
        "vpn_ftps_A.pcap", "vpn_ftps_B.pcap", "vpn_sftp_A.pcap",
        "vpn_sftp_B.pcap", "vpn_skype_files1a.pcap", "vpn_skype_files1b.pcap",
    ),
    "MAIL": ("vpn_email2a.pcap", "vpn_email2b.pcap"),
    "P2P": ("vpn_bittorrent.pcap",),
}
LABELS = {
    filename: label
    for label, filenames in FILES_BY_CLASS.items()
    for filename in filenames
}
EXCLUDED = {"vpn_voipbuster1a.pcap", "vpn_voipbuster1b.pcap"}
EXPECTED = set(LABELS) | EXCLUDED


def discover(data_root):
    """Require the exact known inventory, without assuming folder membership."""
    paths = []
    for folder in FOLDERS:
        directory = data_root / folder
        if not directory.is_dir():
            raise ValueError(f"Required directory not found: {directory}")
        paths.extend(
            path for path in directory.iterdir()
            if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}
        )
    counts = Counter(path.name for path in paths)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    missing = sorted(EXPECTED - set(counts))
    unknown = sorted(set(counts) - EXPECTED)
    problems = []
    if duplicates:
        problems.append("Duplicate capture names: " + ", ".join(duplicates))
    if missing:
        problems.append("Missing expected captures: " + ", ".join(missing))
    if unknown:
        problems.append("Unrecognised captures (no guessed labels): " + ", ".join(unknown))
    if problems:
        raise ValueError("\n".join(problems))
    return sorted(paths, key=lambda path: path.name)


def fingerprint(path):
    before = path.stat()
    if before.st_size == 0:
        raise ValueError(f"Empty capture: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as capture:
        for chunk in iter(lambda: capture.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(f"Capture changed while being read; retry when stable: {path}")
    return before.st_size, digest.hexdigest()


def build_inventory(data_root, paths):
    records = []
    for index, path in enumerate(paths, 1):
        included = path.name not in EXCLUDED
        label = LABELS.get(path.name)
        print(
            f"[{index:02d}/{len(paths):02d}] {path.name}: "
            f"{'INCLUDE ' + label if included else 'EXCLUDE (VoIPBuster baseline policy)'}; "
            "reading fingerprint...",
            flush=True,
        )
        byte_size, sha256 = fingerprint(path)
        records.append({
            "capture_id": path.relative_to(data_root).as_posix(),
            "filename": path.name,
            "path": str(path),
            "size_bytes": byte_size,
            "sha256": sha256,
            "include_in_baseline": included,
            "initial_class": label,
            "label_scope": "capture_activity_hint" if included else "unassigned",
            "reason": (
                "Filename mapping from the associated NOMS2024 reference implementation; "
                "not verified packet- or flow-level ground truth."
                if included else
                "The reference implementation skips VoIPBuster; preserved but excluded "
                "from this initial baseline, not classified as corrupt."
            ),
        })
    selected = [record for record in records if record["include_in_baseline"]]
    return {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "data_root": str(data_root),
        "policy": {
            "id": "iscx_vpn_31_capture_inventory_v1",
            "label_reference": SOURCE_URL,
            "reference_note": (
                "Associated NOMS2024 code, not a claim of exact replication of the "
                "2025 journal paper's complete preprocessing pipeline."
            ),
            "browsing_label_status": (
                "Not assigned at capture level. The reference uses a port-80/443 "
                "flow-level override outside STREAMING; that is a heuristic, "
                "not verified browsing ground truth."
            ),
            "timestamp_correction_applied": False,
            "flow_extraction_applied": False,
            "train_test_split_assigned": False,
            "notes": [
                "No original captures are modified or copied.",
                "Hashes identify file contents; they do not validate packet structure or labels.",
                "No official download checksums are available to this script for comparison.",
                "Initial class is not a guarantee that every contained flow has that activity.",
                "No packet counts or capture properties are inferred from filename or size.",
            ],
        },
        "summary": {
            "total_captures": len(records),
            "included_captures": len(selected),
            "excluded_captures": len(records) - len(selected),
            "included_captures_by_initial_class": dict(sorted(Counter(
                record["initial_class"] for record in selected
            ).items())),
            "total_size_bytes": sum(record["size_bytes"] for record in records),
            "included_size_bytes": sum(record["size_bytes"] for record in selected),
        },
        "captures": records,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path.home() / "p4")
    parser.add_argument(
        "--output", type=Path,
        default=Path.home() / "p4/etc-training/metadata/capture_inventory.json",
    )
    args = parser.parse_args(argv)
    data_root = args.data_root.expanduser().resolve()
    output = args.output.expanduser().absolute()
    try:
        if output.suffix.lower() != ".json":
            raise ValueError("Output must end in .json, not a capture-file extension.")
        if output.exists() or output.is_symlink():
            raise ValueError(f"Output already exists; nothing overwritten: {output}")
        paths = discover(data_root)
        print("Reading captures only; no packet processing or timestamp changes.", flush=True)
        inventory = build_inventory(data_root, paths)
        # Refuse byte-identical captures in the selected baseline: do not silently
        # count a copied capture as a separate recording, especially across classes.
        hashes = {}
        for record in inventory["captures"]:
            if record["include_in_baseline"]:
                previous = hashes.get(record["sha256"])
                if previous is not None:
                    raise ValueError(
                        "Identical included captures need review: "
                        f"{previous} and {record['filename']}"
                    )
                hashes[record["sha256"]] = record["filename"]
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as destination:
            json.dump(inventory, destination, indent=2)
            destination.write("\n")
        print("\nINVENTORY CREATED")
        print(json.dumps(inventory["summary"], indent=2))
        print(f"Saved to: {output}")
        print("BROWSING: pending flow-level labelling; no BROWSING capture count assigned.")
        return 0
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
