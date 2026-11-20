#!/usr/bin/env python3
"""Reclassify retained DNS responses and combine explicitly recorded follow-ups.

The raw runs remain immutable. This checks their hashes before producing a
separate final dataset; no network traffic is generated.
"""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from census import classify, utc


def check_manifest(directory):
    manifest = json.loads((directory / "sha256.json").read_text())
    for relative, expected in manifest.items():
        actual = hashlib.sha256((directory / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Hash mismatch: {directory / relative}")
    return len(manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--followup", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sources = (args.base, args.followup)
    verified_files = sum(check_manifest(source) for source in sources)
    original_summary = json.loads((args.base / "summary.json").read_text())
    followup_summary = json.loads((args.followup / "summary.json").read_text())
    tlds = [line.lower() for line in (args.base / "tlds-alpha-by-domain.txt").read_text().splitlines()
            if line and not line.startswith("#")]
    rows = []
    for tld in sorted(tlds):
        base = json.loads((args.base / (tld + ".json")).read_text())
        observations = []
        for source in sources:
            filename = source / (tld + ".json")
            if not filename.exists():
                continue
            data = json.loads(filename.read_text())
            for old in data["observations"]:
                rawfile = source / old["raw"]
                parsed = classify(rawfile.read_text(), tld, old["query"])
                parsed.update(server=old["server"], query=old["query"], utc=old["utc"],
                              direct=old["direct"], raw=str(rawfile))
                observations.append(parsed)
        definitive = [o for o in observations if o["classification"] != "unresolved"]
        classes = {o["classification"] for o in definitive}
        kind = next(iter(classes)) if len(classes) == 1 and len(definitive) >= 2 else "unresolved"
        ad_servers = sorted({o["server"] for o in definitive if not o["direct"] and o["ad"]})
        authoritative = any(o["direct"] and o["aa"] and o["classification"] == kind for o in definitive)
        covering = any(o["direct"] and o["aa"] and o["status"] == "NXDOMAIN" and
                       o["nsec_covers_query"] for o in definitive)
        compact = any(o["compact_nsec"] for o in definitive)
        # This predicate records measured prerequisites, never exploitation.
        candidate = kind == "nsec" and base["root_ds"] and len(ad_servers) >= 2 and covering and not compact
        row = dict(tld=tld, denial_mechanism=kind, root_ds=base["root_ds"],
                   ad_resolver_count=len(ad_servers), authoritative_confirmed=authoritative,
                   covering_nsec_authoritative=covering, compact_nsec=compact,
                   p21_nsec_parent_candidate=candidate, observations=observations)
        rows.append(row)
    counts = dict(Counter(r["denial_mechanism"] for r in rows))
    assert len(rows) == original_summary["total_iana_tlds"]
    assert counts.get("unresolved", 0) == 0, "Unresolved observations must not be silently excluded"
    assert sum(counts.values()) == len(tlds)
    observed = [r["tld"] for r in rows if r["denial_mechanism"] == "nsec"]
    trusted = [r["tld"] for r in rows if r["denial_mechanism"] == "nsec" and r["root_ds"]]
    candidates = [r["tld"] for r in rows if r["p21_nsec_parent_candidate"]]
    summary = dict(analysis_utc=utc(), started_utc=original_summary["started_utc"],
                   completed_utc=followup_summary["completed_utc"],
                   iana_version=original_summary["iana_version"], total_tlds=len(tlds),
                   counts=counts, root_ds_count=sum(r["root_ds"] for r in rows),
                   nsec_observed=observed, nsec_with_root_ds=trusted,
                   p21_nsec_parent_candidates=candidates,
                   compact_nsec=[r["tld"] for r in rows if r["compact_nsec"]],
                   nsec_without_root_ds=[r["tld"] for r in rows if r["denial_mechanism"] == "nsec" and not r["root_ds"]],
                   source_runs=[str(path) for path in sources], source_files_hash_verified=verified_files,
                   source_observation_count=sum(len(r["observations"]) for r in rows),
                   scope="Observed denial mechanisms and P21 parent-side prerequisites; no exploit testing, arbitrary-target exposure, or registry registration-policy assessment.")
    args.output.mkdir(parents=True, exist_ok=False)
    fields = [key for key in rows[0] if key != "observations"]
    with (args.output / "tld_results.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    (args.output / "observations.json").write_text(json.dumps(rows, indent=2) + "\n")
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for filename, names in (("nsec-observed.txt", observed), ("nsec-root-ds.txt", trusted),
                            ("p21-nsec-parent-candidates.txt", candidates)):
        (args.output / filename).write_text("".join(name + "\n" for name in names))
    manifest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(args.output.iterdir()) if path.is_file()}
    (args.output / "sha256.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
