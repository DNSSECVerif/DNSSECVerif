#!/usr/bin/env python3
"""Read-only, rate-limited TLD denial-mechanism census using BIND dig.

No exploit packets, zone transfers, registration, or configuration changes.
Raw dig output and the IANA/root-zone inputs are retained for every run.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import threading
import time


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RateLimit:
    def __init__(self, qps):
        self.interval = 1 / qps
        self.next = 0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            delay = max(0, self.next - now)
            self.next = max(now, self.next) + self.interval
        time.sleep(delay)


def parse_records(text):
    records = []
    for line in text.splitlines():
        match = re.match(r"^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.+)$", line)
        if match:
            owner, ttl, rtype, data = match.groups()
            records.append(dict(owner=owner.lower(), ttl=int(ttl), type=rtype, data=data))
    return records


def name_key(name):
    return tuple(label.encode("ascii") for label in reversed(name.lower().rstrip(".").split(".")))


def covers(owner, following, query):
    start, end, value = map(name_key, (owner, following, query))
    return start < value < end if start < end else value > start or value < end


def classify(output, tld, qname):
    status = re.search(r"status: (\w+)", output)
    flags = re.search(r";; flags: ([^;]+);", output)
    flags = flags.group(1).split() if flags else []
    records = parse_records(output)
    apex = tld + "."
    soa = [r for r in records if r["type"] == "SOA" and r["owner"] == apex]
    signatures = {(r["owner"], r["data"].split()[0]) for r in records
                  if r["type"] == "RRSIG" and len(r["data"].split()) >= 8
                  and r["data"].split()[7].lower() == apex}
    denial = [r for r in records if r["type"] in ("NSEC", "NSEC3")
              and (r["owner"] == apex or r["owner"].endswith("." + apex))
              and (r["owner"], r["type"]) in signatures]
    types = {r["type"] for r in denial}
    result = dict(status=status.group(1) if status else "NO_RESPONSE", flags=flags,
                  ad="ad" in flags, aa="aa" in flags, soa_apex=bool(soa),
                  records=records, denial_records=denial)
    # Positive wildcard responses can carry signed denial proofs without an
    # SOA. The RRSIG signer check above prevents counting a CNAME target's or
    # the root zone's denial as a proof originating in the measured TLD.
    if result["status"] not in ("NXDOMAIN", "NOERROR"):
        result["classification"] = "unresolved"
    elif types == {"NSEC", "NSEC3"}:
        result["classification"] = "mixed"
    elif types == {"NSEC"}:
        result["classification"] = "nsec"
    elif types == {"NSEC3"}:
        result["classification"] = "nsec3"
    elif soa and not signatures and not types and "ad" not in flags:
        result["classification"] = "unsigned_response"
    else:
        result["classification"] = "unresolved"
    result["nsec_covers_query"] = any(covers(r["owner"], r["data"].split()[0], qname)
                                        for r in denial if r["type"] == "NSEC")
    result["nsec3_optout_observed"] = any(int(r["data"].split()[1]) & 1
                                          for r in denial if r["type"] == "NSEC3")
    result["compact_nsec"] = any(r["type"] == "NSEC" and
                                 {"TYPE128", "NXNAME"}.intersection(r["data"].split())
                                 for r in denial)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qps", type=float, default=8)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--only", nargs="*", help="Optional pilot TLDs; omitted for a full census")
    parser.add_argument("--apex", action="store_true", help="Query the apex, avoiding wildcard/DNAME redirection")
    parser.add_argument("--query-type", default="A")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    raw = out / "raw"
    raw.mkdir()
    started = utc()
    sources = {"tlds-alpha-by-domain.txt": "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
               "root.zone": "https://www.internic.net/domain/root.zone"}
    for filename, url in sources.items():
        subprocess.run(["curl", "-L", "--fail", "--silent", "--show-error", "--max-time", "90",
                        "--output", str(out / filename), url], check=True)
    seed = (out / "tlds-alpha-by-domain.txt").read_text()
    tlds = sorted(line.strip().lower() for line in seed.splitlines() if line and not line.startswith("#"))
    assert len(tlds) == len(set(tlds))
    root_records = parse_records((out / "root.zone").read_text())
    root_ns = {}
    root_addresses = {}
    ds = set()
    for record in root_records:
        owner, typ = record["owner"], record["type"]
        if typ == "NS" and owner.rstrip(".") in tlds:
            root_ns.setdefault(owner.rstrip("."), []).append(record["data"].strip().lower())
        if typ == "A":
            root_addresses.setdefault(owner, []).append(record["data"].strip())
        if typ == "DS":
            ds.add(owner.rstrip("."))
    missing = set(tlds) - set(root_ns)
    if missing:
        raise RuntimeError(f"IANA/root delegation mismatch: {sorted(missing)}")
    selection = sorted(set(t.lower().rstrip(".") for t in args.only)) if args.only else tlds
    assert set(selection) <= set(tlds)
    limiter = RateLimit(args.qps)
    nonce = secrets.token_hex(6)
    dig = shutil.which("dig")
    if not dig:
        raise RuntimeError("dig is required")

    def query(tld, server, index, direct=False):
        qname = tld + "." if args.apex else f"dnssec-measure-{nonce}-{index}.{tld}."
        command = [dig, "@" + server, qname, args.query_type, "+dnssec", "+time=4", "+tries=1",
                   "+bufsize=1232", "+nocookie", "+noall", "+comments", "+answer", "+authority"]
        if direct:
            command.append("+norecurse")
        limiter.wait()
        stamp = utc()
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=12)
            output = proc.stdout + proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            output = "subprocess timeout\n"
            exit_code = 124
        name = f"{tld}--{index}--{server}.txt"
        (raw / name).write_text(output)
        result = classify(output, tld, qname)
        result.update(server=server, query=qname, utc=stamp, direct=direct,
                      command=command, exit_code=exit_code, raw="raw/" + name)
        return result

    def measure(tld):
        observations = [query(tld, server, str(i)) for i, server in enumerate(("1.1.1.1", "8.8.8.8"))]
        if any(o["classification"] == "unresolved" for o in observations) or len({o["classification"] for o in observations}) > 1:
            observations.append(query(tld, "9.9.9.9", "2"))
        definitive = [o for o in observations if o["classification"] != "unresolved"]
        classes = {o["classification"] for o in definitive}
        classification = next(iter(classes)) if len(classes) == 1 and len(definitive) >= 2 else "unresolved"
        direct = []
        if classification in ("nsec", "mixed") or classification == "unresolved":
            for ns in root_ns[tld]:
                for address in root_addresses.get(ns, [])[:1]:
                    result = query(tld, address, "auth" + str(len(direct)), direct=True)
                    result["nameserver"] = ns
                    direct.append(result)
                    if result["classification"] != "unresolved" and result["aa"]:
                        break
                if any(o["classification"] != "unresolved" and o["aa"] for o in direct):
                    break
            direct_classes = {o["classification"] for o in direct if o["aa"] and o["classification"] != "unresolved"}
            if direct_classes and classes and direct_classes != classes:
                classification = "inconsistent"
            elif classification == "unresolved" and len(classes | direct_classes) == 1 and direct_classes and definitive:
                classification = next(iter(direct_classes))
        validated = sum(o["ad"] for o in observations if o["classification"] == classification)
        eligible = (classification == "nsec" and tld in ds and validated >= 2
                    and any(o["aa"] and o["classification"] == "nsec" and o["nsec_covers_query"] for o in direct))
        row = dict(tld=tld, classification=classification, root_ds=tld in ds,
                   validating_resolvers=validated, direct_confirmed=classification != "unresolved" and any(o["aa"] and o["classification"] == classification for o in direct),
                   nsec_parent_precondition_confirmed=eligible,
                   observations=observations + direct)
        (out / (tld + ".json")).write_text(json.dumps(row, indent=2) + "\n")
        return row

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(measure, tld): tld for tld in selection}
        for future in as_completed(futures):
            results.append(future.result())
            if len(results) % 100 == 0 or len(results) == len(selection):
                print(f"{utc()} {len(results)}/{len(selection)} {dict(Counter(r['classification'] for r in results))}", flush=True)
    results.sort(key=lambda row: row["tld"])
    fields = ["tld", "classification", "root_ds", "validating_resolvers", "direct_confirmed", "nsec_parent_precondition_confirmed"]
    with (out / "tld_results.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    confirmed = [r["tld"] for r in results if r["nsec_parent_precondition_confirmed"]]
    observed = [r["tld"] for r in results if r["classification"] == "nsec"]
    (out / "nsec-tlds.txt").write_text("".join(t + "\n" for t in observed))
    (out / "confirmed-nsec-parent-tlds.txt").write_text("".join(t + "\n" for t in confirmed))
    summary = dict(started_utc=started, completed_utc=utc(), iana_version=seed.splitlines()[0],
                   total_iana_tlds=len(tlds), measured=len(results), pilot=bool(args.only),
                   qps_limit=args.qps, workers=args.workers, sources=sources,
                   query_type=args.query_type, apex_queries=args.apex,
                   counts=dict(Counter(r["classification"] for r in results)),
                   root_ds_count=sum(r["root_ds"] for r in results),
                   nsec_tlds=observed, confirmed_nsec_parent_tlds=confirmed,
                   not_confirmed=[r["tld"] for r in results if r["classification"] == "nsec" and not r["nsec_parent_precondition_confirmed"]])
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    manifest = {str(path.relative_to(out)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(out.rglob("*")) if path.is_file()}
    (out / "sha256.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
