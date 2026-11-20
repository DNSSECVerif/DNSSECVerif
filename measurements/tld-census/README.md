# TLD census, September 9, 2026

A dated measurement of the denial mechanism (NSEC or NSEC3) served by every
IANA top-level domain. It measures how common P21's parent-side prerequisite
is: an NSEC-signed parent that returns a covering NSEC. It is not an
exploitation scan, and it does not show that any TLD or name is compromised.

## Results

| Category | TLDs |
| --- | ---: |
| IANA TLDs (list version 2026090900) | 1,438 |
| NSEC3 | 1,309 |
| NSEC | 53 |
| Unsigned response | 76 |
| NSEC with a root DS and AD-set responses from both recursive resolvers | 52 |
| ...and an authoritative NXDOMAIN with a covering NSEC | 51 (3.55%) |

`.xn--fzc2c9e2c` serves NSEC but has no root DS, so it is not among the 52.
`.gov` returns compact denial (NXNAME/TYPE128, RFC 9824) instead of a covering
NSEC, so it is not among the 51. Counts are TLDs, not operators. Registration
eligibility was not assessed; for example, `.arpa` is not an open registry.

## Files

| Path | Contents |
| --- | --- |
| `final-2026-09-09/p21-nsec-parent-candidates.txt` | The 51 TLDs |
| `final-2026-09-09/nsec-root-ds.txt` | The 52 TLDs listed in the paper's Appendix A |
| `final-2026-09-09/nsec-observed.txt` | The 53 NSEC TLDs |
| `final-2026-09-09/tld_results.csv` | One row per TLD |
| `final-2026-09-09/summary.json` | Counts, lists, and run metadata |
| `outputs-2026-09-09.tar.gz` | All runs: raw `dig` responses, IANA list and root-zone snapshots, SHA-256 manifests, and `observations.json` (3,021 parsed observations) |
| `tld_nsec_census.tex` | The paper's 52-TLD table (extended version), checked by the tests |
| `census.py`, `summarize.py`, `test_census.py` | Collection, reanalysis, and offline tests |

## Method

The run lasted from 23:16:09 to 23:24:25 UTC, including follow-ups. For each
TLD, `census.py` sent a DNSSEC OK (DO) query for a random label through 1.1.1.1
and 8.8.8.8, falling back to 9.9.9.9 or a root-listed authoritative server if
the TLD stayed unresolved. Every NSEC TLD was also queried directly at an
authoritative server. A TLD's mechanism is the denial record beneath it whose
RRSIG is signed by that TLD. AD bits come from the recursive resolvers; the
script does not validate signatures itself. Queries were limited to eight `dig`
invocations per second. No exploit, zone transfer, or zone walk was attempted.

Two zones needed apex follow-up queries (`xn--kprw13d`, `xn--node`) to avoid
wildcard or DNAME redirection. `summarize.py` merges the runs, verifies the
hashes of 4,473 source files, and writes `final-2026-09-09/`. The root-zone
snapshot has SOA serial 2026090901.

The observations come from a single vantage point at a single time.
Exploitation also needs a signed child zone, a covering NSEC for the target
name, and a vulnerable downstream resolver.

## Reproducing

Offline reanalysis needs only Python 3. From the repository root:

```sh
tar -xzf measurements/tld-census/outputs-2026-09-09.tar.gz
cd measurements/tld-census
python3 -m unittest -v test_census.py
python3 summarize.py --base 2026-09-09 --followup followup-2026-09-09 --output rechecked-2026-09-09
```

The tests check the archive checksum, the manifests, the classification of
every saved observation, the 51/52/53 lists, and the paper's table. The
reanalysis reproduces the final lists and CSV; only timestamps and paths in
`summary.json` differ.

A new census needs BIND `dig`, `curl`, and network access. Save it under a new
run name:

```sh
python3 census.py --output NEW-RUN --qps 8 --workers 8
```

The apex follow-up used
`--only xn--kprw13d xn--node --apex --query-type TYPE65280`.
