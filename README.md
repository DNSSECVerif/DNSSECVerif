# DNSSECVerif

Artifact for **Mind the Gap: Cross-RFC Formal Analysis Exposes DNSSEC's Hidden
Vulnerabilities** (ACM CCS 2026,
[doi:10.1145/3830454.3846592](https://doi.org/10.1145/3830454.3846592);
extended version: [arXiv:2512.11431](https://doi.org/10.48550/arXiv.2512.11431)).

The paper models ten DNSSEC RFCs in SAPIC+ and checks 23 security properties
with Tamarin and ProVerif. Seventeen hold under the modeled assumptions, and six
are violated:

- Novel cross-RFC vulnerabilities: Cross-Zone Wildcard Cache Poisoning (P21),
  NSEC/NSEC3 coexistence (P22), and NTA cache poisoning (P23).
- Known attacks rediscovered: CD-bit cache poisoning (P7), algorithm downgrade
  (P13), and NSEC zone enumeration (P16).

## Contents

| Path | Contents |
| --- | --- |
| `models/` | 12 SAPIC+ models (`.spthy`, 3,928 lines) and 4 companion ProVerif models (`.pv`) |
| [`MODEL_INDEX.md`](MODEL_INDEX.md) | Property-to-lemma map with reported results and times; RFC clauses and abstractions of each model |
| `run_all.sh`, `Makefile`, `Dockerfile`, `docker-compose.yml` | Verification scripts and container recipe |
| [`measurements/tld-census/`](measurements/tld-census/README.md) | Census of all 1,438 IANA TLDs (September 9, 2026); 51 meet P21's parent-side prerequisite |

## Requirements

Tamarin 1.10.0 and ProVerif 2.04, as in the paper (the study ran Tamarin with
Maude 3.3.1). Alternatively, build the container, which provides both:

```sh
make docker                             # docker build -t dnssecverif .
docker run --rm -it dnssecverif bash    # shell in /app with tamarin-prover and proverif
```

## Running the models

From the repository root (or `/app` in the container):

```sh
# Tamarin
tamarin-prover --prove --derivcheck-timeout=0 models/authentication/dnssec_simple.spthy    # P10–P12, P14
tamarin-prover --prove --derivcheck-timeout=0 models/authentication/dnssec_full.spthy      # P10–P12, P14
tamarin-prover --prove --derivcheck-timeout=0 models/denial_nsec/nsec.spthy                # P15, P17
tamarin-prover --prove --derivcheck-timeout=0 models/aggressive_caching/coexistence.spthy  # P22
tamarin-prover --prove --derivcheck-timeout=0 models/cache/cache_bounded.spthy             # P1–P6, P8–P9

# ProVerif companion models
proverif models/known_attacks/cd_bit_rucsec.pv          # P7
proverif models/known_attacks/algorithm_downgrade.pv    # P13
proverif models/aggressive_caching/nta_vulnerable.pv    # P23
proverif models/aggressive_caching/nta_secure.pv        # P23, fixed model

# SAPIC+ models checked with ProVerif (P18–P20, P21, P21 fixed model):
# export with Tamarin, then verify
mkdir -p results
for m in denial_nsec3/nsec3 rrsig_underflow/rrsig_underflow_vulnerable rrsig_underflow/rrsig_underflow_secure; do
  tamarin-prover -m=proverif "models/$m.spthy" > "results/${m##*/}.pv" && proverif "results/${m##*/}.pv"
done
```

Use `--prove=<lemma>` to check a single Tamarin lemma. In the paper, every model
except the cache model finished within minutes; the cache model took hours to
days.

**Reading the output.** In Tamarin's summary, an `all-traces` lemma marked
`verified` holds, and one marked `falsified` has a counterexample. An
`exists-trace` lemma marked `verified` has a witness; for attack witnesses such
as `attack_exists`, the attack is reachable. ProVerif prints `RESULT ... is
true` (holds), `is false` (with an attack trace), or `cannot be proved`
(inconclusive). For `query event(E)`, `RESULT not event(E) is false` means that
`E` is reachable.

## Runner

`run_all.sh` wraps these commands and writes logs and a summary to
`results/run_<timestamp>/`:

```sh
./run_all.sh --quick                # every model except the cache model (default; make quick)
./run_all.sh --full                 # every model (make all)
./run_all.sh --group cache          # groups: cache, auth, denial, aggressive, attacks
./run_all.sh --model rrsig --json   # models matching a pattern; also writes results.json
docker run --rm -v "$PWD/results:/app/results" dnssecverif --quick   # in the container (make docker-quick)
```

Known limitations:

- P18–P21 are exported with a `sapic` command that the container lacks, so
  these jobs fall back to Tamarin and are summarized as `unknown`. Use the
  export loop above for them.
- The host-side `--docker` option runs `.pv` files with Tamarin. Run inside the
  container instead.
- Summaries count `verified`/`falsified` strings per log, and a zero exit status
  does not mean every lemma finished. Check the per-lemma results.
- `--parse-only` skips `.pv` files, and `--parallel` still runs jobs
  sequentially.

## Scope

In line with coordinated disclosure, the repository omits active exploit
harnesses, historical verification logs, resolver scan data, and P16's
executable secrecy query. It does not independently reproduce all historical
execution timings. Model assumptions are listed in
[MODEL_INDEX.md](MODEL_INDEX.md#shared-assumptions).

## Disclosure

P21 was disclosed to ISC, NLnet Labs, CZ.NIC, and PowerDNS in April 2026, and
all four released fixes: BIND
([CVE-2026-11721](https://kb.isc.org/docs/cve-2026-11721)), Unbound
([CVE-2026-44690](https://nlnetlabs.nl/downloads/unbound/CVE-2026-44690.txt)),
Knot Resolver
([6.4.1](https://www.knot-resolver.cz/documentation/latest/NEWS.html#knot-resolver-6-4-1-2026-07-22)),
and PowerDNS Recursor
([CVE-2026-52688](https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2026-10.html)).
Please report security issues to the authors privately, not in public issues.

## Citation

```bibtex
@inproceedings{zhang2026mindthegap,
  author    = {Zhang, Qifan and Shen, Zilin and Karim, Imtiaz and Bertino, Elisa and Liu, Daiping and Li, Zhou},
  title     = {Mind the Gap: Cross-{RFC} Formal Analysis Exposes {DNSSEC}'s Hidden Vulnerabilities},
  booktitle = {Proceedings of the 2026 ACM SIGSAC Conference on Computer and Communications Security},
  series    = {CCS '26},
  year      = {2026},
  location  = {The Hague, Netherlands},
  publisher = {Association for Computing Machinery},
  address   = {New York, NY, USA},
  doi       = {10.1145/3830454.3846592}
}
```

## License and contact

The artifact is licensed under GPL-3.0-only (see [LICENSE](LICENSE) and
[NOTICE](NOTICE)). For questions, contact Qifan Zhang
(qzhang@paloaltonetworks.com) or Zhou Li (zhou.li@uci.edu, corresponding
author).
