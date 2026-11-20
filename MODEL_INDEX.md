# Model index

Paths are relative to `models/`. Property numbers follow the paper. Some lemma
prefixes and model comments use older numbers: for example, `property7_*` in
the cache model is P8, and the "Property 21" comment in `coexistence.spthy` is
P22.

## Properties

Tools, results, and times are as reported in the paper's Table 3 (Google Cloud
c4d-highmem-384, 384 vCPUs, 3,024 GB RAM).

| # | Property | Model | Lemmas or queries | Tool | Result | Time |
| --- | --- | --- | --- | --- | --- | ---: |
| P1 | Cache Hit Semantics | `cache/cache_bounded.spthy` | `property1_cache_hit_implies_store`, `property1_cache_origin_authenticity` | Tamarin | Holds | 2,238 s |
| P2 | Cache Miss Handling | same | `property2_cache_miss_leads_to_store`, `property2_validation_before_store` | Tamarin | Holds | 195 s |
| P3 | Server Partitioning | same | `property3_no_cross_zone_contamination` | Tamarin | Holds | 100 s |
| P4 | Atomic Expiration | same | `property4_expiry_triggers_deletion`, `property4_no_stale_hits_after_expiry` | Tamarin | Holds | 23.8 h |
| P5 | Mutual Exclusion | same | `property5_lock_precedes_unlock` | Tamarin | Holds | 99.4 s |
| P6 | State Visibility | same | `property6_store_happens_before_hit` | Tamarin | Holds | 90.7 h |
| P7 | Validation Segregation | `known_attacks/cd_bit_rucsec.pv` | `event(AttackSuccessful(...))`; in `.spthy`: `validation_segregation_violated` | ProVerif | Violated | <1 s |
| P8 | Termination | `cache/cache_bounded.spthy` | `property7_query_terminates`, `property7_cache_miss_terminates`, `property7_handles_expiration` | Tamarin | Holds¹ | 23.1 h |
| P9 | Resource Reclamation | same | `property8_locks_released_after_response`, `property8_complete_query_cycle` | Tamarin | Holds¹ | 19.3 h |
| P10 | Origin Authentication | `authentication/dnssec_simple.spthy`, `dnssec_full.spthy` | simple: `property11_data_origin_authentication`, `property11_owner_is_signer`; full: `property9_data_origin_authentication`, `property9_owner_signer_match` | Tamarin | Holds | 0.6 s |
| P11 | Record Validation | same | simple: `property11_all_rrsets_signed`; full: `property10_all_rrsets_signed`, `property10_dnskey_signed` | Tamarin | Holds | 0.1 s |
| P12 | Integrity Preservation | same | `property11_no_forgery` (both) | Tamarin | Holds | 0.1 s |
| P13 | Algorithm Integrity | `known_attacks/algorithm_downgrade.pv` | `event(Downgraded(rr))`, `event(Accept(rr)) ==> event(ServerSent(rr))` | ProVerif | Violated | <1 s |
| P14 | Chain Integrity | `authentication/dnssec_simple.spthy`, `dnssec_full.spthy` | `property12_*` (six in simple, four in full) | Tamarin | Holds | 2.1 s |
| P15 | NSEC Executability | `denial_nsec/nsec.spthy` | `ExistExecutability`, `NonExistExecutability` | Tamarin | Holds | 18.3 s |
| P16 | NSEC Domain Secrecy | same | not included² | Tamarin | Violated | 48.7 s |
| P17 | NSEC Result Authentication | same | `IntegrityAll` | Tamarin | Holds | 23.0 s |
| P18 | NSEC3 Executability | `denial_nsec3/nsec3.spthy` | `ExistExecutability`, `NonExistExecutability` | ProVerif³ | Holds | <1 s |
| P19 | NSEC3 Domain Secrecy | same | `domainNameSecrecy` | ProVerif³ | Holds | <1 s |
| P20 | NSEC3 Result Authentication | same | `wholeIntegrity` | ProVerif³ | Holds | <1 s |
| P21 | Wildcard Signer Containment | `rrsig_underflow/rrsig_underflow_vulnerable.spthy` | `zone_boundary_integrity`; attack witness `attack_exists` | ProVerif³ | Violated | <1 s |
| P22 | Denial Exclusivity | `aggressive_caching/coexistence.spthy` | `denial_exclusivity`; attack witness `coexistence_attack_exists` | Tamarin | Violated | 376 s |
| P23 | Validation Preservation | `aggressive_caching/nta_vulnerable.pv` | event queries for denial, injection, caching, and synthesis; in `.spthy`: `attack_with_nta_expiry`⁴ | ProVerif | Violated | <1 s |

1. `exists-trace` reachability checks: progress is possible, not guaranteed
   for every query or lock.
2. `nsec.spthy` encodes owner names as public natural numbers and notes the
   expected violation in comments; the executable secrecy query is not
   included.
3. Checked with ProVerif after exporting the SAPIC+ model.
4. The ordered NTA-expiry witness. The `.pv` queries check event
   co-occurrence, which alone does not establish this ordering.

**Fixed models.** In `rrsig_underflow_secure.spthy`, `zone_boundary_integrity`
should hold and `attack_exists` should find no trace. In
`nta_secure.{spthy,pv}`, the safety lemmas (`no_synthesis_from_nta_cache`,
`attack_not_reachable`, `synthesis_requires_validation`,
`attacker_nsec_not_validated`) should hold, while `nta_bypass_exists` and
`validated_synthesis_exists` stay reachable.

**Auxiliary checks** (not paper properties): `sanity_*` reachability lemmas in
the cache and authentication models; extra witnesses (`attack_reachable`,
`full_attack_sequence`, `cache_poisoning`, `nta_bypass_exists`,
`cache_synthesis_exists`); combined theorems (`full_dnssec_security`,
`dnssec_security_theorem`); the sources lemma `types_cache_store_source`;
helpers `distinctServer`, `distinctResolver`, and `servicePromise`; and, in
both P21 models, `claim_A_all_eight_conditions_satisfied` (records the
abstracted RRSIG conditions without checking them) and
`sanity_honest_signing_keys_secret`.

## Models

| Model | Properties | RFC clauses | Abstractions and omissions |
| --- | --- | --- | --- |
| `cache/cache_bounded.spthy` | P1–P6, P8–P9 | RFC 1034 §5.1; RFC 1035 §§2.2, 6.1.2–6.1.3; RFC 2181 §5.4.1; RFC 4035 §§4.3, 4.5 | Bounded processes; zone-partitioned cache entries with entry-level locks; freshness (active/expired) and validation state per entry; store completion as a restriction. No wall-clock TTLs or eviction. |
| `authentication/dnssec_simple.spthy` | P10–P12, P14 | RFC 4034 §§2, 3, 5; RFC 4035 §§5.2–5.3 | One key per zone, fixed root/TLD/SLD chain, symbolic signatures and DS hashes. |
| `authentication/dnssec_full.spthy` | P10–P12, P14 | Same; RFC 6781 §3 | Static KSK/ZSK split with DNSKEY RRset signing and DS-to-KSK links. No key rollover. |
| `denial_nsec/nsec.spthy` | P15–P17 | RFC 4034 §§4, 6; RFC 4035 §5.4; RFC 4592 §3 | Small fixed zones; owner names are natural numbers in numeric order. Omits wire-format canonical ordering and type bitmaps. |
| `denial_nsec3/nsec3.spthy` | P18–P20 | RFC 5155 §§3–8 | Fresh symbolic names, salted iterated hashing, closest-encloser proofs. Omits opt-out, parameter changes, and offline dictionary attacks. |
| `rrsig_underflow/rrsig_underflow_vulnerable.spthy` | P21 | RFC 4034 §3.1.3; RFC 4035 §§5.3.1–5.3.2; RFC 4592 §3; RFC 8198 §5.3 | Selected names (`attacker.test`, `test`) and label counts. RRSIG conditions 1–5 are recorded without independent checks; condition 6 uses ground bailiwick facts; condition 7 checks a symbolic signature. A cached NSEC stands in for interval coverage and closest-encloser checks. |
| `rrsig_underflow/rrsig_underflow_secure.spthy` | P21 (fix) | Same | Adds the signer-depth guard σ.labels ≥ \|signer(σ)\|. |
| `aggressive_caching/coexistence.spthy` | P22 | RFC 4034 §4; RFC 5155 §§10.4–10.5; RFC 8198 §5 | Static, inconsistent NSEC and NSEC3 views of one zone. Not a dynamic rollover or a concrete signed-proof model. |
| `aggressive_caching/nta_vulnerable.{spthy,pv}` | P23 | RFC 7646 §§1.1, 2, 4; RFC 8198 §5; RFC 4035 §4.3 | NTA active/expired states; unvalidated denial records injected during the NTA and reused for synthesis. No real NTA lifetimes or TTL aging. |
| `aggressive_caching/nta_secure.{spthy,pv}` | P23 (fix) | Same | Separate validated and unvalidated caches; synthesis requires validated records. |
| `known_attacks/algorithm_downgrade.{spthy,pv}` | P13 | RFC 4034 §§2.1.3, 3.1.2; RFC 4035 §5.2; RFC 6840; RFC 8624 §3 | Two symbolic algorithms, one unsupported; an on-path attacker rewrites the algorithm field. |
| `known_attacks/cd_bit_rucsec.{spthy,pv}` | P7 | RFC 4035 §§3.2.2, 4.5 | A CD=1 query caches an unvalidated DNSKEY in a shared cache; a later CD=0 query fails validation. |

## Shared assumptions

- Dolev-Yao network attacker; honest zones' signing keys are not compromised;
  cryptography is symbolic (unforgeable signatures, one-way hashes).
- Fixed zone hierarchies with concrete zone contents; results depend on the
  encoded zones and denial proofs.
- DNS messages keep their sections and selected flags (such as CD and AD) but
  omit lower-layer fields. TTLs are discrete expiration states, and trust
  anchors are static.
- Validation and denial models assume an abstract cache interface (unexpired
  entries, preserved validation state, mutual exclusion). There is no
  machine-checked composition theorem.

Results apply only to the modeled behaviors, not to all DNSSEC executions or to
resolver implementations.
