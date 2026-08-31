# Risk Scoring (v1)

Implemented in `backend/app/services/risk_engine.py`. This document and
that module must stay in lockstep — if you change one, change the other,
and update `backend/tests/test_risk_engine.py` to match.

## Inputs

Every `Finding` carries four inputs to the risk engine, all populated by
the scanner module that created it (`app/scanners/base.ScanFinding`),
never left to the risk engine to default silently:

| Input | Range | Meaning |
|---|---|---|
| `severity` | `FindingSeverity` enum | The module's qualitative opinion of the finding (info/low/medium/high/critical) |
| `exposure` | `[0, 1]` | How directly internet-reachable the affected surface is. Phase 1/2 modules only ever look at externally-visible targets, so this defaults to `1.0`; a future module examining something less directly reachable could report lower |
| `exploitability` | `[0, 1]` | How easily this specific finding could be leveraged by an attacker, judged per-finding by the module author (e.g. an expired TLS cert is more directly exploitable than a missing `Referrer-Policy` header) |
| `confidence` | `[0, 1]` | How sure the module is that this finding is real/accurate. **Never omitted from the calculation** — see below |

## Weights

```
WEIGHT_SEVERITY       = 0.5
WEIGHT_EXPOSURE       = 0.2
WEIGHT_EXPLOITABILITY = 0.3
```

These sum to `1.0` (enforced by an assertion in `risk_engine.py`).
Severity is weighted highest because it's the primary signal a security
analyst reads first; exploitability is weighted above exposure because,
given two findings on equally-exposed assets, the one that's easier to
actually leverage matters more for prioritization.

## Normalization

`severity` is mapped onto `[0, 1]` on an evenly-spaced scale:

```
info     -> 0.00
low      -> 0.25
medium   -> 0.50
high     -> 0.75
critical -> 1.00
```

`exposure` and `exploitability` are already stored in `[0, 1]` but are
clamped again defensively before use (`_clamp01`), so a future module
supplying an out-of-range value can't produce an out-of-range score.

## Final score calculation (per finding)

```
base_score = (WEIGHT_SEVERITY * severity_norm
            + WEIGHT_EXPOSURE * exposure_norm
            + WEIGHT_EXPLOITABILITY * exploitability_norm) * 100

finding_risk_score = round(base_score * confidence, 2)
```

`confidence` is applied **last**, as a multiplicative scale on the whole
base score — not blended additively with the other three. This means a
low-confidence finding is pulled toward zero regardless of how severe it
looks otherwise, which is the intended effect: a critical-severity,
fully-exploitable finding the module is only 10% sure about should not
carry the same weight as one it's certain of.

The score is bounded to `[0, 100]` by construction: the weights sum to
`1.0`, every normalized input is clamped to `[0, 1]`, and confidence
(also clamped to `[0, 1]`) can only ever scale the result down, never up.
`confidence = 0` always yields exactly `0`, and the maximum possible
input combination always yields exactly `100`.

## Scan-level aggregate

A scan's overall `risk_score` is **not** an average or sum of its
findings — it's the maximum per-finding score among findings with
severity above `info`:

```
relevant = [f for f in findings if f.severity != info]
risk_score = max(finding_risk_score(f) for f in relevant)  # or 0.0 if relevant is empty
```

**Why `info`-severity findings are excluded from the aggregate:** modules
emit an informational "this ran and here's what it saw" finding on every
successful run (e.g. "DNS records enumerated", "Technology fingerprint
completed") with `severity=info`, `exposure=1.0` (the target is external
by definition), `exploitability=0.0`. If those contributed to the
aggregate the same way real issues do, the `exposure` weight alone would
put a ~20-point floor under every scan's score — including one that found
*zero* actual problems — which would undermine trust in the number. They
still get an individual `finding_risk_score` if computed directly (used
in a report's technical appendix for completeness); they just don't move
the scan-level number.

**Why `max()` and not a sum/average (known v1 limitation):** a scan's
risk is at least as bad as its single worst finding, which is simple,
deterministic, and easy to reason about. It deliberately does not yet
account for *volume* — ten independent `medium` findings currently score
the same as one. A future version could add a bounded "many findings"
adjustment on top of the max, but that needs its own design and tests
rather than being folded in as an untested heuristic now.

## Severity bands

Applied to both the scan-level aggregate and (if computed) an individual
finding's score:

| Score range | Band |
|---|---|
| `[0, 20)` | `minimal` |
| `[20, 40)` | `low` |
| `[40, 60)` | `medium` |
| `[60, 80)` | `high` |
| `[80, 100]` | `critical` |

`RiskSeverityBand` is a distinct enum from `FindingSeverity` (see
`app/core/enums.py`) — the two look similar (five roughly-parallel
levels) but represent different things: `FindingSeverity` is a module's
raw per-finding opinion (an *input*), `RiskSeverityBand` is a
classification of a computed aggregate score (an *output*). Coupling them
to the same enum would mean any future change to one vocabulary silently
affects the other; `RiskSeverityBand` also has `minimal` (a scan with no
meaningful findings) which doesn't map cleanly onto `FindingSeverity`'s
`info` (an observation was made, not "nothing to worry about").

## Examples

**1. Missing HSTS header** (`security_headers` module):
severity=`medium` (0.5), exposure=1.0, exploitability=0.3, confidence=0.9
```
base  = (0.5*0.5 + 0.2*1.0 + 0.3*0.3) * 100 = 54.0
score = 54.0 * 0.9 = 48.6   -> medium band
```

**2. Expired TLS certificate** (`ssl` module):
severity=`critical` (1.0), exposure=1.0, exploitability=0.5, confidence=1.0
```
base  = (0.5*1.0 + 0.2*1.0 + 0.3*0.5) * 100 = 85.0
score = 85.0 * 1.0 = 85.0   -> critical band
```

**3. Missing Content-Security-Policy** (`security_headers` module):
severity=`low` (0.25), exposure=1.0, exploitability=0.2, confidence=0.8
```
base  = (0.5*0.25 + 0.2*1.0 + 0.3*0.2) * 100 = 38.5
score = 38.5 * 0.8 = 30.8   -> low band
```

**4. Same critical finding as #2, but low confidence** — shows how much
confidence alone can move the result: severity=`critical` (1.0),
exposure=1.0, exploitability=1.0, confidence=0.1
```
base  = (0.5*1.0 + 0.2*1.0 + 0.3*1.0) * 100 = 100.0
score = 100.0 * 0.1 = 10.0  -> minimal band
```

**5. Maximum possible score**: severity=`critical`, exposure=1.0,
exploitability=1.0, confidence=1.0 → `score = 100.0` → `critical` band.

**6. Scan with only informational findings** (every module ran, found no
actual issues): `relevant` is empty → `risk_score = 0.0`, band `minimal`.
