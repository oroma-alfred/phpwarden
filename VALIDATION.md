# Runtime guard — validation

The PHP-FPM runtime guard (`phpwarden-guard` / `python -m phpwarden.guard`) has
been validated **end-to-end against a live php-fpm pool**: it detects a
poisoned-and-reused worker from the pool's own logs and recycles the real worker
process, with its dry-run and patched-host safety latches confirmed.

Reproduce it with:

```bash
PYTHONPATH="$PWD:$PWD/src" python3 tests/test_guard_live.py
```

The test runs a detector unit test always, and the live integration test when a
`php-fpm` binary is present (it is skipped, not failed, otherwise).

## What the guard does

A php2shell-class attack corrupts a PHP-FPM worker's memory and keeps that worker
alive to serve more requests. The guard watches each pool's **access log**
(worker PID + status) and **error log** (fatal / OOM / SIGSEGV), correlates them
per PID, and when a worker takes a fatal and then keeps serving `5xx`
("oom_then_reuse"), it `SIGTERM`s that worker so the FPM master respawns a clean
one. Detection is behavioural; actuation is gated.

## What was validated (against real php-fpm 8.5.12, real workers, real logs)

| Scenario | Expected | Result |
|---|---|---|
| Vulnerable engine, `ENFORCE` | detect + kill the worker; master respawns | ✅ worker `75916` detected (`oom_then_reuse`, 2 anomalies), `WORKER_KILL` executed, respawned as `84705`, audit-logged |
| `DRYRUN` | detect, **do not** kill | ✅ detected, `suppressed_by: dryrun`, worker unchanged |
| Patched engine, `ENFORCE` | detect, **do not** kill (invariant 7) | ✅ `census: PATCHED` → `noop`, worker unchanged |

All P1–P7 promotion guards passed in the enforce run (`promotion_failed: []`),
and the kill was recorded to the audit log:

```json
{"action":"WORKER_KILL","pool":"web-public","pid":75916,
 "event":{"reason":"oom_then_reuse","evidence":{"anomalies":2}},"result":{"ok":true}}
```

## How the test reproduces it (no exploit)

1. Writes a single-worker php-fpm pool config (access log with `%p`/`%s`, error log).
2. Starts a **real** `php-fpm` and drives **real** requests over FastCGI.
3. Reproduces the php2shell observable **benignly**: `boom.php` writes a
   memory-exhaustion fatal line tagged with its own worker PID to the real error
   log, then returns `500` on the same PID — exactly the signal the guard keys
   on. No RCE, no real exploit.
4. Runs `guard.tick(...)` in each mode and asserts the kill / no-kill outcome and
   the worker PID change.

## Honest caveats

- This validates the **guard mechanism**, not a live exploit chain. The engine is
  classified vulnerable via config (the installed PHP is the patched 8.5.12);
  that is the exact condition a real unpatched host produces automatically.
- The poisoning signal is reproduced benignly (see above), not by running
  php2shell.
- Single-worker pool, localhost, canary stubbed with a plain `200`.
- Not yet done (larger, sandboxed): an end-to-end run driven by a **real
  php2shell exploit against a deliberately-vulnerable PHP build**.
