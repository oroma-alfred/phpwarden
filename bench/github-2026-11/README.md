# GitHub study, November 2026

Scans the root `composer.lock` of the 1,000 most-starred non-archived PHP repositories with phpwarden and prints
aggregate numbers: how many ship a known vulnerability, and how many ship one that is actually exploited (CISA KEV)
or likely to be (EPSS ≥ 50%), split by whether the lockfile changed in the last 12 months.

`sh bench/github-2026-11/run.sh` (needs `gh` logged in, `curl`, `python3`, `phpwarden`).

Per-project results are deliberately not published here. Affected maintainers were notified privately first.
Hits in actively maintained projects should be checked by hand: lockfile scanning cannot see vendor patches.
