#!/bin/sh
# Rerun the GitHub study: scan the root composer.lock of the 1,000 most-starred
# PHP repositories. Needs gh (logged in), curl, python3 and phpwarden on PATH.
# Output stays in a temp dir; agg.py prints aggregate numbers and writes
# per_repo.json there. Results change daily as projects and feeds change.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"; W="$(mktemp -d)"; cd "$W"; mkdir -p locks scans work
for page in 1 2 3 4 5 6 7 8 9 10; do
  gh api -X GET search/repositories -f q='language:PHP stars:>300 archived:false' -f sort=stars \
    -f order=desc -f per_page=100 -f page=$page \
    -q '.items[] | [.full_name, .stargazers_count, .default_branch, .pushed_at, .fork] | @tsv' >> repos.tsv
  sleep 2
done
awk -F'\t' '$5=="false"{print $1"\t"$3}' repos.tsv | while IFS="$(printf '\t')" read -r r b; do
  f="locks/$(echo "$r" | tr / _).lock"; curl -sfL "https://raw.githubusercontent.com/$r/$b/composer.lock" -o "$f" || rm -f "$f"
done
: > withlock.tsv; : > lockdates.tsv
while IFS="$(printf '\t')" read -r r s b p fk; do
  k="$(echo "$r" | tr / _)"; [ -f "locks/$k.lock" ] || continue
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "$r" "$s" "$b" "$p" "$fk" >> withlock.tsv
  d="$(gh api "repos/$r/commits?path=composer.lock&sha=$b&per_page=1" -q '.[0].commit.committer.date')"
  printf '%s\t%s\n' "$k" "$d" >> lockdates.tsv
  mkdir -p "work/$k"; cp "locks/$k.lock" "work/$k/composer.lock"
  phpwarden deps "work/$k/composer.lock" --json --no-reachability > "scans/$k.json" 2>/dev/null || true
done < repos.tsv
python3 -I "$HERE/agg.py"
echo "work dir: $W"
