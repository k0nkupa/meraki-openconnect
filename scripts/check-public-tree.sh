#!/bin/sh
set -eu

failures=0

generated_pattern='(^|/)(profile\.json|settings\.json|policy\.conf|\.env)$|(^|/)(graphify-out|docs/superpowers/plans|xcuserdata)(/|$)|(^|/)\.derivedData|\.(pem|key)$|(^|/)native/(meraki-openconnect-native|tests/test_(policy|protocol))$'
generated=$(
  git ls-files -z |
    while IFS= read -r -d '' tracked; do
      if printf '%s\n' "$tracked" | grep -Eq "$generated_pattern"; then
        printf '%s\n' "$tracked"
      fi
    done
)
if [ -n "$generated" ]; then
  printf '%s\n' 'generated or private paths are tracked:' >&2
  printf '%s\n' "$generated" >&2
  failures=1
fi

stale=$(
  git grep -I -l -E \
    'bw-vpn|bw_vpn|BW VPN|BWVPN|britwyn|Brittain|Wynyard|Accredo' -- \
    ':!scripts/check-public-tree.sh' || true
)
if [ -n "$stale" ]; then
  printf '%s\n' 'stale private product or organization names were found:' >&2
  printf '%s\n' "$stale" >&2
  failures=1
fi

if [ -n "${MERAKI_OPENCONNECT_PRIVATE_PATTERNS_FILE:-}" ]; then
  source_patterns=$MERAKI_OPENCONNECT_PRIVATE_PATTERNS_FILE
  if [ ! -f "$source_patterns" ] || [ -L "$source_patterns" ]; then
    printf '%s\n' 'private-pattern file is missing or unsafe' >&2
    exit 2
  fi
  filtered_patterns=$(mktemp -t meraki-openconnect-patterns.XXXXXX)
  matches=$(mktemp -t meraki-openconnect-matches.XXXXXX)
  trap '/bin/rm -f "$filtered_patterns" "$matches"' EXIT HUP INT TERM
  awk 'NF && $1 !~ /^#/' "$source_patterns" > "$filtered_patterns"
  if [ -s "$filtered_patterns" ]; then
    private_status=0
    git grep -I -l -E -f "$filtered_patterns" > "$matches" || private_status=$?
    if [ "$private_status" -gt 1 ]; then
      printf '%s\n' 'private-pattern file contains an invalid pattern' >&2
      exit 2
    elif [ -s "$matches" ]; then
      printf '%s\n' 'private deployment patterns were found in tracked files:' >&2
      /bin/cat "$matches" >&2
      failures=1
    fi
  fi
fi

if [ "$failures" -ne 0 ]; then
  exit 1
fi
printf '%s\n' 'public tree check passed'
