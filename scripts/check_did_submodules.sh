#!/usr/bin/env bash
#
# check_did_submodules.sh - SEC-003 submodule parity guard for did_rust
#
# Verifies that every consumer repository resolves the SAME did_rust commit.
# Commit divergence between consumers causes silent serialization mismatch
# and handshake failures across iyou_idp, iyou_home and iyou_mobile.
#
# Consumers inspected (relative to the workspace root):
#   iyou_idp/crates/did_rust    git submodule
#   iyou_home/libs/did_rust     git submodule
#   iyou_mobile                 git submodule at iyou_mobile/did_rust OR
#                               Cargo path dependency (src-tauri/Cargo.toml)
#
# Exit codes:
#   0  all participants aligned on one commit
#   1  parity violation (commit hashes differ, pin orphaned, worktree drift)
#   2  environment error (missing repo, uninitialized submodule, bad usage)

set -euo pipefail

EXIT_OK=0
EXIT_PARITY=1
EXIT_ENV=2

PROGRAM_NAME="check_did_submodules.sh"
DEFAULT_SUBMODULE_MODE="160000"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${PARITY_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
CANONICAL_DIR="${PARITY_CANONICAL_DIR:-$SCRIPT_DIR/..}"

MODE="strict"
OUTPUT_JSON=0
QUIET=0
PUSH_SHA=""

usage() {
	cat <<EOF
Usage: $PROGRAM_NAME [options]

Verifies that iyou_idp, iyou_home and iyou_mobile all resolve the same
did_rust commit. Exits non-zero on any divergence (SEC-003).

Options:
  --root PATH                Workspace root containing the consumer repos
                             (default: \$PARITY_ROOT or two levels above this script)
  --canonical PATH           Path to the canonical did_rust checkout
                             (default: \$PARITY_CANONICAL_DIR or this repository)
  --tolerate-canonical-ahead Allow consumers to lag behind the canonical
                             checkout when their pin is an ancestor of it
                             (staged-rollout mode; consumers must still agree)
  --pre-push SHA             Hook mode: require every resolved did_rust commit
                             to be reachable from SHA (blocks orphaning pins)
  --json                     Emit machine-readable JSON report
  --quiet                    Only print failures and the final verdict
  -h, --help                 Show this help

Environment overrides: PARITY_ROOT, PARITY_CANONICAL_DIR
Exit codes: 0 aligned, 1 parity violation, 2 environment/usage error
EOF
}

log() {
	if [ "$QUIET" -ne 1 ]; then
		printf '%s\n' "$*"
	fi
	return 0
}

die_env() {
	printf 'ERROR: %s\n' "$*" >&2
	exit "$EXIT_ENV"
}

usage_error() {
	usage >&2
	exit "$EXIT_ENV"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--root)
		[ $# -ge 2 ] || usage_error "missing value for $1"
		ROOT="$2"
		shift 2
		;;
	--canonical)
		[ $# -ge 2 ] || usage_error "missing value for $1"
		CANONICAL_DIR="$2"
		shift 2
		;;
	--tolerate-canonical-ahead)
		MODE="tolerant"
		shift
		;;
	--pre-push)
		[ $# -ge 2 ] || usage_error "missing value for $1"
		PUSH_SHA="$2"
		MODE="pre-push"
		shift 2
		;;
	--json)
		OUTPUT_JSON=1
		shift
		;;
	--quiet)
		QUIET=1
		shift
		;;
	-h | --help)
		usage
		exit "$EXIT_OK"
		;;
	*)
		usage_error "unknown option: $1"
		;;
	esac
done

[ -d "$ROOT" ] || die_env "workspace root does not exist: $ROOT"
CANONICAL_DIR="$(cd "$CANONICAL_DIR" && pwd)"

if [ "$OUTPUT_JSON" -eq 1 ]; then
	QUIET=1
fi

if [ "$MODE" = "pre-push" ]; then
	git -C "$CANONICAL_DIR" rev-parse --verify "${PUSH_SHA}^{commit}" >/dev/null 2>&1 ||
		die_env "--pre-push value is not a valid commit reachable from $CANONICAL_DIR: $PUSH_SHA"
else
	CANONICAL_HEAD="$(git -C "$CANONICAL_DIR" rev-parse HEAD 2>/dev/null)" ||
		die_env "canonical did_rust checkout is not a git repository: $CANONICAL_DIR"
fi

SITES_NAMES=()
SITES_TYPES=()
SITES_PATHS=()
SITES_RECORDED=()
SITES_WORKTREE=()
SITES_EFFECTIVE=()
VIOLATIONS=()

emit_site() {
	SITES_NAMES+=("$1")
	SITES_TYPES+=("$2")
	SITES_PATHS+=("$3")
	SITES_RECORDED+=("$4")
	SITES_WORKTREE+=("$5")
	SITES_EFFECTIVE+=("$6")
}

add_violation() {
	VIOLATIONS+=("$1")
	printf 'PARITY VIOLATION: %s\n' "$1" >&2
}

cargo_did_rust_path() {
	local repo="$1" manifest="" rel="" depdir=""
	manifest="$(find "$repo" -maxdepth 3 -name Cargo.toml -not -path '*/target/*' 2>/dev/null |
		while read -r f; do
			if grep -Eq '^[[:space:]]*did[-_]rust[[:space:]]*=' "$f" 2>/dev/null &&
				grep -Eq 'did[-_]rust[^=]*=.*path[[:space:]]*=' "$f" 2>/dev/null; then
				printf '%s\n' "$f"
				break
			fi
		done)"
	[ -n "$manifest" ] || return 1
	rel="$(grep -E '^[[:space:]]*did[-_]rust[[:space:]]*=' "$manifest" |
		sed -E 's/.*path[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/' | head -n 1)"
	[ -n "$rel" ] || return 1
	depdir="$(cd "$(dirname "$manifest")" && cd "$rel" 2>/dev/null && pwd)" || return 1
	printf '%s\n' "$depdir"
}

resolve_consumer() {
	local label="$1" repo_rel="$2" sub_rel="$3"
	local repo="$ROOT/$repo_rel"
	local worktree="" recorded="" recorded_mode="" wt_head=""

	if [ ! -d "$repo" ]; then
		add_violation "$label: consumer repository not found at $repo"
		emit_site "$label" "missing" "$repo" "none" "none" "unresolvable"
		return 0
	fi
	if ! git -C "$repo" rev-parse --verify HEAD >/dev/null 2>&1; then
		add_violation "$label: $repo is not a usable git repository"
		emit_site "$label" "broken-repo" "$repo" "none" "none" "unresolvable"
		return 0
	fi

	if [ "$sub_rel" != "-" ] && [ -d "$repo/$sub_rel" ]; then
		worktree="$repo/$sub_rel"
		local recorded_line="" worktree_phys="" worktree_top=""
		worktree_phys="$(cd "$worktree" && pwd -P)"
		recorded_line="$(git -C "$repo" ls-tree HEAD -- "$sub_rel" 2>/dev/null | head -n 1)"
		recorded_mode="$(printf '%s' "$recorded_line" | awk '{print $1}')"
		recorded="$(printf '%s' "$recorded_line" | awk '{print $3}')"

		wt_head=""
		if ! wt_head="$(git -C "$worktree" rev-parse HEAD 2>/dev/null)"; then
			wt_head=""
		fi
		worktree_top="$(git -C "$worktree" rev-parse --show-toplevel 2>/dev/null || true)"
		if [ -z "$wt_head" ] || [ "$worktree_top" != "$worktree_phys" ]; then
			add_violation "$label: submodule not initialized at $worktree (fix: git -C $repo submodule update --init $sub_rel)"
			emit_site "$label" "submodule-uninitialized" "$worktree" "${recorded:-none}" "none" "unresolvable"
			return 0
		fi

		if [ "$recorded_mode" = "$DEFAULT_SUBMODULE_MODE" ] && [ -n "$recorded" ]; then
			if [ "$wt_head" != "$recorded" ]; then
				add_violation "$label: checked-out worktree ($wt_head) differs from committed submodule pin ($recorded) at $worktree (fix: git -C $repo submodule update $sub_rel)"
			fi
			emit_site "$label" "submodule" "$worktree" "$recorded" "$wt_head" "$recorded"
		else
			emit_site "$label" "vendored-checkout" "$worktree" "none" "$wt_head" "$wt_head"
		fi
		return 0
	fi

	if depdir="$(cargo_did_rust_path "$repo")"; then
		if wt_head="$(git -C "$depdir" rev-parse HEAD 2>/dev/null)"; then
			emit_site "$label" "cargo-path-dep" "$depdir" "none" "$wt_head" "$wt_head"
		else
			add_violation "$label: cargo path dependency target is not a git repository: $depdir"
			emit_site "$label" "cargo-path-dep-broken" "$depdir" "none" "none" "unresolvable"
		fi
		return 0
	fi

	if [ "$sub_rel" != "-" ]; then
		add_violation "$label: neither submodule directory nor cargo path dependency found under $repo (expected $repo/$sub_rel)"
	else
		add_violation "$label: no did_rust consumption point found under $repo (no $repo/$sub_rel and no did_rust cargo path dependency)"
	fi
	emit_site "$label" "unresolved" "$repo" "none" "none" "unresolvable"
}

resolve_consumer "iyou_idp" "iyou_idp" "crates/did_rust"
resolve_consumer "iyou_home" "iyou_home" "libs/did_rust"
resolve_consumer "iyou_mobile" "iyou_mobile" "did_rust"

site_count=${#SITES_NAMES[@]}
if [ "$site_count" -eq 0 ]; then
	die_env "no consumers could be resolved under root $ROOT"
fi

print_table() {
	log ""
	log "did_rust commit parity report (SEC-003)"
	log "root:      $ROOT"
	if [ "$MODE" = "pre-push" ]; then
		log "canonical: (pre-push mode, validating against $PUSH_SHA)"
	else
		log "canonical: $CANONICAL_DIR @ ${CANONICAL_HEAD:0:12}"
	fi
	log ""
	log "SITE         TYPE                     EFFECTIVE    RECORDED     PATH"
	i=0
	while [ "$i" -lt "$site_count" ]; do
		printf '%-12s %-24s %-12s %-12s %s\n' \
			"${SITES_NAMES[$i]}" \
			"${SITES_TYPES[$i]}" \
			"${SITES_EFFECTIVE[$i]:0:12}" \
			"${SITES_RECORDED[$i]:0:12}" \
			"${SITES_PATHS[$i]}" | log_cat
		i=$((i + 1))
	done
	log ""
}

log_cat() {
	while IFS= read -r line; do log "$line"; done
}

collect_effectives() {
	effects=""
	i=0
	while [ "$i" -lt "$site_count" ]; do
		effects="$effects ${SITES_EFFECTIVE[$i]}"
		i=$((i + 1))
	done
	printf '%s\n' "$effects"
}

json_escape() {
	printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' ' | sed -e 's/[[:space:]]*$//'
}

emit_json() {
	local status="$1" out="" i=0
	out="{\"status\":\"$status\",\"mode\":\"$MODE\",\"root\":\"$(json_escape "$ROOT")\",\"canonical\":"
	if [ "$MODE" = "pre-push" ]; then
		out="${out}\"$PUSH_SHA\""
	else
		out="${out}\"$CANONICAL_HEAD\""
	fi
	out="${out},\"sites\":["
	i=0
	while [ "$i" -lt "$site_count" ]; do
		if [ "$i" -gt 0 ]; then
			out="${out},"
		fi
		out="${out}{\"name\":\"${SITES_NAMES[$i]}\",\"type\":\"${SITES_TYPES[$i]}\",\"path\":\"$(json_escape "${SITES_PATHS[$i]}")\",\"recorded\":\"${SITES_RECORDED[$i]}\",\"worktree\":\"${SITES_WORKTREE[$i]}\",\"effective\":\"${SITES_EFFECTIVE[$i]}\"}"
		i=$((i + 1))
	done
	out="${out}],\"violations\":["
	i=0
	while [ "$i" -lt "${#VIOLATIONS[@]}" ]; do
		if [ "$i" -gt 0 ]; then
			out="${out},"
		fi
		out="${out}\"$(json_escape "${VIOLATIONS[$i]}")\""
		i=$((i + 1))
	done
	out="${out}]}"
	printf '%s\n' "$out"
}

if [ "$MODE" = "pre-push" ]; then
	print_table
	i=0
	while [ "$i" -lt "$site_count" ]; do
		sha="${SITES_EFFECTIVE[$i]}"
		if [ "$sha" != "unresolvable" ]; then
			if ! git -C "$CANONICAL_DIR" merge-base --is-ancestor "$sha" "$PUSH_SHA" >/dev/null 2>&1; then
				add_violation "${SITES_NAMES[$i]} pins did_rust commit ${sha} which is NOT reachable from pushed commit ${PUSH_SHA}; pushing would orphan the consumer pin (rebase/force-push rejected)"
			fi
		fi
		i=$((i + 1))
	done
else
	print_table

	has_unresolvable=0
	i=0
	while [ "$i" -lt "$site_count" ]; do
		case "${SITES_EFFECTIVE[$i]}" in
		unresolvable) has_unresolvable=1 ;;
		esac
		i=$((i + 1))
	done

	consumer_shas_are_uniform() {
		[ "$(printf '%s\n' $(collect_effectives) | sort -u | wc -l | tr -d ' ')" = "1" ]
	}

	if [ "$has_unresolvable" -eq 0 ] && ! consumer_shas_are_uniform; then
		dupes="$(collect_effectives | tr ' ' '\n' | sort | uniq -c | sort -rn | while read -r c sha; do
			if [ -n "$sha" ]; then
				printf '  %dx %s\n' "$c" "$sha"
			fi
		done)"
		add_violation "consumers resolve to DIFFERENT did_rust commits:
$dupes
This causes silent serialization mismatch and handshake failures across iyou_idp/iyou_home/iyou_mobile."
	elif [ "$has_unresolvable" -eq 0 ]; then
		pin="${SITES_EFFECTIVE[0]}"
		if [ "$pin" != "$CANONICAL_HEAD" ]; then
			if [ "$MODE" = "tolerant" ] && git -C "$CANONICAL_DIR" merge-base --is-ancestor "$pin" "$CANONICAL_HEAD" >/dev/null 2>&1; then
				ahead="$(git -C "$CANONICAL_DIR" rev-list --count "$pin..$CANONICAL_HEAD")"
				log "WARNING: consumers are aligned at $pin, canonical checkout is $ahead commit(s) ahead ($CANONICAL_HEAD)."
				log "         Tolerated (--tolerate-canonical-ahead). To converge: git -C <parent> submodule update --remote --merge"
			else
				relation="diverged from"
				if git -C "$CANONICAL_DIR" merge-base --is-ancestor "$pin" "$CANONICAL_HEAD" >/dev/null 2>&1; then
					relation="behind"
				elif git -C "$CANONICAL_DIR" merge-base --is-ancestor "$CANONICAL_HEAD" "$pin" >/dev/null 2>&1; then
					relation="ahead of"
				fi
				add_violation "all consumers align at $pin but the canonical did_rust checkout is $CANONICAL_HEAD ($relation the canonical checkout). Local builds do not exercise what ships. Align the canonical checkout or bump the consumer pins."
			fi
		fi
	fi
fi

if [ "${#VIOLATIONS[@]}" -eq 0 ]; then
	if [ "$OUTPUT_JSON" -eq 1 ]; then
		emit_json "ok"
	fi
	if [ "$MODE" = "pre-push" ]; then
		log "PRE-PUSH OK: all consumer did_rust pins are reachable from pushed commit $PUSH_SHA"
	else
		log "PARITY OK: $((site_count + 1)) did_rust sites aligned at ${SITES_EFFECTIVE[0]}"
	fi
	exit "$EXIT_OK"
fi

if [ "$OUTPUT_JSON" -eq 1 ]; then
	emit_json "failed"
fi
log ""
log "PARITY FAILED: ${#VIOLATIONS[@]} violation(s). Release builds and remote deployments are BLOCKED until resolved."
log "Remediation: see docs/strategy/SECURITY_HARDENING.md (SEC-003)."
exit "$EXIT_PARITY"
