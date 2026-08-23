#!/usr/bin/env bash
#
# test_check_did_submodules.sh - fixture-based self-test for the SEC-003
# parity guard. Builds throwaway git repositories in a temp directory and
# asserts the exit codes and output of scripts/check_did_submodules.sh.
# Exits non-zero if any assertion fails.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$HERE/check_did_submodules.sh"

PASS_COUNT=0
FAIL_COUNT=0

note() { printf '%s\n' "$*"; }

cleanup() {
	if [ -n "${SANDBOX:-}" ] && [ -d "${SANDBOX:-}" ]; then
		rm -rf "$SANDBOX"
	fi
}
trap cleanup EXIT

report() {
	local name="$1" expected_rc="$2" actual_rc="$3" expect_grep="${4:-}" combined="${5:-}"
	local ok=1
	if [ "$expected_rc" != "$actual_rc" ]; then
		ok=0
		note "  [FAIL] $name (expected exit $expected_rc, got $actual_rc)"
	elif [ -n "$expect_grep" ] && ! printf '%s' "$combined" | grep -q -- "$expect_grep"; then
		ok=0
		note "  [FAIL] $name (exit ok but output missing pattern: $expect_grep)"
	fi
	if [ "$ok" = "1" ]; then
		PASS_COUNT=$((PASS_COUNT + 1))
		note "  [ok] $name (exit $actual_rc)"
	else
		FAIL_COUNT=$((FAIL_COUNT + 1))
		printf '%s\n' "$combined" | sed 's/^/      | /'
	fi
}

commit_file() {
	local dir="$1" msg="$2"
	git -C "$dir" add -A
	git -C "$dir" -c user.email=parity-test@local -c user.name=parity-test commit -q -m "$msg"
}

new_repo() {
	local dir="$1"
	git init -q "$dir"
	echo "seed-$RANDOM-$RANDOM" >"$dir/file.txt"
	commit_file "$dir" "init"
}

attach_submodule() {
	local parent="$1" subpath="$2" child="$3" sha="$4"
	git clone -q "$child" "$parent/$subpath"
	git -C "$parent/$subpath" checkout -q "$sha" 2>/dev/null
	git -C "$parent" update-index --add --cacheinfo "160000,$sha,$subpath"
	git -C "$parent" -c user.email=parity-test@local -c user.name=parity-test commit -q -m "pin $subpath at ${sha:0:12}"
}

head_of() {
	git -C "$1" rev-parse HEAD
}

build_fixture() {
	local sb="$1" canonical_advance="${2:-no}"

	new_repo "$sb/did_rust"
	echo advance >>"$sb/did_rust/file.txt"
	commit_file "$sb/did_rust" "second commit"
	FIX_PIN="$(head_of "$sb/did_rust")"
	if [ "$canonical_advance" = "yes" ]; then
		echo ahead >>"$sb/did_rust/file.txt"
		commit_file "$sb/did_rust" "canonical-only commit"
	fi
	FIX_CANON="$(head_of "$sb/did_rust")"
	FIX_CANON_BRANCH="$(git -C "$sb/did_rust" rev-parse --abbrev-ref HEAD)"

	new_repo "$sb/iyou_idp"
	new_repo "$sb/iyou_home"
	attach_submodule "$sb/iyou_idp" "crates/did_rust" "$sb/did_rust" "$FIX_PIN"
	attach_submodule "$sb/iyou_home" "libs/did_rust" "$sb/did_rust" "$FIX_PIN"

	mkdir -p "$sb/iyou_mobile/src-tauri/src"
	cat >"$sb/iyou_mobile/src-tauri/Cargo.toml" <<EOF
[package]
name = "mobile-app"

[dependencies]
did_rust = { path = "../../did_rust" }
EOF
	new_repo "$sb/iyou_mobile"
}

run_checker_in() {
	local sb="$1"
	shift
	bash "$CHECKER" --root "$sb" --canonical "$sb/did_rust" "$@"
}

scenario() {
	local title="$1"
	note ""
	note "scenario: $title"
	SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/did-parity-test.XXXXXX")"
}

end_scenario() {
	rm -rf "$SANDBOX"
	SANDBOX=""
}

case_aligned() {
	scenario "all consumers aligned -> exit 0"
	build_fixture "$SANDBOX" no
	run_case "strict parity passes" 0 "PARITY OK" run_checker_in "$SANDBOX"
	run_case "table lists cargo path dep site" 0 "cargo-path-dep" run_checker_in "$SANDBOX"

	local tmpjson
	tmpjson="$SANDBOX/report.json"
	if run_checker_in "$SANDBOX" --json >"$tmpjson" 2>/dev/null; then
		if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["status"]=="ok", d; assert len(d["sites"])==3, d; print("VALID")' "$tmpjson" >/dev/null 2>&1; then
			PASS_COUNT=$((PASS_COUNT + 1))
			note "  [ok] --json emits valid aligned report (status ok, 3 sites)"
		else
			FAIL_COUNT=$((FAIL_COUNT + 1))
			note "  [FAIL] --json report failed validation:"
			sed 's/^/      | /' <"$tmpjson"
		fi
	else
		FAIL_COUNT=$((FAIL_COUNT + 1))
		note "  [FAIL] --json invocation exited non-zero on aligned fixture"
	fi
	end_scenario
}

case_consumer_drift() {
	scenario "one submodule pointer altered -> exit 1"
	build_fixture "$SANDBOX" no

	new_repo "$SANDBOX/divergent"
	local other
	other="$(head_of "$SANDBOX/divergent")"
	git clone -q "$SANDBOX/divergent" "$SANDBOX/iyou_home/libs/did_rust.new"
	rm -rf "$SANDBOX/iyou_home/libs/did_rust"
	mv "$SANDBOX/iyou_home/libs/did_rust.new" "$SANDBOX/iyou_home/libs/did_rust"
	git -C "$SANDBOX/iyou_home" update-index --add --cacheinfo "160000,$other,libs/did_rust"
	git -C "$SANDBOX/iyou_home" -c user.email=parity-test@local -c user.name=parity-test commit -q -m "repoint libs/did_rust to divergent commit"

	run_case "diverged pins exit 1" 1 "DIFFERENT did_rust commits" run_checker_in "$SANDBOX"
	end_scenario
}

case_worktree_pin_skew() {
	scenario "submodule worktree not at pinned commit -> exit 1"
	build_fixture "$SANDBOX" no
	git -C "$SANDBOX/iyou_idp/crates/did_rust" checkout -q "$FIX_PIN^"
	run_case "worktree/pin skew exits 1" 1 "differs from committed submodule pin" run_checker_in "$SANDBOX"
	end_scenario
}

case_uninitialized_submodule() {
	scenario "submodule directory present but uninitialized -> exit 1"
	build_fixture "$SANDBOX" no
	rm -rf "$SANDBOX/iyou_idp/crates/did_rust"
	mkdir "$SANDBOX/iyou_idp/crates/did_rust"
	run_case "uninitialized submodule exits 1" 1 "submodule not initialized" run_checker_in "$SANDBOX"
	end_scenario
}

case_missing_consumer() {
	scenario "consumer repository missing -> exit 1 with environment detail"
	build_fixture "$SANDBOX" no
	mv "$SANDBOX/iyou_mobile" "$SANDBOX/iyou_mobile.gone"
	run_case "missing iyou_mobile exits 1" 1 "consumer repository not found" run_checker_in "$SANDBOX"
	end_scenario
}

case_canonical_ahead() {
	scenario "consumers lag canonical by ancestor commits"
	build_fixture "$SANDBOX" no

	git clone -q "$SANDBOX/did_rust" "$SANDBOX/did_rust_pinned"
	git -C "$SANDBOX/did_rust_pinned" checkout -q "$FIX_PIN"
	cat >"$SANDBOX/iyou_mobile/src-tauri/Cargo.toml" <<EOF
[dependencies]
did_rust = { path = "../../did_rust_pinned" }
EOF
	commit_file "$SANDBOX/iyou_mobile" "pin mobile via mirror clone"

	echo ahead >>"$SANDBOX/did_rust/file.txt"
	commit_file "$SANDBOX/did_rust" "canonical-only commit"
	FIX_CANON="$(head_of "$SANDBOX/did_rust")"

	run_case "strict mode blocks staged rollout" 1 "behind" run_checker_in "$SANDBOX"
	run_case "tolerant mode warns and passes" 0 "Tolerated" run_checker_in "$SANDBOX" --tolerate-canonical-ahead
	end_scenario
}

case_pre_push() {
	scenario "pre-push hook mode"
	build_fixture "$SANDBOX" yes

	git -C "$SANDBOX/did_rust" checkout -q --orphan rewritten-history
	echo orphan >"$SANDBOX/did_rust/orphan.txt"
	commit_file "$SANDBOX/did_rust" "rewritten unrelated history"
	local orphan
	orphan="$(head_of "$SANDBOX/did_rust")"
	git -C "$SANDBOX/did_rust" checkout -q "$FIX_CANON_BRANCH"

	run_case "pushing canonical head keeps pins reachable" 0 "PRE-PUSH OK" \
		run_checker_in "$SANDBOX" --pre-push "$FIX_CANON"
	run_case "orphaned history rejected" 1 "orphan the consumer pin" \
		run_checker_in "$SANDBOX" --pre-push "$orphan"
	end_scenario
}

case_usage_errors() {
	scenario "environment/usage errors exit 2"
	build_fixture "$SANDBOX" no
	run_case "unknown root exits 2" 2 "workspace root does not exist" \
		run_checker_in "$SANDBOX" --root "$SANDBOX/does-not-exist"
	run_case "invalid pre-push sha exits 2" 2 "not a valid commit" \
		run_checker_in "$SANDBOX" --pre-push deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
	end_scenario
}

run_case() {
	local name="$1" expected_rc="$2" expect_grep="${3:-}"
	shift 3
	if [ "${1:-}" = "run_checker_in" ]; then
		shift
	fi
	local out rc
	out="$(run_checker_in "$@" 2>&1)"
	rc=$?
	report "$name" "$expected_rc" "$rc" "$expect_grep" "$out"
}

main() {
	note "checker under test: $CHECKER"
	case_aligned
	case_consumer_drift
	case_worktree_pin_skew
	case_uninitialized_submodule
	case_missing_consumer
	case_canonical_ahead
	case_pre_push
	case_usage_errors

	note ""
	if [ "$FAIL_COUNT" -eq 0 ]; then
		note "SELF-TEST PASSED: $PASS_COUNT assertion(s) verified"
		exit 0
	fi
	note "SELF-TEST FAILED: $FAIL_COUNT failed, $PASS_COUNT passed"
	exit 1
}

main "$@"
