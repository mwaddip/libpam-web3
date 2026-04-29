#!/bin/bash
#
# Tests for resolve-signing-host.sh — focused on the override branch
# behaviour added for onion-routed deployments.
#
# Runs as a regular user against a tmpdir; overrides the script's output
# and TLS paths via env vars so we don't touch /run or /etc.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/resolve-signing-host.sh"

if [ ! -x "$TARGET" ] && [ ! -r "$TARGET" ]; then
    echo "FAIL: $TARGET not found or not readable"
    exit 1
fi

PASS=0
FAIL=0

# Each test runs in a private tmpdir with isolated paths.
make_env() {
    local d
    d="$(mktemp -d)"
    mkdir -p "$d/run" "$d/tls"
    echo "$d"
}

run_script() {
    local sandbox="$1"
    local override_file="$2"

    SIGNING_HOST_OUTPUT="$sandbox/run/signing_host" \
    SIGNING_HOST_TLS_DIR="$sandbox/tls" \
    SIGNING_HOST_OVERRIDE_FILE="$override_file" \
        bash "$TARGET" >"$sandbox/stdout" 2>"$sandbox/stderr" || true
}

assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "ok - $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL - $name"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local name="$1" needle="$2" haystack="$3"
    case "$haystack" in
        *"$needle"*)
            echo "ok - $name"
            PASS=$((PASS + 1))
            ;;
        *)
            echo "FAIL - $name"
            echo "    expected to contain: $needle"
            echo "    haystack: $haystack"
            FAIL=$((FAIL + 1))
            ;;
    esac
}

# ── 1. Override file with .onion is used verbatim ────────────────────

t1() {
    local sb; sb="$(make_env)"
    local override="$sb/host-address"
    echo "myhost-abc.onion" > "$override"
    run_script "$sb" "$override"
    local got
    got="$(cat "$sb/run/signing_host" 2>/dev/null || echo MISSING)"
    assert_eq "override .onion is written verbatim" "myhost-abc.onion" "$got"
    rm -rf "$sb"
}

# ── 2. Override file with surrounding whitespace is trimmed ───────────

t2() {
    local sb; sb="$(make_env)"
    local override="$sb/host-address"
    printf "  spaced.onion  \n" > "$override"
    run_script "$sb" "$override"
    local got
    got="$(cat "$sb/run/signing_host" 2>/dev/null || echo MISSING)"
    assert_eq "override is trimmed" "spaced.onion" "$got"
    rm -rf "$sb"
}

# ── 3. Override file with comment + value: comment ignored ────────────

t3() {
    local sb; sb="$(make_env)"
    local override="$sb/host-address"
    {
        echo "# This is a comment"
        echo "real.onion"
    } > "$override"
    run_script "$sb" "$override"
    local got
    got="$(cat "$sb/run/signing_host" 2>/dev/null || echo MISSING)"
    assert_eq "comment is ignored, value used" "real.onion" "$got"
    rm -rf "$sb"
}

# ── 4. Override file empty → fall back to discovery ──────────────────

t4() {
    local sb; sb="$(make_env)"
    local override="$sb/host-address"
    : > "$override"  # zero-byte file
    run_script "$sb" "$override"
    local got
    got="$(cat "$sb/run/signing_host" 2>/dev/null || echo MISSING)"
    # We don't assert exact value (depends on host's FQDN/IPs), only
    # that we didn't blank-write and didn't use empty as the override.
    if [ -z "$got" ] || [ "$got" = "MISSING" ]; then
        echo "FAIL - empty override falls back to discovery"
        echo "    output empty or missing: $got"
        FAIL=$((FAIL + 1))
    else
        echo "ok - empty override falls back to discovery (got: $got)"
        PASS=$((PASS + 1))
    fi
    rm -rf "$sb"
}

# ── 5. Override file with only comments → fall back to discovery ──────

t5() {
    local sb; sb="$(make_env)"
    local override="$sb/host-address"
    {
        echo "# nothing real here"
        echo "# only comments"
    } > "$override"
    run_script "$sb" "$override"
    local got
    got="$(cat "$sb/run/signing_host" 2>/dev/null || echo MISSING)"
    case "$got" in
        ""|"MISSING"|*"comment"*|*"#"*)
            echo "FAIL - comments-only override falls back"
            echo "    output: $got"
            FAIL=$((FAIL + 1))
            ;;
        *)
            echo "ok - comments-only override falls back (got: $got)"
            PASS=$((PASS + 1))
            ;;
    esac
    rm -rf "$sb"
}

# ── 6. Override file missing → fall back to discovery ────────────────

t6() {
    local sb; sb="$(make_env)"
    local override="$sb/does-not-exist"
    run_script "$sb" "$override"
    local got
    got="$(cat "$sb/run/signing_host" 2>/dev/null || echo MISSING)"
    if [ -z "$got" ] || [ "$got" = "MISSING" ]; then
        echo "FAIL - missing override file falls back to discovery"
        echo "    output: $got"
        FAIL=$((FAIL + 1))
    else
        echo "ok - missing override file falls back to discovery (got: $got)"
        PASS=$((PASS + 1))
    fi
    rm -rf "$sb"
}

# ── 7. Override case logs that it used the override ──────────────────

t7() {
    local sb; sb="$(make_env)"
    local override="$sb/host-address"
    echo "test.onion" > "$override"
    run_script "$sb" "$override"
    local out
    out="$(cat "$sb/stdout" "$sb/stderr" 2>/dev/null)"
    assert_contains "override case logs source file" "Using override" "$out"
    rm -rf "$sb"
}

# ── 8. Cert SAN reflects the override host ───────────────────────────

t8() {
    if ! command -v openssl >/dev/null 2>&1; then
        echo "ok - cert SAN test (skipped: openssl missing)"
        PASS=$((PASS + 1))
        return
    fi
    local sb; sb="$(make_env)"
    local override="$sb/host-address"
    echo "san-test.onion" > "$override"
    run_script "$sb" "$override"
    if [ ! -f "$sb/tls/cert.pem" ]; then
        echo "FAIL - cert was not generated"
        FAIL=$((FAIL + 1))
        rm -rf "$sb"
        return
    fi
    local sans
    sans="$(openssl x509 -in "$sb/tls/cert.pem" -noout -ext subjectAltName 2>/dev/null)"
    assert_contains "cert SAN includes override host" "san-test.onion" "$sans"
    rm -rf "$sb"
}

# ── Run all ──────────────────────────────────────────────────────────

t1; t2; t3; t4; t5; t6; t7; t8

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
