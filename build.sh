#!/bin/bash
#
# Build libpam-web3 and chain backend packages.
#
# Usage:
#   ./build.sh                              # core + all checked-out backends
#   ./build.sh --with-backends=evm,cardano  # core + specific backends
#   ./build.sh --with-backends=none         # core only
#
# Each backend is a subdirectory under plugins/ with a packaging/build-deb.sh.
# By default, every checked-out backend directory that has a build script is built.

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Parse arguments ───────────────────────────────────────────────────

BACKENDS=""
for arg in "$@"; do
    case "$arg" in
        --with-backends=*)
            BACKENDS="${arg#--with-backends=}"
            ;;
        -h|--help)
            echo "Usage: $0 [--with-backends=chain1,chain2,...|none]"
            echo ""
            echo "Builds libpam-web3 core .deb and optionally chain backend .debs."
            echo ""
            echo "Options:"
            echo "  --with-backends=LIST   Comma-separated list of backends to build"
            echo "                         Use 'none' to skip backends entirely"
            echo "                         Default: build all checked-out backends"
            echo ""
            echo "Any name is accepted — it just needs plugins/<name>/packaging/build-deb.sh."
            echo ""
            echo "Currently checked out:"
            for d in "$PROJECT_DIR"/plugins/*/packaging/build-deb.sh; do
                [ -f "$d" ] && echo "  $(basename "$(dirname "$(dirname "$d")")")"
            done
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Use --help for usage."
            exit 1
            ;;
    esac
done

# ── Discover backends ─────────────────────────────────────────────────

if [ "$BACKENDS" = "none" ]; then
    BACKEND_LIST=()
elif [ -n "$BACKENDS" ]; then
    IFS=',' read -ra BACKEND_LIST <<< "$BACKENDS"
    for b in "${BACKEND_LIST[@]}"; do
        if [ ! -f "$PROJECT_DIR/plugins/$b/packaging/build-deb.sh" ]; then
            echo "ERROR: No build script at plugins/$b/packaging/build-deb.sh"
            exit 1
        fi
    done
else
    # Default: all checked-out backends with a build script
    BACKEND_LIST=()
    for d in "$PROJECT_DIR"/plugins/*/packaging/build-deb.sh; do
        [ -f "$d" ] || continue
        chain="$(basename "$(dirname "$(dirname "$d")")")"
        BACKEND_LIST+=("$chain")
    done
fi

# ── Build core ────────────────────────────────────────────────────────

echo "=== Building libpam-web3 core ==="
"$PROJECT_DIR/packaging/build-deb.sh"
echo ""

# ── Build backends ────────────────────────────────────────────────────

if [ ${#BACKEND_LIST[@]} -eq 0 ]; then
    echo "No backends to build."
else
    echo "=== Building backends: ${BACKEND_LIST[*]} ==="
    echo ""
    for chain in "${BACKEND_LIST[@]}"; do
        echo "--- Building $chain ---"
        "$PROJECT_DIR/plugins/$chain/packaging/build-deb.sh"
        echo ""
    done
fi

# ── Summary ───────────────────────────────────────────────────────────

echo "=== Build complete ==="
echo ""
echo "Packages:"
ls -1h "$PROJECT_DIR"/packaging/*.deb 2>/dev/null || true
for chain in "${BACKEND_LIST[@]}"; do
    ls -1h "$PROJECT_DIR/plugins/$chain/packaging/"*.deb 2>/dev/null || true
done
