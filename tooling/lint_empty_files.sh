#!/usr/bin/env sh
set -eu

echo "[lint] Checking for empty or invalid placeholder files..."

FAIL=0

# Find tracked files only
git ls-files | while read -r file; do
    # Skip binary files
    case "$file" in
        *.png|*.jpg|*.jpeg|*.gif|*.wasm|*.zip) continue ;;
    esac

    # Allow .keep files
    if [ "$(basename "$file")" = ".keep" ]; then
        continue
    fi

    # Skip directories
    [ -f "$file" ] || continue

    # Check zero-byte files
    if [ ! -s "$file" ]; then
        echo "❌ EMPTY FILE: $file"
        FAIL=1
        continue
    fi

    # Check Rust placeholders
    case "$file" in
        *.rs)
            if ! grep -Eq '(//!|///|unimplemented!|panic!|forbid\(unsafe_code\))' "$file"; then
                echo "❌ INVALID PLACEHOLDER (Rust): $file"
                FAIL=1
            fi
        ;;
    esac
done

if [ "$FAIL" -ne 0 ]; then
    echo "[lint] ❌ Empty file lint FAILED"
    exit 1
fi

echo "[lint] ✅ Empty file lint PASSED"
