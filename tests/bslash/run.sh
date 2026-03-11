#!/bin/sh

set -eu

cc -std=c11 -O2 tests/bslash/bso_fixture.c -o build/bso_fixture

./build/bso_fixture emit-abs-ref build/bslash-ref.bso
./build/bso_fixture emit-target build/bslash-target.bso
./build/bso_fixture emit-dup-a build/bslash-dup-a.bso
./build/bso_fixture emit-dup-b build/bslash-dup-b.bso

./build/cld link build/bslash-ref.bso build/bslash-target.bso -o build/bslash-merged.bso --output-kind relocatable --target bslash
./build/bso_fixture check-merged build/bslash-merged.bso

./build/cld link build/bslash-ref.bso build/bslash-target.bso -o build/bslash.bin --output-kind executable --target bslash
./build/bso_fixture check-bin build/bslash.bin

if ./build/cld link build/bslash-ref.bso -o build/bslash-unresolved.bin --output-kind executable --target bslash >build/bslash-unresolved.stdout 2>build/bslash-unresolved.stderr; then
	echo "expected unresolved BSlash link to fail" >&2
	exit 1
fi
grep -F "undefined symbol target" build/bslash-unresolved.stderr >/dev/null

if ./build/cld link build/bslash-dup-a.bso build/bslash-dup-b.bso -o build/bslash-dup.bso --output-kind relocatable --target bslash >build/bslash-dup.stdout 2>build/bslash-dup.stderr; then
	echo "expected duplicate BSlash symbol link to fail" >&2
	exit 1
fi
grep -F "multiple definitions of symbol dup" build/bslash-dup.stderr >/dev/null

echo "BSlash tests passed"