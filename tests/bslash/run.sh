#!/bin/sh

set -eu

CHS_BIN="../CHS/build/chs"
EXTERN_MAIN="../../BSlash/bas/tests/extern_main.bas"
EXTERN_HELPER="../../BSlash/bas/tests/extern_helper.bas"

cc -std=c11 -O2 tests/bslash/bso_fixture.c -o build/bso_fixture

if [ ! -x "$CHS_BIN" ]; then
	make -C ../CHS >/dev/null
fi

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

"$CHS_BIN" --arch bslash --format macho --output build/roundtrip-main-macho.o "$EXTERN_MAIN"
"$CHS_BIN" --arch bslash --format macho --output build/roundtrip-helper-macho.o "$EXTERN_HELPER"
./build/cld link build/roundtrip-main-macho.o build/roundtrip-helper-macho.o -o build/roundtrip-macho.bso --output-kind relocatable --target bslash -nostdlib
./build/bso_fixture check-roundtrip-bso build/roundtrip-macho.bso
./build/cld link build/roundtrip-macho.bso -o build/roundtrip-macho.bin --output-kind executable --target bslash -nostdlib
./build/bso_fixture check-roundtrip-bin build/roundtrip-macho.bin

"$CHS_BIN" --arch bslash --format elf64 --output build/roundtrip-main-elf.o "$EXTERN_MAIN"
"$CHS_BIN" --arch bslash --format elf64 --output build/roundtrip-helper-elf.o "$EXTERN_HELPER"
./build/cld link build/roundtrip-main-elf.o build/roundtrip-helper-elf.o -o build/roundtrip-elf.bso --output-kind relocatable --target bslash -nostdlib
./build/bso_fixture check-roundtrip-bso build/roundtrip-elf.bso
./build/cld link build/roundtrip-elf.bso -o build/roundtrip-elf.bin --output-kind executable --target bslash -nostdlib
./build/bso_fixture check-roundtrip-bin build/roundtrip-elf.bin

echo "BSlash tests passed"