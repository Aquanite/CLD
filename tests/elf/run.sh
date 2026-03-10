#!/bin/sh

set -eu

if ! command -v x86_64-elf-gcc >/dev/null 2>&1; then
	echo "x86_64-elf-gcc is required for ELF tests" >&2
	exit 1
fi
if ! command -v x86_64-elf-readelf >/dev/null 2>&1; then
	echo "x86_64-elf-readelf is required for ELF tests" >&2
	exit 1
fi
if ! command -v x86_64-elf-nm >/dev/null 2>&1; then
	echo "x86_64-elf-nm is required for ELF tests" >&2
	exit 1
fi

x86_64-elf-gcc -c tests/elf/00/main.c -O2 -ffreestanding -nostdlib -o tests/elf/00/main.o
x86_64-elf-gcc -c tests/elf/01/main.c -O2 -ffreestanding -nostdlib -o tests/elf/01/main.o
x86_64-elf-gcc -c tests/elf/01/test.c -O2 -ffreestanding -nostdlib -o tests/elf/01/test.o
x86_64-elf-gcc -c tests/elf/02/a.c -O2 -ffreestanding -nostdlib -o tests/elf/02/a.o
x86_64-elf-gcc -c tests/elf/02/b.c -O2 -ffreestanding -nostdlib -o tests/elf/02/b.o

./build/cld link tests/elf/00/main.o -o build/test-elf-00 --output-kind executable --target x86_64-elf >build/test-elf-00.stdout 2>build/test-elf-00.stderr
grep -F "enabling -nostdlib by default because the current platform is not the target" build/test-elf-00.stderr >/dev/null
x86_64-elf-readelf -h build/test-elf-00 | grep -F "Type:                              EXEC (Executable file)" >/dev/null
x86_64-elf-readelf -h build/test-elf-00 | grep -F "Machine:                           Advanced Micro Devices X86-64" >/dev/null
x86_64-elf-nm build/test-elf-00 | grep -E ' main$' >/dev/null

./build/cld link tests/elf/01/main.o tests/elf/01/test.o -o build/test-elf-01.o --output-kind relocatable --target x86_64-elf >build/test-elf-01-rel.stdout 2>build/test-elf-01-rel.stderr
grep -F "enabling -nostdlib by default because the current platform is not the target" build/test-elf-01-rel.stderr >/dev/null
x86_64-elf-readelf -h build/test-elf-01.o | grep -F "Type:                              REL (Relocatable file)" >/dev/null
x86_64-elf-nm build/test-elf-01.o | grep -E ' main$' >/dev/null
x86_64-elf-nm build/test-elf-01.o | grep -E ' test$' >/dev/null
x86_64-elf-nm build/test-elf-01.o | grep -E ' data$' >/dev/null

./build/cld link build/test-elf-01.o -o build/test-elf-01 --output-kind executable --target x86_64-elf >build/test-elf-01.stdout 2>build/test-elf-01.stderr
grep -F "enabling -nostdlib by default because the current platform is not the target" build/test-elf-01.stderr >/dev/null
x86_64-elf-readelf -h build/test-elf-01 | grep -F "Type:                              EXEC (Executable file)" >/dev/null
x86_64-elf-nm build/test-elf-01 | grep -E ' main$' >/dev/null
x86_64-elf-nm build/test-elf-01 | grep -E ' test$' >/dev/null

if ./build/cld link tests/elf/02/a.o tests/elf/02/b.o -o build/test-elf-02.o --output-kind relocatable --target x86_64-elf >build/test-elf-02.stdout 2>build/test-elf-02.stderr; then
	echo "expected duplicate ELF symbol link to fail" >&2
	exit 1
fi
grep -F "enabling -nostdlib by default because the current platform is not the target" build/test-elf-02.stderr >/dev/null

echo "ELF tests passed"