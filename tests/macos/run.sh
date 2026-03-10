#!/bin/sh

set -eu

cc -c tests/macos/00/main.c -O3 -ffreestanding -nostdlib -o tests/macos/00/main.o
cc -c tests/macos/01/main.c -O3 -ffreestanding -nostdlib -o tests/macos/01/main.o
cc -c tests/macos/01/test.c -O3 -ffreestanding -nostdlib -o tests/macos/01/test.o
cc -c tests/macos/02/a.c -O3 -ffreestanding -nostdlib -o tests/macos/02/a.o
cc -c tests/macos/02/b.c -O3 -ffreestanding -nostdlib -o tests/macos/02/b.o
cc -c tests/macos/03/main.c -O3 -o tests/macos/03/main.o
cc -c tests/macos/04/main.c -O2 -o tests/macos/04/main.o
cc -c tests/macos/04/io.c -O2 -o tests/macos/04/io.o
cc -c tests/macos/04/story.c -O2 -o tests/macos/04/story.o
cc -c tests/macos/04/endings.c -O2 -o tests/macos/04/endings.o

./build/cld link tests/macos/00/main.o -o build/test-00 --output-kind executable --target macos-arm64
set +e
./build/test-00
status=$?
set -e
if [ "$status" -ne 123 ]; then
	echo "expected build/test-00 to exit 123, got $status" >&2
	exit 1
fi

./build/cld link tests/macos/00/main.o -o build/test-00-nostdlib --output-kind executable --target macos-arm64 -nostdlib
set +e
./build/test-00-nostdlib
status=$?
set -e
if [ "$status" -ne 123 ]; then
	echo "expected build/test-00-nostdlib to exit 123, got $status" >&2
	exit 1
fi
if otool -l build/test-00-nostdlib | grep -F "/usr/lib/libSystem.B.dylib" >/dev/null; then
	echo "expected build/test-00-nostdlib to omit libSystem load commands" >&2
	exit 1
fi

./build/cld link tests/macos/01/main.o tests/macos/01/test.o -o build/test-01.o --output-kind relocatable --target macos-arm64
./build/cld link build/test-01.o -o build/test-01 --output-kind executable --target macos-arm64
set +e
./build/test-01
status=$?
set -e
if [ "$status" -ne 100 ]; then
	echo "expected build/test-01 to exit 100, got $status" >&2
	exit 1
fi

./build/cld link tests/macos/03/main.o -o build/test-03 --output-kind executable --target macos-arm64
set +e
./build/test-03 >build/test-03.log
status=$?
set -e
if [ "$status" -ne 7 ]; then
	echo "expected build/test-03 to exit 7, got $status" >&2
	exit 1
fi
grep -F "hello from printf" build/test-03.log >/dev/null

./build/cld link tests/macos/04/main.o tests/macos/04/io.o tests/macos/04/story.o tests/macos/04/endings.o -o build/test-04 --output-kind executable --target macos-arm64
set +e
printf 'e\nv\n' | ./build/test-04 >build/test-04.log
status=$?
set -e
if [ "$status" -ne 46 ]; then
	echo "expected build/test-04 to exit 46, got $status" >&2
	exit 1
fi
grep -F "The Clockwork Gate" build/test-04.log >/dev/null
grep -F "Ending: Harbor Keeper" build/test-04.log >/dev/null

if ./build/cld link tests/macos/02/a.o tests/macos/02/b.o -o build/test-02.o --output-kind relocatable --target macos-arm64 >build/test-02.log 2>&1; then
	echo "expected duplicate symbol link to fail" >&2
	exit 1
fi

grep -F "multiple definitions of symbol _clash in tests/macos/02/a.o and tests/macos/02/b.o" build/test-02.log >/dev/null

echo "macOS tests passed"