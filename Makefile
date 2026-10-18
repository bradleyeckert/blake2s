# make test: build and run the tests. make vectors: regenerate vectors.h
# from Python's hashlib (needs Python 3; the generated file is checked in).

test: test.c src/blake2s.c src/blake2s.h blake2-kat.h vectors.h
	gcc -Wall -Wextra -o test test.c ./src/blake2s.c -I./src
	./test
	gcc -Wall -Wextra -DBLAKE2S_UNROLL -o test test.c ./src/blake2s.c -I./src
	./test

vectors:
	python3 vectors.py > vectors.h

.PHONY: test vectors
