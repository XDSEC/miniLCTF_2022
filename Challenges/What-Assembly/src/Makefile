EXPORTS=-s EXPORTED_RUNTIME_METHODS='["intArrayFromString", "allocate", "ALLOC_STACK"]'

all:
	emcc --bind check.c -s WASM=1 -o flag.html $(EXPORTS) -g2
	rm flag.html