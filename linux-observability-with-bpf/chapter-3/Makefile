CLANG = clang

INCLUDE_PATH += -I/usr/src/linux-source-6.2.0/linux-source-6.2.0/tools/lib/bpf

LIBRARY_PATH = -L/usr/lib/x86_64-linux-gnu
BPFSO = -lbpf
C_FLAG = -g

.PHONY: clean 

clean:
	rm -f fetch save

fetch: 	03map_pinning_fetch.c 
	clang -o fetch -lelf $(INCLUDE_PATH) $(LIBRARY_PATH) $(BPFSO) $(C_FLAG) $?

save: 	02map_pinning_save.c
	clang -o save -lelf $(INCLUDE_PATH) $(LIBRARY_PATH) $(BPFSO) $(C_FLAG) $?

build: fetch save

.DEFAULT_GOAL := build
