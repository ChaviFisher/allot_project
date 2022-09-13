CFLAGS_DEBUG := -g -DDEBUG -O0
CFLAGS := -Wall -pthread -fprofile-arcs -ftest-coverage
# -std=c99 -D_POSIX_C_SOURCE=200809L
ifeq ($(DEBUG),1)
  CFLAGS := $(CFLAGS_DEBUG) $(CFLAGS)
endif
main : main.c structs.h
	clang $(CFLAGS) main.c -fopenmp -lpcap -ljson-c -o main -lrt
clean:
	rm *.gcda *.gcno