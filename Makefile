CFLAGS = -std=c11 -g -O1 -Wall -Wextra -ffile-prefix-map=$(CURDIR)=.

trace: trace.c
	$(CC) $(CFLAGS) -o $@ $<

test: trace
	@./t/run.sh

clean:
	rm -f trace t/*.bin t/*.tmp

.PHONY: test clean
