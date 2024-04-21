CC	:= gcc

CFLAGS	:= -Wall -Wextra
CFLAGS	+= -no-pie
CFLAGS	+= -Wl,-z,relro,-z,now

OUTFILE	:= chall
CFILE	:= $(OUTFILE).c

.PHONY: clean build run

clean:
	rm -f $(OUTFILE)

build: clean
	$(CC) $(CFLAGS) $(CFILE) -o $(OUTFILE)

run: build
	./$(OUTFILE)