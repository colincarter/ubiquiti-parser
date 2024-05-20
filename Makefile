CC=cc
CFLAGS=-Wall -Werror
OBJ=parser.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm *.o
	rm parser