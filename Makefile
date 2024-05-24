CC=cc
CFLAGS=-Wall -Werror
OBJ=parser.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean leak

clean:
	rm *.o
	rm parser

leak:
	valgrind --leak-check=full \
			 --show-leak-kinds=all \
			 --track-origins=yes \
			 --verbose \
			 --log-file=valgrind-out.txt \
			 ./parser