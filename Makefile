CC=cc
CFLAGS=-Wall -Werror
OBJ=parser.o

%.o: %.c
	$(CC) -g -O0 -c -o $@ $< $(CFLAGS)

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean leak-linux leak-mac

clean:
	rm *.o
	rm parser

leak-linux:
	rm valgrind-out.txt
	valgrind --leak-check=full \
			 --show-leak-kinds=all \
			 --track-origins=yes \
			 --verbose \
			 --log-file=valgrind-out.txt \
			 ./parser

leak-mac:
	leaks --atExit -- ./parser
