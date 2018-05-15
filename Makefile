CC = gcc
CFLAGS = -Wall -std=c11 -pthread

SRC1 = wildcards.c test_wildcards.c
OBJ1 = wildcards.o test_wildcards.o

EXE1 = test_wildcards

all: $(EXE1)

$(EXE1): $(OBJ1) Makefile
	$(CC) $(CFLAGS) -o $(EXE1) $(OBJ1) -g

clean:
	rm -f $(OBJ1) $(EXE1)
