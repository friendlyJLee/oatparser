# Makfie for oatparser

CC=gcc

CFLAGS=-I.

DEPS = oatparse.h \
			 elfparse.h \
			 dexparse.h

OBJ = oatparse.o \
			dexparse.o \
			elfparse.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

oatparse: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

clean:
	rm -rf *.o oatparse

