# Originally written by Joey Adams
HEADERS = $(wildcard *.h)
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))

.PHONY: default all clean
.PRECIOUS: ids $(OBJECTS)

default: all

%.o: %.c $(HEADERS)
	gcc -std=gnu99 -c $< -o $@

all: $(OBJECTS)
	gcc $(OBJECTS) -lpcap -o ids

clean:
	-rm -f *.o
	-rm -f ids