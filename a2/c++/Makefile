# Originally written by Joey Adams
HEADERS = $(wildcard *.h)
OBJECTS = $(patsubst %.cpp, %.o, $(wildcard *.cpp))

.PHONY: default all clean
.PRECIOUS: ids $(OBJECTS)

default: all

%.o: %.cpp $(HEADERS)
	g++ -c $< -o $@

all: $(OBJECTS)
	g++ $(OBJECTS) -lpcap -o ids

clean:
	-rm -f *.o
	-rm -f ids
