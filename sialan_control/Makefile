GCC=gcc
CFLAGS=-Wall -O3 -DJEMALLOC_NO_DEMANGLE -fstack-protector-all -fPIE -Wstack-protector
LIBS=-lm -ldb -lncurses
TARGET=sialan_ctl
OBJS=main.o search.o helper.o generic_domain.o add.o

all: $(OBJS)
	$(GCC) $(OBJS) -o $(TARGET) $(LIBS)
	strip $(TARGET)
	
clean:
	rm -rf $(OBJS) $(TARGET)
