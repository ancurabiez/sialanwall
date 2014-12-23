GCC=gcc
CFLAGS=-pthread -Wall -O3 -D_BSD_SOURCE -DJEMALLOC_NO_RENAME \
-fstack-protector-all -fPIE -Wstack-protector
LIBS=-lnetfilter_queue -lrt -ldb-4.8 -ljemalloc -lnfnetlink -lm -lpthread
TARGET=sialan_fw
OBJS=main.o queue.o checksum.o helper.o raw_socket.o http_rule.o dns_rule.o \
buffer.o rule.o generic_domain.o cache.o buffer_sorting.o


all: $(OBJS) sialan_input sialan_lookup
	$(GCC) $(OBJS) -o $(TARGET) $(LIBS)
	strip $(TARGET)

sialan_ctrl: sialan_ctrl.o
	$(GCC) $(SQLITE_OBJ) sialan_ctrl.o helper.o -o sialan_ctrl -lm -ldl -lpthread -ljemalloc
	strip sialan_ctrl

sialan_input: db_input.o ip_dom.o
	$(GCC) helper.o ip_dom.o db_input.o -o sialan_input -ldb-4.8 -ljemalloc
	strip sialan_input

sialan_lookup: dns_lookup.o
	$(GCC) dns_lookup.o helper.o -o sialan_lookup -ldb-4.8 -ljemalloc
	strip sialan_lookup

install:
	mkdir /var/sialan_firewall
	install -m 644 ./sialan_fw /usr/sbin
	install -m 644 sialan_control/sialan_ctl /usr/sbin
	install -m 644 ./sialan_input /usr/sbin
	install -m 644 ./sialan /usr/sbin
	install -m 644 ./sialan_lookup /usr/sbin

clean:
	rm -rf $(OBJS) $(TARGET)
	rm -rf dns_lookup.o sialan_lookup
	rm -rf ip_dom.o db_input.o sialan_input
