LDLIBS=-lpcap -pthread

all: arp-spoof

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

send.o : iphdr.h send.h send.cpp

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o send.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
