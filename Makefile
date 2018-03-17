all: pcap_test

pcap_test: main.o
	gcc -o pcap_test main.o -lpcap

main.o:
	gcc -o main.o -c main.c

clean:
	rm -f pcap_test
	rm -f *.o

