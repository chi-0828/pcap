all: pcap

pcap: pcap.c
	gcc pcap.c -o pcap -lpcap
clean:
	rm -f pcap