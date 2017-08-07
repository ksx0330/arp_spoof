all: arp_spoofing

arp_spoofing: spoofing.c
	gcc -w -o arp_spoofing spoofing.c -l pcap -l pthread

clean: 
	rm arp_spoofing
