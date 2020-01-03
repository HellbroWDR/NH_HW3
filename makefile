all: pcap

pcap:
	gcc -g NH_HW3.c -o NH_HW3 -lpcap
cls:
	rm -f NH_HW3
