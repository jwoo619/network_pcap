all: pcap

pcap:
	g++ -o pcap pcap.cpp -lpcap -std=c++11

clean:
	rm pcap
