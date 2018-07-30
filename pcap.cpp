#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <cstdint>

struct eth{
	u_int8_t srcmac[6];
	u_int8_t destmac[6];
	u_int16_t type;

	int i = 0;

	void printSrcMAC(eth *eth){
		printf("Source MAC : ");
		for(i = 0; i < 6; ++i) {
			printf("%02X", (int *)((*eth).srcmac[i]));
			if(i != 5)
				printf(":");
		}
		printf("\n");
	}

	void printDestMAC(eth *eth){
		printf("Destination MAC : ");	
		for(i = 0; i < 6; ++i) {
			printf("%02X", (int *)((*eth).destmac[i]));
			if(i != 5)
				printf(":");
		}
		printf("\n");
	}
};

struct ip_s{
	u_int8_t header_len : 4;
	u_int8_t version : 4;
	u_int8_t servicetype;
	u_int16_t totallen;
	u_int16_t identification;
	u_int16_t fragmentoff;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t headerchksum;
	u_int8_t srcip[4];
	u_int8_t destip[4];
	
	int i = 0;

	void printSrcIP(ip_s *ip){
		printf("Source IP : ");
		for(i = 0; i < 4; ++i) {
			printf("%d", (int *)((*ip).srcip[i]));
			if(i != 3)
				printf(".");
		}
		printf("\n");
	}

	void printDestIP(ip_s *ip){
		printf("Destination IP : ");
		for(i = 0; i < 4; ++i) {
			printf("%d", (int *)((*ip).destip[i]));
			if( i != 3)
				printf(".");
		}
		printf("\n");
	}
};	

struct tcp{
	u_int16_t srcport;
	u_int16_t destport;
	u_int32_t seqnum;
	u_int32_t acknum;
	u_int8_t reserved :4;
	u_int8_t header_len :4;
	u_int8_t tcpflag;
	u_int16_t window;
	u_int16_t checksum;
	u_int16_t uregntpoint;
	u_int32_t tcp_option;

	uint16_t my_ntohs(u_int16_t val){
		uint16_t res;
		res = (((val) & 0xff) << 8) | ((val >> 8) & 0xff);
		return res;
	}

	void printSrcPort(tcp *tcp){
		printf("Source Port : ");
		printf("%d\n",my_ntohs(((*tcp).srcport)));
	}

	void printDestPort(tcp *tcp){
		printf("Destination Port : ");
		printf("%d\n",my_ntohs(((*tcp).destport)));
	}
};

int main(int argc, char *argv[]){
	pcap_t *handle;			
	char *dev;			
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packet;
	eth *eth_header;
	ip_s *ip_header;
	tcp *tcp_header;
	
	if(argv[1] == NULL)
		return 0;

	dev = argv[1];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	while(1){
		if(pcap_next_ex(handle, &header, &packet) == 0)
			continue;

		printf("\n\n[ETHERNET]\n");
		eth_header = (eth *)packet;
		eth_header->printSrcMAC(eth_header);
		eth_header->printDestMAC(eth_header);

		if((*eth_header).type != ntohs(ETHERTYPE_IP))
			continue;

		printf("[IP]\n");
		ip_header = (ip_s*)(packet+14);
		ip_header->printSrcIP(ip_header);
		ip_header->printDestIP(ip_header);

		if ((*ip_header).protocol != IPPROTO_TCP)
			continue;

		printf("[TCP]\n");
		//tcp_header = (tcp*)(packet+14 + (((*ip_header).header_len) * 4));
		tcp_header = (tcp*)(packet + (((*ip_header).header_len)*4));
		tcp_header->printSrcPort(tcp_header);
		tcp_header->printDestPort(tcp_header);
				
	}
}
