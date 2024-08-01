#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "structures.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
void print_mac(uint8_t *mac){
	// mac = ntohl(mac);
	for(int i = 0; i!=6; i++){
		printf("%02x:",mac[i]);
	}
	printf("\n");
}


void print_payload20(u_char* payload, u_int64_t len){
	if(len > 20) len = 20;
	if(len > 0){
		printf("print payload %ubytes\n",len);
		for (int i=0; i !=len; i++){
			printf("%02x ",payload[i]);
			if(i%10 == 9){
				printf("\n");
			}
		}
		printf("\n");
	}
}

void print_packet(	struct libnet_ethernet_hdr *E_Header,
					struct libnet_ipv4_hdr *IP_Header,
					struct libnet_tcp_hdr * TCP_Header
					){
	printf("src mac : ");
	print_mac(E_Header->ether_shost);
	printf("dst mac : ");
	print_mac(E_Header->ether_dhost);
	// printf("type: %x\n",ntohs(E_Header->ether_type));

	printf("src ip  : %s\n",inet_ntoa(IP_Header->ip_src));
	printf("dst ip  : %s\n",inet_ntoa(IP_Header->ip_dst));
	// printf("protocol: %u\n",IP_Header->ip_p);

	printf("src port: %u\n",ntohs(TCP_Header->th_sport));
	printf("dst port: %u\n",ntohs(TCP_Header->th_dport));
	// printf("LEN     : %d\n",ntohs(->))

}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	uint32_t count = 1;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		count %= 100000000;

		u_int64_t offset = 0;
		struct libnet_ethernet_hdr *E_Header;
		E_Header = packet;
		
		offset+= sizeof(struct libnet_ethernet_hdr);
		struct libnet_ipv4_hdr *IP_Header;
		IP_Header = packet + offset;
		
		offset += (IP_Header->ip_hl * 4);
		struct libnet_tcp_hdr * TCP_Header;
		TCP_Header = packet + offset;
		
		offset += (TCP_Header->th_off * 4);
		if ((E_Header->ether_type == 0x08) && (IP_Header->ip_p == 0x06)){
			printf("==================\n");
			printf("count: [%08u]\n",count++);
			printf("%u bytes TCP captured\n", header->caplen);
			print_packet(E_Header,IP_Header,TCP_Header);
			printf("LEN & offset: %u, %lu\n",header->len, offset);
			print_payload20(packet + offset, header->len - offset);
			printf("==================\n");
			printf("\n");
		}
		
	}

	pcap_close(pcap);
}
