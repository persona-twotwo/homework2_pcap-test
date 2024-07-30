#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#define LIBNET_LIL_ENDIAN 1


struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[0x6];/* destination ethernet address */
    u_int8_t  ether_shost[0x6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

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

void print_ip(uint8_t *ip){
	// mac = ntohl(mac);
	for(int i = 0; i!=4; i++){
		printf("%1d:",ip[i]);
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
