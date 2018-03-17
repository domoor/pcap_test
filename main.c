#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#define ETHER_ADDR_LEN 6

struct ethernet_hdr {
	uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	uint16_t ether_type;                 /* protocol */
};

struct ip_hdr {
    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    uint8_t ip_tos;       /* type of service */
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
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
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
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct tcp_hdr {
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
    uint8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    uint8_t  th_flags;       /* control flags */
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
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
};

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

char* ether_ntoa_u(uint8_t *addr) {
	static char buf[18];
	sprintf(buf, "%02X-%02X-%02X-%02X-%02X-%02X",
	addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
	return buf;
}

int main(int argc, char* argv[]) {

	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	while(1) {
		puts("");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("\n[ Packet ]\n%u Bytes captured",header->caplen);

		struct ethernet_hdr *eth = (struct ethernet_hdr*)packet;
		printf("\nSource MAC\t: %s",ether_ntoa_u(eth->ether_shost));
		printf("\nDestination MAC\t: %s",ether_ntoa_u(eth->ether_dhost));
		if(eth->ether_type != 0x0008) continue;

		int eth_len=14;
		struct ip_hdr *ip = (struct ip_hdr*)(packet + eth_len);
		printf("\nSource IP\t: %s",inet_ntoa(ip->ip_src));
		printf("\nDestination IP\t: %s",inet_ntoa(ip->ip_dst));
		if(ip->ip_p!=0x06) continue;

		int ip_len=(ip->ip_hl)*4;
		struct tcp_hdr *tcp = (struct tcp_hdr*)(packet + eth_len + ip_len);
		printf("\nSource Port\t: %u",ntohs(tcp->th_sport));
		printf("\nDestination Port: %u",ntohs(tcp->th_dport));
		int tcp_len = tcp->th_off*4;
		if(header->caplen-(eth_len+ip_len+tcp_len)<16) continue;

		uint8_t *payload = (uint8_t*)(packet + eth_len + ip_len + tcp_len);
		puts("\n[ Payload ]");
		for(int i=0; i<16; i++) printf("%02X ", payload[i]);
	}
	pcap_close(handle);
	return 0;
}

