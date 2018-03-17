#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdio.h>

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

		uint8_t *p = (uint8_t*)packet;
		int i;
		p+=6;
		printf("\nSource MAC\t: %s",ether_ntoa_u(p));
		p-=6;
		printf("\nDestination MAC\t: %s",ether_ntoa_u(p));
		p+=12;
		if(*(uint16_t*)p != 0x0008) continue;

		p+=14;
		printf("\nSource IP\t: %s",inet_ntoa(*(struct in_addr*)p));
		p+=4;
		printf("\nDestination IP\t: %s",inet_ntoa(*(struct in_addr*)p));
		if(packet[23]!=0x06) continue;

		int eth_len=14, ip_len=(packet[14]&0x0f)*4;
		p=(uint8_t*)packet + eth_len + ip_len;
		printf("\nSource Port\t: %u",ntohs(*(uint16_t*)p));
		p+=2;
		printf("\nDestination Port: %u",ntohs(*(uint16_t*)p));
		int tcp_len = ((packet[eth_len+ip_len+12]&0xf0)>>4)*4;
		if(header->caplen-(eth_len+ip_len+tcp_len)<16) continue;

		p=(uint8_t*)packet + eth_len + ip_len + tcp_len;
		puts("\n[ Payload ]");
		for(i=0; i<16; i++,p++) printf("%02X ", *p);
	}
	pcap_close(handle);
	return 0;
}

