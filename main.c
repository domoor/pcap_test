#include <pcap.h>
#include <stdint.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
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
		printf("\n[ Packet ]\n%u Bytes captured\n",header->caplen);

		uint8_t *p = (uint8_t*)packet;
		int i;
//		for(i=0; i<header->caplen; i++,p++) if(i%16)printf("%02X ", *p); else printf("\n%02X ", *p);
		printf("Source MAC\t: ");
		for(p=(uint8_t*)packet+(i=6); i<12; i++,p++)
		       	i!=6?printf("-%02X",*p):printf("%02X",*p);
		printf("\nDestination MAC\t: ");
		for(p=(uint8_t*)packet+(i=0); i<6; i++,p++)
			i?printf("-%02X",*p):printf("%02X",*p);

		p+=6;
		if(*(uint16_t*)p != 0x0008) continue;
		printf("\nSource IP\t: ");
		for(p=(uint8_t*)packet+(i=26); i<30; i++,p++)
		       	i!=26?printf(".%d",*p):printf("%d",*p);
		printf("\nDestination IP\t: ");
		for(; i<34; i++,p++)
			i!=30?printf(".%d",*p):printf("%d",*p);

		if(packet[23]!=0x06) continue;
		int eth_len=14, ip_len=(packet[14]&0x0f)*4;
		p=(uint8_t*)packet + eth_len + ip_len;
		printf("\nSource Port\t: %d",*p*256 + *(p+1));
		p+=2;
		printf("\nDestination Port: %d",*p*256 + *(p+1));

		int tcp_len = ((packet[eth_len+ip_len+12]&0xf0)>>4)*4;
		if(header->caplen-(eth_len+ip_len+tcp_len)<16) continue;
		p=(uint8_t*)packet + eth_len + ip_len + tcp_len;
		puts("\n[ Payload ]");
		for(i=0; i<16; i++,p++) printf("%02X ", *p);
	}
	pcap_close(handle);
	return 0;
}

