#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#define LIBNET_BIG_ENDIAN       1

#include "libnet-macros.h"
#include "libnet-headers.h"

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void print_mac(u_int8_t *mac){
    int i;
    for (i=0;i<6;i++){
        printf("%02x", mac[i]);
        if (i != 5) printf(":");
        if (i == 5) printf("\n");
    }
}

void packet_info(const u_char *packet){
    struct libnet_ethernet_hdr *eth_hdr;
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_tcp_hdr *tcp_hdr;

	int i;
	char buf1[20];
	char buf2[20];

    //print mac
    eth_hdr = (libnet_ethernet_hdr *)packet;
	printf("----------------MAC------------------\n");
	printf("Source Mac : ");
    print_mac(eth_hdr->ether_shost);
	printf("Destination Mac : ");
	print_mac(eth_hdr->ether_dhost);

    //if ip print ip
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
        packet += sizeof(struct libnet_ethernet_hdr);
        ip_hdr = (libnet_ipv4_hdr *)packet;

		printf("\n-----------------IP------------------\n");
        inet_ntop(AF_INET, &ip_hdr->ip_src, buf1, sizeof(buf1));
		printf("Source IP : \t%s\n", buf1);
        inet_ntop(AF_INET, &ip_hdr->ip_dst, buf2, sizeof(buf2));
		printf("Destination IP : %s\n\n", buf2);

        //if tcp print tcp
        if (ip_hdr->ip_p == IPPROTO_TCP){
            packet += (ip_hdr->ip_hl) * 4;     //using ip header length
            tcp_hdr = (libnet_tcp_hdr *)packet;

            printf("-----------------TCP-----------------\n");
            printf("Source TCP : \t%d\n", ntohs(tcp_hdr->th_sport));
            printf("Destination TCP : %d\n\n", ntohs(tcp_hdr->th_dport));

            //print data
            packet += (tcp_hdr->th_off) * 4;    //using tcp data offset
            printf("----------------DATA-----------------\n");
            for (i=0;i<16;i++){
                printf("%02x", *(packet++));
            }
            printf("\n\n");
        }
    }
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

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        packet_info(packet);
    }

    pcap_close(handle);
    return 0;
}