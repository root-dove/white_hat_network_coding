#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    printf("\n==== Packet Captured ====\n");

    printf("Ethernet Header:\n");
    printf("   Src MAC");
    for(int i= 0; i < 6;i++){
        printf(":%02x",eth->ether_shost[i]);
    }
    printf("\n");
    printf("   Dst MAC");
    for(int i= 0; i < 6;i++){
        printf(":%02x",eth->ether_dhost[i]);
    }
    printf("\n");

    if (ntohs(eth->ether_type) == 0x0800) { 
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("IP Header:\n");
        printf("   From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("   To: %s\n", inet_ntoa(ip->iph_destip));

        if (ip->iph_protocol != IPPROTO_TCP) {
            printf("   Protocol: Not TCP (ignored)\n");
            return; 
        }

        int ip_header_len = ip->iph_ihl * 4;

        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
        
        printf("TCP Header:\n");
        printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
        printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

        int tcp_header_len = (tcp->tcp_offx2 >> 4) * 4;
        int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
        int payload_len = header->caplen - payload_offset;

        if (payload_len > 0) {
            printf("Payload (%d bytes): ", payload_len);
            for (int i = 0; i < (payload_len > 16 ? 16 : payload_len); i++) {
                printf("%02x ", packet[payload_offset + i]);
            }
            printf("...\n");
        } else {
            printf("Payload: None\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; 
    bpf_u_int32 net;

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't apply filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}