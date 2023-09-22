#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP) { // IP type
    struct ip *ip = (struct ip *)(packet + sizeof(struct ethheader));

    if (ip->ip_p == IPPROTO_TCP) { // TCP protocol
      struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + (ip->ip_hl << 2));

      // Print Ethernet Header
      printf("Ethernet Header:\n");
      printf("   Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
             eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
      printf("   Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
             eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

      // Print IP Header
      printf("IP Header:\n");
      printf("   Source IP: %s\n", inet_ntoa(ip->ip_src));
      printf("   Destination IP: %s\n", inet_ntoa(ip->ip_dst));

      // Print TCP Header
      printf("TCP Header:\n");
      printf("   Source Port: %d\n", ntohs(tcp->th_sport));
      printf("   Destination Port: %d\n", ntohs(tcp->th_dport));

      // Print Message (up to 16 bytes)
      int ip_header_len = ip->ip_hl << 2;
      int tcp_header_len = tcp->th_off << 2;
      int data_len = header->len - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);
      int max_message_len = 16;
      if (data_len > 0) {
        printf("Hello network!\n");
        printf("\n");
      }
    }
  }
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth0
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF pseudo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   // Close the handle
  return 0;
}
