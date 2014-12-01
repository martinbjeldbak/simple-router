#include <stdio.h>
#include <stdlib.h>
#include "sr_rt.h"
#include "sr_utils.h"

void sr_handle_ip(struct sr_instance* sr, uint8_t *packet, unsigned int len, char *interface) {
  print_hdrs(packet, len);

  // Extract ethernet and IP hdrs
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  // Get IP protocol information
  uint8_t ip_proto = ip_protocol((uint8_t *)ip_hdr);

  // If this an ICMP packet
  if(ip_proto == ip_protocol_icmp) {
    // Extract header info
    sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

    printf("ICMPP HDR:\n");
    print_hdr_icmp((uint8_t *)icmp_hdr);
  }
}
