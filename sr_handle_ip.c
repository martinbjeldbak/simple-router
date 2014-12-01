#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_handle_ip.h"

void sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
  //printf("PACKET RECEIVED\n");
  //print_hdrs(packet, len);

  // Extract ethernet and IP hdrs
  //sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  // Check IP header for checksum corruption
  if(chk_ip_chksum(ip_hdr) == -1) {
    Debug("Computed checksum IP is not same as given. Dropping packet");
    return;
  }

  // Check if we are receiver
  if(iface->ip == ip_hdr->ip_dst) {
    sr_handle_ip_rec(sr, packet, len, iface);
  }
  // Not for me, do IP forwarding
  else {
    // TODO: Before forwarding, check TTL
  }
}

void sr_handle_ip_rec(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
  // Extract ethernet and IP hdrs
  //sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  // Get IP protocol information
  uint8_t ip_proto = ip_protocol((uint8_t *)ip_hdr);

  // If this an ICMP packet
  if(ip_proto == ip_protocol_icmp) {
    // Extract header info
    sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

    // Check ICMP checksum for corruption
    // TODO: not working
    //if(chk_icmp_cksum(icmp_hdr) == -1) {
    //  Debug("Computed ICMP checksum is not same as given. Dropping packet");
    //  return;
    //}

    if(icmp_hdr->icmp_type == 8) {
      // Send ICMP echo reply
      sr_send_icmp(sr, 8, packet, len, iface);
    }
  }
}

int sr_send_icmp(struct sr_instance *sr, uint8_t icmp_code, uint8_t *packet, int len, struct sr_if *iface) {
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  uint32_t req_src = ip_hdr->ip_src;
  ip_hdr->ip_src = iface->ip; // src is this interface's ip
  ip_hdr->ip_dst = req_src; // dst is requester's ip

  icmp_hdr->icmp_type = 0; // echo reply code (0)
  icmp_hdr->icmp_sum = cksum(icmp_hdr,
      sizeof(sr_icmp_hdr_t)); // cksum of ICMP
  // Debug("Sending ICMP echo reply packet\n");
  int res = sr_send_packet(sr, packet, len, iface->name);
  return res;
}
