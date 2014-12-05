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

  // If packet is a TCP or UDP packet...
  if(ip_proto == ip_protocol_tcp || ip_proto == ip_protocol_udp) {
    // Send ICMP port unreachable
    sr_send_icmp_to(sr, packet, icmp_protocol_type_dest_unreach,
        icmp_protocol_code_port_unreach, iface);
  }
  // If it is an ICMP packet...
  else if(ip_proto == ip_protocol_icmp) {
    // Extract header info
    sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

    // Send ICMP port unreachable
    sr_send_icmp_to(sr, packet, icmp_protocol_type_dest_unreach,
        icmp_protocol_code_port_unreach, iface);

    // Check ICMP checksum for corruption
    // TODO: not working
    //if(chk_icmp_cksum(icmp_hdr) == -1) {
    //  Debug("Computed ICMP checksum is not same as given. Dropping packet");
    //  return;
    //}

    if(icmp_hdr->icmp_type == icmp_protocol_type_echo_req &&
        icmp_hdr->icmp_code == icmp_protocol_code_empty) {
      // Send ICMP echo reply
      sr_modify_and_send_icmp(sr, icmp_protocol_type_echo_rep,
          icmp_protocol_type_echo_rep, packet, len, iface);
    }
  }
}

int sr_send_icmp_to(struct sr_instance *sr, uint8_t *receiver,
    uint8_t icmp_type, uint8_t icmp_code, struct sr_if *iface) {
  unsigned int len = sizeof(sr_ethernet_hdr_t) +
    sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  uint8_t *packet = (uint8_t *)malloc(len);
  bzero(packet, len);

  // Get our newly constructed packet headers
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

  // Get original sender (our receiver) header infos
  sr_ethernet_hdr_t *rec_eth_hdr = packet_get_eth_hdr(receiver);
  sr_ip_hdr_t *rec_ip_hdr = packet_get_ip_hdr(receiver);

  memcpy(eth_hdr, rec_eth_hdr, sizeof(sr_ethernet_hdr_t));
  memcpy(ip_hdr, rec_ip_hdr, sizeof(sr_ip_hdr_t));

  // Construct ethernet hdr
  memcpy(eth_hdr->ether_dhost, rec_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  // Construct ip hdr
  ip_hdr->ip_src = iface->ip;
  ip_hdr->ip_dst = rec_ip_hdr->ip_src;

  // Construct ICMP header
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  icmp_hdr->icmp_sum = cksum(icmp_hdr,
      sizeof(sr_icmp_hdr_t)); // cksum of ICMP
  // Debug("Sending ICMP echo reply packet\n");
  int res = sr_send_packet(sr, packet, len, iface->name);
  return res;
}

int sr_modify_and_send_icmp(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t *packet, int len, struct sr_if *iface) {
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  uint32_t req_src = ip_hdr->ip_src;
  ip_hdr->ip_src = iface->ip; // src is this interface's ip
  ip_hdr->ip_dst = req_src; // dst is requester's ip

  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  icmp_hdr->icmp_sum = cksum(icmp_hdr,
      sizeof(sr_icmp_hdr_t)); // cksum of ICMP
  // Debug("Sending ICMP echo reply packet\n");
  int res = sr_send_packet(sr, packet, len, iface->name);
  return res;
}
