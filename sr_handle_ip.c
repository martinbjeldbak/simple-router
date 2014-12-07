#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_handle_ip.h"

void sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
  // Extract ethernet and IP hdrs
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  // Check IP header for checksum corruption
  if(chk_ip_chksum(ip_hdr) == -1) {
    Debug("Computed checksum IP is not same as given. Dropping packet\n");
    return;
  }

  // If we are the receiver
  if(iface->ip == ip_hdr->ip_dst) {
    Debug("Got a packet destined for the router\n");
    sr_handle_ip_rec(sr, packet, len, iface);
  }
  // Not for me, do IP forwarding
  else {
    Debug("Got a packet not destined to the router\n");
    // Decrement TTL
    ip_hdr->ip_ttl--;

    // If TTL now 0, drop and let receiver know
    if(ip_hdr->ip_ttl == 0) {
      Debug("\tDecremented a packet to TTL of 0, \
          dropping and sending TTL expired ICMP\n");
      sr_send_icmp_t3_to(sr, packet,
          icmp_protocol_type_time_exceed,
          icmp_protocol_code_ttl_expired);
    }

    // Now do the forwarding for this packet
    sr_do_forwarding(sr, packet, len, iface);
  }
}

/*
 * Finds the interface to forward this packet on, sending an ICMP error message
 * to the sender if we're unable to find the IP in the routing table
 * */
void sr_do_forwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len) {
  // Get interface we need to send this packet out on
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  struct sr_if *out_if = sr_iface_for_dst(sr, ip_hdr->ip_dst);

  // See if we have a matching interface to forward the packet to
  if(out_if) {
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache,
        ip_hdr->ip_dst);
    if(arp_entry) {
      Debug("Using next_hop_ip->mac mapping in entry to send the packet\n");

      free(arp_entry);
      forward_packet(sr, packet, len, arp_entry->mac, out_if);
      return;
    }
    else {
      Debug("\tNo entry found for receiver IP, queing packet \
          and sending ARP req\n");
      struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, 
          ip_hdr->ip_dst, packet, len, out_if->name);

      sr_arpcache_handle_req_sending(sr, req);
      return;
    }
  }
  else {
    // Don't know where to forward this, ICMP error send net unreachable
    Debug("\tGo home, you're drunk! I don't have an interface for that!\n");
    sr_send_icmp_t3_to(sr, packet, icmp_protocol_type_dest_unreach,
        icmp_protocol_code_net_unreach);
  }
}

void sr_handle_ip_rec(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
  Debug("Got IP packet:\n");

  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  // Get IP protocol information
  uint8_t ip_proto = ip_hdr->ip_p;

  switch(ip_proto) {
    // If packet is a TCP or UDP packet...
    case ip_protocol_tcp:
    case ip_protocol_udp:
      Debug("\tTCP/UDP request received, sending port unreachable\n");
      // Send ICMP port unreachable
      sr_send_icmp_t3_to(sr, packet, icmp_protocol_type_dest_unreach,
          icmp_protocol_code_port_unreach);
      break;
    // If it is an ICMP packet...
    case ip_protocol_icmp: ;
      // Extract header info
      sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

      // Check ICMP checksum for corruption
      // TODO: not working
      //if(chk_icmp_cksum(icmp_hdr) == -1) {
      //  Debug("Computed ICMP checksum is not same as given. Dropping packet");
      //  return;
      //}
      if(icmp_hdr->icmp_type == icmp_protocol_type_echo_req &&
          icmp_hdr->icmp_code == icmp_protocol_code_empty) {
        Debug("\tGot an echo (ping) request, responding with reply\n");
        // Send ICMP echo reply
        sr_modify_and_send_icmp(sr, icmp_protocol_type_echo_rep,
            icmp_protocol_type_echo_rep, packet, len, iface);
      }
      break;
    default:
      Debug("\tUnable to process packet with protocol number %d\n", ip_proto);
      return;
  }
}

// Sends an ICMP error message from sr out of interface iface
// to receiver noted in the uint8_t receiver IP packet.
int sr_send_icmp_t3_to(struct sr_instance *sr, uint8_t *receiver,
    uint8_t icmp_type, uint8_t icmp_code) {

  unsigned int len = sizeof(sr_ethernet_hdr_t) +
    sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *packet = (uint8_t *)malloc(len);
  bzero(packet, len);

  // Get our newly constructed packet headers
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  sr_icmp_t3_hdr_t *icmp_hdr = packet_get_icmp_t3_hdr(packet);

  // Get original sender (our receiver) header infos
  sr_ethernet_hdr_t *rec_eth_hdr = packet_get_eth_hdr(receiver);
  sr_ip_hdr_t *rec_ip_hdr = packet_get_ip_hdr(receiver);

  // Get interface we should be sending the packet on
  struct sr_if *iface = sr_iface_for_dst(sr, rec_ip_hdr->ip_src);

  // Construct ethernet hdr
  memcpy(eth_hdr->ether_dhost, rec_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  // Construct ip hdr
  ip_hdr->ip_hl = rec_ip_hdr->ip_hl;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_tos = rec_ip_hdr->ip_tos;
  ip_hdr->ip_off = htons(IP_DF); // set dont fragment bit
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_v = rec_ip_hdr->ip_v;
  ip_hdr->ip_src = iface->ip;
  ip_hdr->ip_dst = rec_ip_hdr->ip_src;
  ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_sum = cksum((const void *)ip_hdr,
      sizeof(sr_ip_hdr_t));

  // Construct ICMP header
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  memcpy(icmp_hdr->data, rec_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = cksum((const void *)icmp_hdr,
      sizeof(sr_icmp_t3_hdr_t)); // cksum of ICMP

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
  int res = sr_send_packet(sr, packet, len, iface->name);

  return res;
}
