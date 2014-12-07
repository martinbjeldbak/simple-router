#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_handle_ip.h"

void sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
  // Extract and IP hdr
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  // Check IP header for checksum corruption
  if(chk_ip_chksum(ip_hdr) == -1) {
    Debug("Computed checksum IP is not same as given. Dropping packet\n");
    return;
  }

  // If we are the receiver
  if(iface->ip == ip_hdr->ip_dst) {
    Debug("Got a packet destined for the router\n");
    sr_handle_ip_rec(sr, packet, len);
  }
  // Not for me, do IP forwarding
  else {
    Debug("Got a packet not destined to the router\n");
    // Decrement TTL
    ip_hdr->ip_ttl--;

    // If TTL now 0, drop and let receiver know
    if(ip_hdr->ip_ttl == 0) {
      Debug("\tDecremented a packet to TTL of 0, dropping and sending TTL expired ICMP\n");
      sr_send_icmp_t3_to(sr, packet,
          icmp_protocol_type_time_exceed,
          icmp_protocol_code_ttl_expired);
    }

    // Now do the forwarding for this packet
    sr_do_forwarding(sr, packet, len);
  }
}

/*
 * Finds the interface to forward this packet on, and forwards the
 * packet on it, sending an ICMP error message to the sender, if
 * we're unable to find the IP in the routing table
 */
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
      sr_forward_packet(sr, packet, len, arp_entry->mac, out_if);
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

void sr_handle_ip_rec(struct sr_instance *sr, uint8_t *packet, unsigned int len) {
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
            icmp_protocol_type_echo_rep, packet, len);
      }
      break;
    default:
      Debug("\tUnable to process packet with protocol number %d\n", ip_proto);
      return;
  }
}


int sr_modify_and_send_icmp(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t *packet, int len) {
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

  // Get interface we should be sending the packet on
  struct sr_if *iface = sr_iface_for_dst(sr, ip_hdr->ip_src);

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
