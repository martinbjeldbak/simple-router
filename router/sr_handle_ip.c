#include <stdlib.h>
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_handle_ip.h"

/* Scope: local to this file
 * Given the IP header and the length of the entire packet, finds out
 * whether the length of the packet is at least what is required to fill the
 * header, along with making sure that the header checksum is calculated correctly
 */
uint8_t is_sanity_check_of_ip_packet_ok(sr_ip_hdr_t *ip_hdr, unsigned int len) {
  uint8_t we_good = 1; // assume all is well
  if(!sanity_check_ip_packet_len_ok(len)) {
    Debug("Sanity check for IP packet failed! Dropping packet.\n");
    we_good = 0;
  }
  if(!is_ip_chksum_ok(ip_hdr)) {
    Debug("Computed checksum IP is not same as given. Dropping packet.\n");
    we_good = 0;
  }
  return we_good;
}

/* Scope: local to this file
 * Serves same purpose as above, just for incoming ICMP packets and
 * their headers.
 */
uint8_t is_sanity_check_of_icmp_packet_ok(sr_ip_hdr_t *ip_hdr,
    sr_icmp_hdr_t *icmp_hdr, unsigned int len) {
  uint8_t we_good = 1;

  if(!sanity_check_icmp_packet_len_ok(len)) {
    Debug("Received ICMP packet that was too small. Dropping packet.\n");
    we_good = 0;
  }
  if(!is_icmp_chksum_ok(ip_hdr->ip_len, icmp_hdr)) {
    Debug("Computed ICMP checksum is not same as given. Dropping packet.\n"); 
    we_good = 0;
  }
  return we_good;
}

void sr_handle_ip(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, struct sr_if *rec_iface) {
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  // Check for too small packet length or wrong checksum
  if(!is_sanity_check_of_ip_packet_ok(ip_hdr, len)) return;

  struct sr_if *iface_walker = sr->if_list;

  // Loop through all interfaces to see if it matches one
  while(iface_walker) {
    // If we are the receiver, could also compare ethernet
    // addresses as an extra check
    if(iface_walker->ip == ip_hdr->ip_dst) {
      Debug("Got a packet destined the router at interface %s\n",
          iface_walker->name);
      sr_handle_ip_rec(sr, packet, len, iface_walker);
      return;
    }
    iface_walker = iface_walker->next;
  }

  // Not for me, do IP forwarding
  Debug("Got a packet not destined to the router, forwarding it\n");
  // Decrement TTL
  ip_hdr->ip_ttl--;

  // If TTL now 0, drop and let sender know
  if(ip_hdr->ip_ttl == 0) {
    Debug("\tDecremented a packet to TTL of 0, dropping and sending TTL expired ICMP\n");
    sr_send_icmp_t3_to(sr, packet,
        icmp_protocol_type_time_exceed, icmp_protocol_code_ttl_expired,
        rec_iface);
    return;
  }

  // Sanity checks done, forward packet
  sr_do_forwarding(sr, packet, len, rec_iface);
}

/*
 * Finds the interface to forward this packet on, and forwards the
 * packet on it, sending an ICMP error message to the sender, if
 * we're unable to find the IP in the routing table
 */
void sr_do_forwarding(struct sr_instance *sr, uint8_t *packet,
    unsigned int len, struct sr_if *rec_iface) {
  // Get interface we need to send this packet out on
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  struct sr_if *out_if = sr_iface_for_dst(sr, ip_hdr->ip_dst);

  // See if we have a matching interface to forward the packet to
  if(out_if) {
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache,
        ip_hdr->ip_dst);
    if(arp_entry) {
      Debug("Using next_hop_ip->mac mapping in entry to send the packet\n");

      sr_forward_packet(sr, packet, len, arp_entry->mac, out_if);
      free(arp_entry);
      return;
    }
    else {
      Debug("\tNo entry found for receiver IP, queing packet and sending ARP req\n");
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
        icmp_protocol_code_net_unreach, rec_iface);
  }
}

void sr_handle_ip_rec(struct sr_instance *sr, uint8_t *packet,
    unsigned int len, struct sr_if *iface) {
  Debug("Got IP packet:\n");

  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  // Get IP protocol information
  uint8_t ip_proto = ip_hdr->ip_p;

  switch(ip_proto) {
    // If packet is a TCP or UDP packet...
    case ip_protocol_tcp:
    case ip_protocol_udp:
      Debug("\tTCP/UDP request received on iface %s, sending port unreachable\n",
          iface->name);
      // Send ICMP port unreachable
      sr_send_icmp_t3_to(sr, packet, icmp_protocol_type_dest_unreach,
          icmp_protocol_code_port_unreach, iface);
      break;
    // If it is an ICMP packet...
    case ip_protocol_icmp: ;
      // Extract header info
      sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

      // Check for too small packet length or wrong checksum
      if(!is_sanity_check_of_icmp_packet_ok(ip_hdr, icmp_hdr, len)) return;

      if(icmp_hdr->icmp_type == icmp_protocol_type_echo_req &&
          icmp_hdr->icmp_code == icmp_protocol_code_empty) {
        
        // Send ICMP echo reply
        sr_send_icmp(sr, icmp_protocol_type_echo_rep,
            icmp_protocol_type_echo_rep, packet, len, iface);
      }
      break;
    default:
      Debug("\tUnable to process packet with protocol number %d\n", ip_proto);
      return;
  }
}

