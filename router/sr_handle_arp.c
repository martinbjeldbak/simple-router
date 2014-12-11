#include <stdlib.h>
#include <string.h>
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_handle_arp.h"

void sr_handle_arp(struct sr_instance* sr,
    uint8_t *packet, unsigned int len, struct sr_if *rec_iface) {
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);

  if(!sanity_check_arp_packet_len_ok(len)) {
    Debug("Sanity check for ARP packet length failed! Ignoring ARP.\n");
    return;
  }

  Debug("Sensed an ARP frame, processing it\n");

  switch(ntohs(arp_hdr->ar_op)) {
    case arp_op_request:
      sr_handle_arp_req(sr, eth_hdr, arp_hdr, rec_iface);
      break;
    case arp_op_reply:
      sr_handle_arp_rep(sr, arp_hdr, rec_iface);
      break;
    default:
      Debug("Didn't get an ARP frame I understood, quitting!\n");
      return;
  }
}

/*
 * ARP reply processing. Based on the pseudocode given in
 * the header file sr_arpcache.h
 */
void sr_handle_arp_rep(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr,
    struct sr_if* rec_iface) {

  // Check if we are destination of ARP reply
  if(arp_hdr->ar_tip == rec_iface->ip) {
    Debug("\tGot ARP reply at interfce %s, caching it\n", rec_iface->name);

    // Cache it
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,
        arp_hdr->ar_sha, arp_hdr->ar_sip);

    // Go through request queue and send packets waiting on this reply
    if(req) {
      // Get waiting packets
      struct sr_packet *waiting_packet_walker = req->packets;
      // Loop through waiting
      while(waiting_packet_walker) {
        Debug("Forwarding packet that has been waiting for ARP reply\n");
        sr_forward_packet(sr, waiting_packet_walker->buf,
            waiting_packet_walker->len, arp_hdr->ar_sha, rec_iface);

        // try to go to a next waiting packet
        waiting_packet_walker = waiting_packet_walker->next; 
      }
      // Drop the request from oustanding queue since it is now forwarded
      sr_arpreq_destroy(&sr->cache, req);
    }
  }
}

/*
 * ARP request processing. If we get a request, respond to it. Cache
 * it regardless of it was to us or not.
 */
void sr_handle_arp_req(struct sr_instance* sr,
    sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if* rec_iface) {

  // Insert this host into our ARP cache regardless if for me or not
  sr_arpcache_insert(&sr->cache, req_arp_hdr->ar_sha, req_arp_hdr->ar_sip);

  // If the ARP req was for this me, respond with ARP reply
  // I could also compare ethernet addresses here
  if(req_arp_hdr->ar_tip == rec_iface->ip) {
    Debug("\tGot ARP request at interfce %s, constructing reply\n", rec_iface->name);

    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *rep_packet = (uint8_t *)malloc(len);
    bzero(rep_packet, len);

    // Construct ethernet hdr part of ARP reply packet
    construct_arp_rep_eth_hdr_at(rep_packet, req_eth_hdr, rec_iface);

    // Construct ARP hdr
    construct_arp_rep_hdr_at(rep_packet + sizeof(sr_ethernet_hdr_t),
        req_arp_hdr, rec_iface);

    // Put our new (modified) packet back on the wire
    sr_send_packet(sr, rep_packet, len, rec_iface->name);
  }
}

void construct_arp_rep_eth_hdr_at(uint8_t *buf, sr_ethernet_hdr_t *eth_hdr, struct sr_if *rec_iface) {
  // Construct ethernet hdr
  struct sr_ethernet_hdr *rep_eth_hdr = (sr_ethernet_hdr_t *)buf;
  // set destination to origin
  memcpy(rep_eth_hdr->ether_dhost,
      eth_hdr->ether_shost, ETHER_ADDR_LEN);
  //set source to our interface's eth addr
  memcpy(rep_eth_hdr->ether_shost,
      rec_iface->addr, ETHER_ADDR_LEN);
  // ethernet type is ARP
  rep_eth_hdr->ether_type = ntohs(ethertype_arp);
}


void construct_arp_rep_hdr_at(uint8_t *buf, sr_arp_hdr_t *arp_hdr,
    struct sr_if *rec_iface) {
    sr_arp_hdr_t *rep_arp_hdr = (sr_arp_hdr_t *)buf;
    rep_arp_hdr->ar_hrd = arp_hdr->ar_hrd; // 1 for ethernet
    rep_arp_hdr->ar_pro = arp_hdr->ar_pro; // protocol format is IPv4 (0x800)
    rep_arp_hdr->ar_hln = arp_hdr->ar_hln; // hardware length is same (6 = ETHER_ADDR_LEN)
    rep_arp_hdr->ar_pln = arp_hdr->ar_pln; // protocol length is same (4)
    rep_arp_hdr->ar_op = htons(arp_op_reply); // ARP reply
    memcpy(rep_arp_hdr->ar_sha,
        rec_iface->addr, ETHER_ADDR_LEN); // set hw addr
    rep_arp_hdr->ar_sip = rec_iface->ip; // setting us as sender
    memcpy(rep_arp_hdr->ar_tha,
        arp_hdr->ar_sha, ETHER_ADDR_LEN); // target
    rep_arp_hdr->ar_tip = arp_hdr->ar_sip;
}

