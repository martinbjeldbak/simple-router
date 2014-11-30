/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  uint16_t ethtype = ethertype(packet);

  //printf("*** -> Received packet of length %d \n",len);

  printf("Received packet:\n");
  print_hdrs(packet, len); printf("\n");

  if(ethtype == ethertype_arp)
    sr_handlearp(sr, packet, len, interface);

}/* end sr_ForwardPacket */


void sr_handlearp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char* interface) {
    sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);

    switch(ntohs(eth_hdr->ether_type)) {
      case ethertype_arp:
        // Send the packet down to ARP handling code
        sr_handle_arp(sr, packet, len, interface);
        break;
      case ethertype_ip:
        break;
      default:
        fprintf(stderr, "Packet was neither of type ARP or IP, dropping\n");
        return;
    }
}

void sr_handle_arp(struct sr_instance* sr,
    uint8_t *packet, unsigned int len, char *interface) {
  // Get packet arp header
  sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);

  // Request to me, construct ARP reply and send it back
  if(ntohs(arp_hdr->ar_op) == arp_op_request)
    sr_handle_arpreq(sr, packet, len, interface);
  // Reply to me. Cache it, go through request queue and send outstanding packets
  else if(ntohs(arp_hdr->ar_op) == arp_op_reply)
    sr_handle_arprep(sr, packet, len, interface);
}

/**
   # When sending packet to next_hop_ip
   entry = arpcache_lookup(next_hop_ip)

   if entry:
       use next_hop_ip->mac mapping in entry to send the packet
       free entry
   else:
       req = arpcache_queuereq(next_hop_ip, packet, len)
       handle_arpreq(req)
       free(packet) // not sure if I sould do this
**/
void sr_handle_arpreq(struct sr_instance* sr,
    uint8_t *packet, unsigned int len, char* interface) {
  sr_ethernet_hdr_t *req_eth_hdr = packet_get_eth_hdr(packet);
  sr_arp_hdr_t *req_arp_hdr = packet_get_arp_hdr(packet);
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, req_arp_hdr->ar_tip);

  // Get interface of router this arp req was received on
  struct sr_if *iface = sr_get_interface(sr, interface);

  unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *rep_packet = (uint8_t *)malloc(new_len);
  bzero(rep_packet, new_len);

  // Construct ethernet hdr
  struct sr_ethernet_hdr *rep_eth_hdr = (sr_ethernet_hdr_t *)rep_packet;
  // set destination to origin
  memcpy(rep_eth_hdr->ether_dhost,
      req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  //set source to our interface's eth addr
  memcpy(rep_eth_hdr->ether_shost,
      iface->addr, ETHER_ADDR_LEN);
  // ethernet type is ARP
  rep_eth_hdr->ether_type = ntohs(ethertype_arp);

  // If the ARP req was for this IP, respond with ARP reply
  if(req_arp_hdr->ar_tip == iface->ip) {
    // Construct ARP hdr
    sr_arp_hdr_t *rep_arp_hdr
      = (sr_arp_hdr_t *)(rep_packet + sizeof(sr_ethernet_hdr_t));
    rep_arp_hdr->ar_hrd = req_arp_hdr->ar_hrd; // 1 for ethernet
    rep_arp_hdr->ar_pro = req_arp_hdr->ar_pro; // protocol format is IPv4 (0x800)
    rep_arp_hdr->ar_hln = req_arp_hdr->ar_hln; // hardware length is same (6)
    rep_arp_hdr->ar_pln = req_arp_hdr->ar_pln; // protocol length is same (4)
    rep_arp_hdr->ar_op = htons(arp_op_reply); // ARP reply
    memcpy(rep_arp_hdr->ar_sha,
        iface->addr, ETHER_ADDR_LEN); // set hw addr
    rep_arp_hdr->ar_sip = iface->ip; // setting us as sender
    memcpy(rep_arp_hdr->ar_tha,
        req_arp_hdr->ar_sha, ETHER_ADDR_LEN); // target
    rep_arp_hdr->ar_tip = req_arp_hdr->ar_sip;

    //print_hdrs(rep_packet, new_len);

    // Put our new packet back on the wire
    sr_send_packet(sr, (uint8_t *)rep_packet,
        new_len, interface);
    free(rep_packet);
  }

  // We don't know about this host already, so add it
  if(entry != NULL) {
  }
  // Otherwise add it to ARP cache, refreshing timeout memory
  else {
    //sr_print_if(iface);
  }

}

/**
   The ARP reply processing code should move entries from the ARP request
   queue to the ARP cache:

   # When servicing an arp reply that gives us an IP->MAC mapping
   req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)
 **/
void sr_handle_arprep(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {
  sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);
  printf("lol2\n");
}

