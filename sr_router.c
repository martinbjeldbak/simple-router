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

  print_hdrs(packet, len);

  if(ethtype == ethertype_arp)
    sr_handlearp(sr, packet, len, interface);

}/* end sr_ForwardPacket */


void sr_handlearp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char* interface) {
    // Get packet arp header
    sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);

    //sr_arpcache_dump(&sr->cache);

    // Request to me, construct ARP reply and send it back
    if(ntohs(arp_hdr->ar_op) == arp_op_request)
      sr_handle_arpreq(sr, packet, len, interface);
    // Reply to me. Cache it, go through request queue and send outstanding packets
    else if(ntohs(arp_hdr->ar_op) == arp_op_reply)
      sr_handle_arprep(sr, packet, len, interface);
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
void sr_handle_arpreq(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {
  sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_tip);

  if(entry != NULL) {
  }
}
