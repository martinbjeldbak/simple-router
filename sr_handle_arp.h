#ifndef SR_HANDLE_ARP_H
#define SR_HANDLE_ARP_H

void sr_handle_arp(struct sr_instance* sr, uint8_t *packet, unsigned int len, char *interface);

void sr_handle_arp_req(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface);

void sr_handle_arp_rep(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface);

void construct_arp_hdr_at(uint8_t *buf, sr_arp_hdr_t *arp_hdr, struct sr_if *iface);
void construct_arp_eth_hdr_at(uint8_t *buf, sr_ethernet_hdr_t *eth_hdr, struct sr_if *iface);


#endif
