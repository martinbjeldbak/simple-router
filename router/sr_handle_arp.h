#ifndef SR_HANDLE_ARP_H
#define SR_HANDLE_ARP_H

void sr_handle_arp(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *rec_iface);

void sr_handle_arp_req(struct sr_instance* sr, sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if* rec_iface);

void sr_handle_arp_rep(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, struct sr_if* rec_iface);

void construct_arp_rep_hdr_at(uint8_t *buf, sr_arp_hdr_t *arp_hdr, struct sr_if *rec_iface);
void construct_arp_rep_eth_hdr_at(uint8_t *buf, sr_ethernet_hdr_t *eth_hdr, struct sr_if *rec_iface);

#endif
