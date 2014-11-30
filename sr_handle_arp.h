#ifndef SR_HANDLE_ARP_H
#define SR_HANDLE_ARP_H

void sr_handle_arp(struct sr_instance* sr, uint8_t *packet, unsigned int len, char *interface);

void sr_handle_arp_req(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface);

void sr_handle_arp_rep(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface);

#endif
