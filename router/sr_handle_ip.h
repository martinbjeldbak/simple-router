#ifndef SR_HANDLE_IP_H
#define SR_HANDLE_IP_H

// General handling method
void sr_handle_ip(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *rec_iface);

// Handle all IP datagrams meant for router
void sr_handle_ip_rec(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *rec_iface);

void sr_do_forwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *rec_iface);

#endif
