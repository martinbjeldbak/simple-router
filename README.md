# Simple Router
My implementation of the Simple Router assignment in UCSD's CSE 123 Computer Networks course in Fall of 2014.

- Name: Martin Bjeldbak Madsen
- PID: U06616356
- Email: <ax003222@acsmail.ucsd.edu>

## Design Decisions
This section includes a description of my implementation at a high level along with a list of requirements.

### Description

### Requirements
- The router must successfully route packets between the Internet and the application servers.
- The router must correctly handle ARP requests and replies.
- The router must correctly handle traceroutes through it (where it is not the end host) and to it (where it is the end host).
- The router must respond correctly to ICMP echo requests.
- The router must handle TCP/UDP packets sent to one of its interfaces. In this case the router should respond with an ICMP port unreachable.
- The router must maintain an ARP cache whose entries are invalidated after a timeout period (timeouts should be on the order of 15 seconds).
- The router must queue all packets waiting for outstanding ARP replies. If a host does not respond to 5 ARP requests, the queued packet is dropped and an ICMP host unreachable message is sent back to the source of the queued packet.
- The router must not needlessly drop packets (for example when waiting for an ARP reply)
- The router must enforce guarantees on timeouts--that is, if an ARP request is not responded to within a fixed period of time, the ICMP host unreachable message is generated even if no more packets arrive at the router. (Note: You can guarantee this by implementing the sr_arpcache_sweepreqs function in sr_arpcache.c correctly.)