# Simple Router
My implementation of the Simple Router assignment in UCSD's CSE 123 Computer Networks course in Fall of 2014.

- Name: Martin Bjeldbak Madsen
- PID: U06616356
- Email: <ax003222@acsmail.ucsd.edu>

I am unfortunately not competing for the Espresso prise.

## Design Decisions
This section includes a description of my implementation at a high level along with a list of requirements.

### Description
I have done my best to implement the router exactly as described on the project website along with following the flow chart used in the Project 2 discussion.

#### Modifying packets in flight vs. allocation new packets
When creating new ARP packets (responding to requests), I have chosen to allocate new ARP packets, simply because I was just getting started and thought it'd be a little cleaner this way and that it'd give me more explicit control over what goes where. This is obviously not the faster variant, as modifying the data structures in flight before sending them out is probably be the best idea.

Alternatively, for the ICMP echo responding code, I had problems with computing the chksum of a new sr_icmp_hdr_t "object". So, I simply swapped the incoming packet's ethernet src/dst, the IP ethernet and IP src/dsts, updated the ICMP type to 0, and finally recomputed the checksum to have it successfully respond to pings. Why this approach works instead of allocating a new ethernet/ip/icmp frame? I honestly cannot say. Maybe because of the ICMP data section...?


#### Handling ARPs
If we notice an ARP request on the wire and its target IP address is our (by our I mean the router's) IP address, then simply construct an ARP reply packet destined to the requester. If the ARP request is not for us, we (the router) do not need to  respond to it.

As stated on page 229 in the book about ARP queries, if we notice any ARP request, we can add it to our ARP cache, since the ARP request contains the requester's MAC and IP addresses. So this is what we do. If it is already added, then the information about the host will be refreshed.

If we get an ARP reply destined to us, cache the reply and loop through any outstanding packets in the request queue and now try to forward those packets.

#### TCP/UDP packets
If they're destined to the router, a ICMP t3 packet is constructed and returned (took me forever to figure out *not* to use the sr_icmp_hdr structure) to the sender with type destination unreachable (3) and code port unreachable (3). All of this was found in the Wikipedia article on ICMPv4 packets [here](http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Destination_unreachable). This is also where I finally figured out that you need to include the "rest of header" (in our case, the IP header and first 8 bytes of data from packet we ignored) information when responding with destination unreachable.

#### ICMP packets
If they're destined to router with type echo request (control message 8) simply send an ICMP echo reply (control message 0) back to the origin after having recomputed the checksum and modified the enclosing ethernet and IP packets.

### Header file changes
- sr_protocol.h
    - Added the protocol numbers for TCP (0x0006) and UDP (0x0011) to the sr_ip_protocol enum, used to check whether the router receives either type of packet so it can discard them (as pr. discussion slides).
    - Added sr_icmp_protocol enum with the ICMP protocol control messages we need to respond with.

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