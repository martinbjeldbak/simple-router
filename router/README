# Simple Router
My implementation of the Simple Router assignment in UCSD's CSE 123 Computer Networks course in Fall of 2014, based off of the assignment at [mininet/mininet](https://github.com/mininet/mininet).

- Name: Martin Bjeldbak Madsen
- PID: U06616356
- Email: <ax003222@acsmail.ucsd.edu>

I am unfortunately not competing for the Espresso prise.

## Design Decisions
This section includes a high level description of my implementation, along with a list of requirements.

### Description
I have done my best to implement the router exactly as described on the project website along with following the flow chart used in the Project 2 discussion, along with comparing my solution to the supplied sr_solution binary.

The below sections describe my trains of thoughts and how I have implemented logic in the router, again at a high level. To see details, please read my source code. I have tried to make it as understandable as possible with comments where needed.

### Modifying packets in flight vs. allocation new packets
When creating new ARP (responding to requests) and sending new ICMP (ICMP t3) error messages that require the IP packet in the data segment, I have chosen to allocate new packets, simply because I somehow feel this way is a little cleaner, and that it'd also give me more explicit control over what goes where. This is obviously not the faster variant, as modifying the data structures in flight before sending them out is probably be the best idea. During development I tried both approaches, but found allocating new packets each time to be the most general solution, saving me a few functions.

When responding to an ICMP request such as an echo request, I simply modify the ethernet and IP sender/destination headers, and set the correct flags on the ICMP header before send the frame back to the source.

### Handling ARPs
If we notice an ARP request on the wire and its target IP address is our (by *our* I mean the router's) IP address, then simply construct an ARP reply packet destined to the requester. If the ARP request is not for us, we (the router) do not need to  respond to it.

As stated on page 229 in the book about ARP queries, if we notice any ARP request, we can add it to our ARP cache, since the ARP request contains the requester's MAC and IP addresses. So this is what we do. If it is already added, then the information about the host will be refreshed.

If we get an ARP reply destined to us, cache the reply and loop through any outstanding packets in the request queue waiting on that ARP reply and now to forward those packets, removing them from the queue.

### Handling IP packets
In this project, there are two possible cases when receiving an IP packet: either it's for us, or for someone else. If it's for us, then we need to handle it. If it's for someone else, we need  to figure out who is the receiver and then initiate appropriate forwarding logic.

#### If IP packet is destined to the router
The first thing I do when receiving an IP packet is checking if one of our interfaces was the destination. I do this by looping through each of the router's interfaces and comparing the IP packet's destination with the interface's IP. You could add an extra comparison to double check with the destination ethernet address and the interface's address, but this is not required and would require some comparison function to compare the uint8_t address array of the ethernet header (sr_ethernet_hdr) data structure with the unsigned char array data structure belonging the interface data structure (sr_if).

There are only 2 cases to handle if it's for us. Either the IP packet is a TCP/UDP packet or an ICMP packet. How we handle each is described below.

##### TCP/UDP packets
If the packet is a TCP/UDP packet a ICMP t3 packet is constructed and returned (took me forever to figure out *not* to use the sr_icmp_hdr structure, since we need to append some bits of the IP packet's header to the ICMP packet) to the sender with type destination unreachable (3) and code port unreachable (3). Most of this was found in the Wikipedia article on ICMPv4 packets [here](http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Destination_unreachable). This is also where I finally figured out that you need to include the "rest of header" (in our case, the IP header and first 8 bytes of data from packet we ignored) information when responding with destination unreachable.

##### ICMP packets
If they're destined to router with type echo request (control message 8) simply send an ICMP echo reply (control message 0) back to the origin after having recomputed the checksum and modified the enclosing ethernet and IP packets.

#### If the IP packet is to be forwarded
If we receive a packet that we need to forward, first I decrement the TTL and check to see if it becomes zero. If so, we don't have to spend our time on it and can send the ICMP error time exceeded (type 11) back to the sender. Then, before forwarding the packet, we look in our ARP cache for a matching IP->MAC mapping. If one exists (ARP cache hit), we simply forward the packet to that MAC address on the appropriate interface, found as described below. If no mapping is found (ARP cache miss), I call my ARP request sending handler and queue the packet. The handler will make sure to forward the packet as soon as we get an ARP reply from the target host. This handler is also called every second when the ARP cache is swept for ARP requests we are waiting on.

The outgoing interface we put the packet on is found using the preconfigured routing/forwarding table for this. The process is described on page 223 of the fifth edition of Computer Systems: A Networking Approach. Basically, we can find the next hop by looping through each entry in the routing table to bitwise AND each entry's subnet mask with the destination IP address. If this result is the same as the subnet number (the destination in our routing table), then we have found the matching interface we need to forward this packet to. In our sample routing table, there is technically no need for this since the mask is 255.255.255.255 and all the destinations equals each host when binary AND'ed together, but it still might be beneficial to implement this functionality, since who knows what other routing tables we may be tested on.

If the above subnet matching returns a result, look in ARP cache for the receiver IP->MAC mapping. We now have all the information we need to forward the packet, so rewrite the headers and forward it!

If the subnet mapping doesn't return any result, we have been asked to forward a packet to a destination we do not know about! So drop the packet and send an ICMP error message network unreachable (type 3, code 0) back to the sender.

### Header file changes
I started updating this section a week or two after implementing, so this list may not be complete. I plan to do diffs on the header files to find functions and enums I've added to ease development.
- sr_protocol.h
    - Added the protocol numbers for TCP (0x0006) and UDP (0x0011) to the sr_ip_protocol enum, used to check whether the router receives either type of packet so it can discard them (as pr. discussion slides).
    - Added sr_icmp_type_protocol and sr_icmp_code_protocol enums with the ICMP protocol control messages we need to respond with.
- sr_utils.h
    - Added many helper functions the bottom of this header file and the corresponding C source file. These functions include extracting header information from packets, sending ARP requests and replies, ICMP packets, the packet forwarding function, the subnetting function to find the outgoing interface for an IP, and the sanity checking functions of packets to make sure they meet the minimum length requirements and that they have a correct checksum.
- sr_arpcache.h
    - Added the sr_arpcache_handle_req_sending function, which has  the job of (re)sending or dropping outstanding ARP requests that we are waiting for ARP replies on.

## Requirements
I used this list during implementation to make sure I was on track and knew what I had to work on.
- The router must successfully route packets between the Internet and the application servers.
- The router must correctly handle ARP requests and replies.
- The router must correctly handle traceroutes through it (where it is not the end host) and to it (where it is the end host).
- The router must respond correctly to ICMP echo requests.
- The router must handle TCP/UDP packets sent to one of its interfaces. In this case the router should respond with an ICMP port unreachable.
- The router must maintain an ARP cache whose entries are invalidated after a timeout period (timeouts should be on the order of 15 seconds).
- The router must queue all packets waiting for outstanding ARP replies. If a host does not respond to 5 ARP requests, the queued packet is dropped and an ICMP host unreachable message is sent back to the source of the queued packet.
- The router must not needlessly drop packets (for example when waiting for an ARP reply)
- The router must enforce guarantees on timeouts--that is, if an ARP request is not responded to within a fixed period of time, the ICMP host unreachable message is generated even if no more packets arrive at the router. (Note: You can guarantee this by implementing the sr_arpcache_sweepreqs function in sr_arpcache.c correctly.)