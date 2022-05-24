#include "queue.h"
#include "skel.h"
#define ICMP_ERROR_DATA_BYTES 64
#define TRAILER_DATA 64
#define DEFAULT_TTL 64
#define ICMP_ERROR_LEN 92

// Init Router Structures
struct Trie *trieHead = NULL;
struct queue *waitingPackets = NULL;
struct arp_entry *arptable = NULL;
int arptable_len = -1;

typedef struct Trie {
	uint32_t nextHop;
	uint32_t mask;
	uint32_t prefix;
	int interface;

	// Mark whether node represents a route or not.
	// 1 = true, 0 = false
	int marked;

	struct Trie *l;
	struct Trie *r;
}Trie;

// Helpful functions used throughout.
packet* copyPacket(packet *p) {
	packet *copy = malloc(sizeof(packet));

	copy->len = p->len;
	memcpy(copy->payload, p->payload, sizeof(copy->payload));
	copy->interface = p->interface;

	return copy;
}

Trie* allocNode() {
	Trie *output = malloc(sizeof(Trie));

	output->l = NULL;
	output->r = NULL;

	output->marked = 0;
	output->interface = 0;
	output->mask = 0;
	output->prefix = 0;
	output->nextHop = 0;

	return output;
}

int maskToSlash(uint32_t mask) {
	unsigned int count = 0;
	while (mask) {
			count += mask & 1;
			mask >>= 1;
	}
	return count;
}

void parseRoutingTable(const char *path, struct Trie* head) {
	FILE *fp = fopen(path, "r");
	char *p, line[64];

	uint32_t prefix;
	uint32_t mask;
	uint32_t nextHop;
	int interface;

	while (fgets(line, sizeof(line), fp) != NULL) {
		// Read entries from static table.

		struct in_addr tmp;

		// Network Address
		p = strtok(line, " ");
		inet_aton(p, &tmp);
		prefix = ntohl(tmp.s_addr);
		// inet_aton() returns in network order, get it in host order.

		// Next-hop
		p = strtok(NULL, " ");
		inet_aton(p, &tmp);
		nextHop = ntohl(tmp.s_addr);

		// Subnet Mask
		p = strtok(NULL, " ");
		inet_aton(p, &tmp);
		mask = ntohl(tmp.s_addr);

		// Interface
		p = strtok(NULL, " ");
		interface = atoi(p);

		// Parse Trie and insert route where appropiate.
		Trie* curr = head;
		uint32_t i = 1 << 31; // left most bit of prefix

		// It can process default routes as well.
		int maskEnd = 32 - maskToSlash(mask);
		int currentBit = 32;
		while(1) {

			if (currentBit == maskEnd) {
				curr->interface = interface;
				curr->mask = mask;
				curr->prefix = prefix;
				curr->nextHop = nextHop;

				curr->marked = 1;
				break;
			} else {
				int bit = prefix & i;
				// Left = 0, Right = 1;
				if (bit) {
					if (curr->r == NULL) {
						curr->r = allocNode();
						curr = curr->r;
					} else curr = curr->r;
				} else {
					if (curr->l == NULL) {
						curr->l = allocNode();
						curr = curr->l;
					} else curr = curr->l;
				}

				// Next bit of prefix
				i = i >> 1;
				--currentBit;
			}
		}

	}
}

Trie* findRouteNode(uint32_t ipAddress, Trie* head) {
	Trie* curr = head;
	Trie* lastMarked = NULL;
	int currentBit = 31;

	// Search until we run in a dead end.
	// Left = 0, Right = 1;
	while(1) {

		if (curr->marked == 1) lastMarked = curr;

		if ((ipAddress >> currentBit) & 1) {
			if (curr->r == NULL) break;
			curr = curr->r;
		} else {
			if (curr->l == NULL) break;
			curr = curr->l;
		}
		--currentBit;
	}
	return lastMarked;
}

struct arp_entry *get_arp_entry(uint32_t dest_ip) {
  for (int i = 0; i < arptable_len; i++) {
    if (arptable[i].ip == dest_ip) {
    	return &arptable[i];
    }
  }
  return NULL;
}

int checksumCheck(struct iphdr *ip_hdr) {

	uint16_t old_checksum = ip_hdr->check;
	ip_hdr->check = 0;

	uint16_t new_checksum = ip_checksum((uint8_t*) (ip_hdr), sizeof(struct iphdr));
	ip_hdr->check = new_checksum;

	if (old_checksum != new_checksum) return -1;
	return 0;
}

uint16_t rfc1624(uint16_t oldTTL, uint16_t newTTL, uint16_t oldCheck) {
	// Done using Eqn. 3 from RFC1624
	uint16_t m = ~ntohs(oldTTL);
	uint16_t newM = ntohs(newTTL);
	uint16_t oldChecksum = ~ntohs(oldCheck);

	// Add in a uint32_t in order to preserve carry bits.
	uint32_t sum = (uint32_t)(oldChecksum + m + newM);
	// 1's complement addition.
	return htons(~((uint16_t)(sum >> 16) + (sum & 0xffff)));

}


// ARP-related functions.
void arpReply(packet *m) {
	struct in_addr myIP;
	inet_aton(get_interface_ip(m->interface), &myIP);

	// Extract Headers
	struct ether_header *eth_hdr = (struct ether_header*) m->payload;
	struct arp_header *arphdr = (struct arp_header*)(m->payload + sizeof(struct ether_header));

	// Complete ARP header.
	arphdr->op = htons(ARPOP_REPLY);

	// Target becomes Source
	arphdr->tpa = arphdr->spa;
	memcpy(arphdr->tha, arphdr->sha, sizeof(arphdr->tha));

	// Source Becomes me.
	get_interface_mac(m->interface, arphdr->sha);
	arphdr->spa = myIP.s_addr;

	// Complete Ethernet header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	get_interface_mac(m->interface, eth_hdr->ether_shost);

	send_packet(m);
}

void populateARPTable(packet *m) {
	struct in_addr myIP;
	inet_aton(get_interface_ip(m->interface), &myIP);
	struct arp_header *arphdr = (struct arp_header*)(m->payload + sizeof(struct ether_header));

	// If I sent the packet
	if (arphdr->tpa == myIP.s_addr) {

		// Enter entry in table.
		arptable[arptable_len].ip = arphdr->spa;
		memcpy(arptable[arptable_len].mac, arphdr->sha, sizeof(arphdr->tha));

		// Dequeue and send packets.
		while(!queue_empty(waitingPackets)) {
			packet *p = queue_deq(waitingPackets);

			struct ether_header *eth_hdr = (struct ether_header*) p->payload;
			memcpy(eth_hdr->ether_dhost, arptable[arptable_len].mac, sizeof(arptable[arptable_len].mac));
			send_packet(p);
			free(p);
		}

		// Increment table length.
		++arptable_len;
	}

}

void arpRequest(uint32_t targetIP, int interface) {

	// Create ARP Request frame.
	packet output;
	output.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	output.interface = interface;

	struct ether_header *reqEthernet = (struct ether_header*) output.payload;
	struct arp_header *arphdr = (struct arp_header*)(output.payload + sizeof(struct ether_header));

	struct in_addr myIP;
	inet_aton(get_interface_ip(interface), &myIP);

	// Set frame type to ARP
	reqEthernet->ether_type = htons(ETHERTYPE_ARP);

	// Set MAC adresses.
	hwaddr_aton("FF:FF:FF:FF:FF:FF", reqEthernet->ether_dhost);
	get_interface_mac(interface, reqEthernet->ether_shost);

	// Set ARP header details
	arphdr->htype = htons(ARPHRD_ETHER);
	arphdr->ptype = htons(ETHERTYPE_IP);
	arphdr->hlen = 6; // only one byte, no need for hton
	arphdr->plen = 4;
	arphdr->op = htons(ARPOP_REQUEST);

	// Set ARP header adresses.
	memcpy(arphdr->sha, reqEthernet->ether_shost, sizeof(reqEthernet->ether_shost));
	arphdr->spa = myIP.s_addr;

	memset(arphdr->tha, 0, sizeof(reqEthernet->ether_shost));
	arphdr->tpa = targetIP;

	send_packet(&output);
}

// All-purpose routing function.
int routePacket(packet *m) {

	struct ether_header *eth_hdr = (struct ether_header *) m->payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m->payload + sizeof(struct ether_header));

	if (ip_hdr->ttl <= 1) return ICMP_TIME_EXCEEDED;

	// Check IPv4
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

		// Find route.
		struct in_addr dest_ip;
		dest_ip.s_addr = ip_hdr->daddr;

		Trie* route = findRouteNode(ntohl(dest_ip.s_addr), trieHead);

		if (route == NULL) return ICMP_DEST_UNREACH;

		// Find Neighbor
		struct arp_entry *neighbour = get_arp_entry(htonl(route->nextHop));
		if (neighbour == NULL) {
			arpRequest(htonl(route->nextHop), route->interface);

			// Update TTL and Recalculate checksum of packet to be stored.
			ip_hdr->check = rfc1624(ip_hdr->ttl, ip_hdr->ttl - 1, ip_hdr->check);
			ip_hdr->ttl = ip_hdr->ttl - 1;

			// Put the source address because we know that as well.
			get_interface_mac(route->interface, eth_hdr->ether_shost);

			// Set interface.
			m->interface = route->interface;

			// Queue it up.
			queue_enq(waitingPackets, copyPacket(m));
			return -1;
		}

		// Update TTL and recalculate Checksum
		ip_hdr->check = rfc1624(ip_hdr->ttl, ip_hdr->ttl - 1, ip_hdr->check);
		ip_hdr->ttl = ip_hdr->ttl - 1;

		// Update MAC addresses.
		memcpy(eth_hdr->ether_dhost, neighbour->mac, sizeof(neighbour->mac));
		get_interface_mac(route->interface, eth_hdr->ether_shost);

		// Set interface to send packet (frame in actuality) on.
		m->interface = route->interface;
		return 0;
	} else return -1;
}

// ICMP-related functions.
void echoError(packet *m, uint16_t type) {
	packet newP;

	struct ether_header *old_eth_hdr = (struct ether_header *) m->payload;
	struct iphdr *old_ip_hdr = (struct iphdr *)(m->payload + sizeof(struct ether_header));

	struct ether_header *eth_hdr = (struct ether_header *) newP.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(newP.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(newP.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	char *dataPointer = (char *)(newP.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	// Copy error data.
	memcpy(dataPointer, old_ip_hdr, ICMP_ERROR_DATA_BYTES);

	// Set interface
	newP.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + TRAILER_DATA;
	newP.interface = m->interface;

	// Set MAC adresses
	memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, sizeof(old_eth_hdr->ether_shost));
	get_interface_mac(m->interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

	// Reuse most of old IP header.
	memcpy(ip_hdr, old_ip_hdr, sizeof(struct iphdr));

	// Set IP Adresses
	struct in_addr myIP;
	inet_aton(get_interface_ip(m->interface), &myIP);

	ip_hdr->daddr = old_ip_hdr->saddr;
	ip_hdr->saddr = myIP.s_addr;

	//TTL and Checksum
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->ttl = DEFAULT_TTL;
	ip_hdr->check = 0;
	ip_hdr->tot_len = htons(ICMP_ERROR_LEN);
	ip_hdr->check = ip_checksum((uint8_t*) (ip_hdr), sizeof(struct iphdr));

	//ICMP Header
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;

	uint16_t new_icmp_checksum = icmp_checksum((uint16_t*)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));
	icmp_hdr->checksum = new_icmp_checksum;

	send_packet(&newP);
}

void echoReply(packet *m) {
	struct ether_header *eth_hdr = (struct ether_header *) m->payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m->payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m->payload + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Switch MAC adresses around.
	unsigned char auxMAC[6];
	memcpy(auxMAC, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	memcpy(eth_hdr->ether_dhost, auxMAC, sizeof(auxMAC));

	// Switch IP adresses around.
	uint32_t auxIP;
	auxIP = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = auxIP;

	// Modify ICMP header
	icmp_hdr->type = ICMP_ECHOREPLY;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;

	uint16_t new_icmp_checksum = icmp_checksum((uint16_t*)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));
	icmp_hdr->checksum = new_icmp_checksum;

	// Update TTL, Recalculate checksum
	ip_hdr->check = rfc1624(ip_hdr->ttl, ip_hdr->ttl - 1, ip_hdr->check);
	ip_hdr->ttl = ip_hdr->ttl - 1;

	// Away it goes.
	send_packet(m);
}

// Begin Main function.
int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Trie Stuff
	trieHead = malloc(sizeof(struct Trie));
	trieHead->l = NULL;
	trieHead->r = NULL;
	trieHead->marked = 0;
	if(argv[1] == NULL) {
		printf("Usage: ./router <routeTable> <Interfaces>\n");
		return 0;
	}
	parseRoutingTable(argv[1], trieHead);

	// Allocate structures.
	waitingPackets = queue_create();
	arptable = malloc(sizeof(struct arp_entry) * 80000);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// Extract Ethernet header
		struct ether_header *eth_hdr = (struct ether_header *) m.payload;

		struct in_addr myIP;
		inet_aton(get_interface_ip(m.interface), &myIP);

		// If IPv4
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

			// Extract some more Headers
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

			// Utterly stupid check, if source address is mine, don't duplicate packets.
			if (ip_hdr->saddr == myIP.s_addr) continue;
			if (checksumCheck(ip_hdr) == -1) continue;

			// Check if packet is ICMP and act accordingly.
			if (ip_hdr->protocol == IPPROTO_ICMP) {
				// Check if packet is meant for me
				if(myIP.s_addr == ip_hdr->daddr) {
					if (icmp_hdr->type == ICMP_ECHO) {
						// Mandatory TTL check.
						if(ip_hdr->ttl <= 1) echoError(&m, ICMP_TIME_EXCEEDED);
						else echoReply(&m);
						continue;
					} else {
						continue;
					}
				}
			}

			switch(routePacket(&m)) {
				case 0:
				send_packet(&m);
				break;

				case -1:
				continue;
				break;

				case ICMP_DEST_UNREACH:
				echoError(&m, ICMP_DEST_UNREACH);
				break;

				case ICMP_TIME_EXCEEDED:
				echoError(&m, ICMP_TIME_EXCEEDED);
				break;

				default: continue;
			}

		} else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {

			// Extract ARP header
			struct arp_header *arphdr = (struct arp_header*)(m.payload + sizeof(struct ether_header));

			// Daca este ARP reply, add data to table and send queued packets.
			if (ntohs(arphdr->op) == ARPOP_REPLY) {
				populateARPTable(&m);
				continue;
			} else if (ntohs(arphdr->op) == ARPOP_REQUEST) {
				if (arphdr->tpa == myIP.s_addr) arpReply(&m);
				continue;
			}

		}
	}

}
