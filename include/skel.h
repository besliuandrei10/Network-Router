#ifndef _SKEL_H_
#define _SKEL_H_

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>
/* ethheader */
#include <net/ethernet.h>
/* ether_header */
#include <arpa/inet.h>
/* icmphdr */
#include <netinet/ip_icmp.h>
/* arphdr */
#include <net/if_arp.h>
#include <asm/byteorder.h>

/*
 *Note that "buffer" should be at least the MTU size of the
 * interface, eg 1500 bytes
 */
#define MAX_LEN 1600
#define ROUTER_NUM_INTERFACES 3

#define DIE(condition, message) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[(%s:%d)]: %s\n", __FILE__, __LINE__, (message)); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

typedef struct {
	int len;
	char payload[MAX_LEN];
	int interface;
} packet;

/* Ethernet ARP packet from RFC 826 */
struct arp_header {
	uint16_t htype;   /* Format of hardware address */
	uint16_t ptype;   /* Format of protocol address */
	uint8_t hlen;    /* Length of hardware address */
	uint8_t plen;    /* Length of protocol address */
	uint16_t op;    /* ARP opcode (command) */
	uint8_t sha[ETH_ALEN];  /* Sender hardware address */
	uint32_t spa;   /* Sender IP address */
	uint8_t tha[ETH_ALEN];  /* Target hardware address */
	uint32_t tpa;   /* Target IP address */
} __attribute__((packed));

/* Route table entry */
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

/* ARP table entry when skipping the ARP exercise */
struct arp_entry {
    __u32 ip;
    uint8_t mac[6];
};

extern int interfaces[ROUTER_NUM_INTERFACES];

/**
 * @brief Sends a packet on an interface.
 *
 * @param m packet
 * @return int
 */
int send_packet(packet *m);
/**
 * @brief Blocking function for receiving packets.
 * Returns -1 in exceptional conditions.
 *
 * @param m
 * @return int
 */
int get_packet(packet *m);

/**
 * @brief Get the interface ip object.
 *
 * @param interface
 * @return char*
 */
char *get_interface_ip(int interface);

/**
 * @brief Get the interface mac object. The function writes
 * the MAC at the pointer mac. uint8_t *mac should be allocated.
 *
 * @param interface
 * @param mac
 */
void get_interface_mac(int interface, uint8_t *mac);

/**
 * @brief Homework infrastructure function.
 *
 * @param argc
 * @param argv
 */
void init(int argc, char *argv[]);

/**
 * @brief ICMP checksum per RFC 792. To compute the checksum
 * of an ICMP header we must set the checksum to 0 beforehand.
 *
 * @param data memory area to checksum
 * @param size in bytes
 */
uint16_t icmp_checksum(uint16_t *data, size_t size);

/**
 * @brief IPv4 checksum per  RFC 791. To compute the checksum
 * of an IP header we must set the checksum to 0 beforehand.
 *
 * @param data memory area to checksum
 * @param size in bytes
 */
uint16_t ip_checksum(uint8_t *data, size_t size);

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

/* Populates a route table from file, rtable should be allocated
 * e.g. rtable = malloc(sizeof(struct route_table_entry) * 80000);
 * This function returns the size of the route table.
 */
int read_rtable(const char *path, struct route_table_entry *rtable);

/* Parses a static mac table from path and populates arp_table.
 * arp_table should be allocated and have enough space. This
 * function returns the size of the arp table.
 * */
int parse_arp_table(char *path, struct arp_entry *arp_table);

#endif /* _SKEL_H_ */
