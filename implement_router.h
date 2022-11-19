// Profeanu Ioana, 323CA
// header for the functions used throghout the program
#ifndef IMPLEMENT_ROUTER_H
#define IMPLEMENT_ROUTER_H
#include "queue.h"
#include "skel.h"

struct route_table_entry* initialise_rtable(int* rtable_size, char* path);

struct arp_entry* initialise_arp_table();

struct arp_entry* get_arp_entry(uint32_t dest_ip, int arp_table_size,
						struct arp_entry* arp_table);

struct route_table_entry *get_best_route(uint32_t dest_ip, int rtable_len,
									struct route_table_entry* rtable);

void send_arp_reply_packet(struct ether_header *ethernet_header,
				struct arp_header* arp_header, packet* m);

void send_arp_request_packet(struct ether_header* ethernet_header,
	struct route_table_entry* best_route_entry);

void parse_arp_reply_packet(struct arp_header* arp_header,
							struct route_table_entry* rtable,
							int rtable_size, struct arp_entry* arp_table,
							int *arp_table_size, queue packets_queue);

void prepare_packet(struct route_table_entry* best_route_entry,
			struct arp_entry* dest_arp_entry, packet* m,
			struct ether_header* ethernet_header);

void error_send_icmp(struct ether_header *ethernet_header,
					struct iphdr* ip_header, packet *m,
					u_int8_t type, u_int8_t code);

void ping_send_reply_icmp(struct ether_header *ethernet_header,
					struct iphdr* ip_header, struct icmphdr* icmp_header,
					packet *m);

uint16_t bonus_get_new_checksum(struct iphdr* ip_header);

#endif
