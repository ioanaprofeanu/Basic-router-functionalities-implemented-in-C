// Profeanu Ioana, 323CA
// source file with the main function where the flow of the program
// is implemented
#include "implement_router.h"

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;

	// create the queue used to store the waiting packages
	queue packets_queue = queue_create();

	// initialise the route table
	int rtable_size;
	struct route_table_entry* rtable = initialise_rtable
								(&rtable_size, argv[1]);

	// initialise the ARP table
	int arp_table_size = 0;
	struct arp_entry* arp_table = initialise_arp_table();

	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		// extract the ethernet header
		struct ether_header *ethernet_header = (struct ether_header*)m.payload;

		// check if the package type is ARP
		// it means that we received a packet for the router,
		// with the purpose of giving the mac address of the
		// interface which received the request
		if (ethernet_header->ether_type == (htons)(ETHERTYPE_ARP)) {
			// extract the arp header
			struct arp_header* arp_header = (struct arp_header*)
						(m.payload + sizeof(struct ether_header));
			// if the ARP operation is a request
			if (arp_header->op == (htons)(ARPOP_REQUEST)) {
				// send an arp reply packet
				send_arp_reply_packet(ethernet_header, arp_header, &m);
				continue;
			// if the ARP operation is a reply
			} else if (arp_header->op == (htons)(ARPOP_REPLY)) {
				// parse the received reply
				parse_arp_reply_packet(arp_header, rtable,
				rtable_size, arp_table, &arp_table_size, packets_queue);
				continue;
			}
		}

		// check if the package type is IP
		if (ethernet_header->ether_type == (htons)(ETHERTYPE_IP)) {
			// extract the ip header
			struct iphdr* ip_header = (struct iphdr*)(m.payload
									+ sizeof(struct ether_header));

			// if it's an icmp protocol
			if (ip_header->protocol == 1) {
				/// extract the icmp header
				struct icmphdr* icmp_header = (struct icmphdr*)
							(m.payload + sizeof(struct ether_header)
							+ sizeof(struct iphdr));
				// verify if it's a ping (echo request)
				if (icmp_header->type == 8 && icmp_header->code == 0) {
					// send ping reply
					ping_send_reply_icmp(ethernet_header, ip_header,
							icmp_header, &m);
					continue;
				}
			}

			// check the checksum as required by IPv4
			if (ip_checksum((void *) ip_header, sizeof(struct iphdr)) != 0) {
				continue;
			}

			// check if TTL >= 1
			if (ip_header->ttl <= 1) {
				// send an icmp error, with the time exceeded type and code
				error_send_icmp(ethernet_header, ip_header, &m, 11, 0);
				continue;
			} else {
				// change the checksum
				ip_header->check = bonus_get_new_checksum(ip_header);
			}

			// get the best route for the destination address within the
			// ip header
			struct route_table_entry* best_route_entry = get_best_route
							(ip_header->daddr, rtable_size, rtable);
			// check if a best matching route was found;
			// if not, send icmp error packet
			if (best_route_entry == NULL) {
				// send an icmp error, with the no destination found
				// type and code
				error_send_icmp(ethernet_header, ip_header, &m, 3, 0);
			}

			// get the matching entry in the arp table for the best route's
			// next hop (where the packet will be sent next)
			struct arp_entry* dest_arp_entry = get_arp_entry
					(best_route_entry->next_hop, arp_table_size, arp_table);
			// prepare the packet for sending
			prepare_packet(best_route_entry, dest_arp_entry,
					&m, ethernet_header);

			// if no matching arp entry is found
			if (dest_arp_entry == NULL) {
				// add the packet to the packets queue
				packet* to_enqueue_packet = (packet*)calloc(1, sizeof(packet));
				DIE(!to_enqueue_packet, "Error calloc to_enqueue_packet");
				memcpy(to_enqueue_packet, &m, sizeof(packet));
				queue_enq(packets_queue, to_enqueue_packet);
				// send an arp request for the receiver's mac address
				send_arp_request_packet(ethernet_header, best_route_entry);
				continue;
			} else {
				// if we already know the mac of the receiver, add it to the
				// ethernet header and send the packet
				memcpy(ethernet_header->ether_dhost, dest_arp_entry->mac, 6);
				send_packet(&m);
				continue;
			}
		}
	}

	// free the route table and the arp table
	free(rtable);
	free(arp_table);
}
