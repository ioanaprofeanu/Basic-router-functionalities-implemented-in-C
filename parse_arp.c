// Profeanu Ioana, 323CA
// source file where the ARP protocol is implemented
#include "implement_router.h"

/**
 * @brief Send an arp reply once receiving an arp request
 * the purpose is to give out own mac address
 * @param ethernet_header the received packet's ethernet header
 * @param arp_header the received packet's arp header
 * @param m the received packet
 */
void send_arp_reply_packet(struct ether_header *ethernet_header,
				struct arp_header* arp_header, packet* m)
{
	// if the ip of the receiver found within the arp header
	// does not mach the interface, throw away the packet
	if (arp_header->tpa != inet_addr(get_interface_ip((*m).interface))) {
		return;
	}

	// extracted the router's interface ip and mac
	uint8_t interface_mac[6];
	get_interface_mac((*m).interface, interface_mac);

	// reverse the mac and ip addresses from sender to
	// receiver and from receiver to sender; the only difference
	// is that now in arp_header->sha and
	// ethernet_header->ether_shost we will have the mac address
	// the initial sender wanted to find out

	// keep the new sender and receiver mac addresses
	// in two auxiliary variables
	uint8_t mac_aux_sender[6], mac_aux_receiver[6];
	memcpy(mac_aux_sender, interface_mac, 6);
	memcpy(mac_aux_receiver, arp_header->sha, 6);

	memcpy(ethernet_header->ether_shost, mac_aux_sender, 6);
	memcpy(ethernet_header->ether_dhost, mac_aux_receiver, 6);

	memcpy(arp_header->sha, mac_aux_sender, 6);
	memcpy(arp_header->tha, mac_aux_receiver, 6);

	// keep the new sender and receiver ip addresses
	// in two auxiliary variables
	uint32_t ip_aux_sender, ip_aux_receiver;
	ip_aux_sender = arp_header->tpa;
	ip_aux_receiver = arp_header->spa;

	arp_header->spa = ip_aux_sender;
	arp_header->tpa = ip_aux_receiver;

	// change the operation type into reply
	arp_header->op = (htons)(ARPOP_REPLY);

	// send the packet
	send_packet(m);
}

/**
 * @brief When not finding the destination's ip and mac addresses within
 * the arp table, send an arp request to the future destination in order to
 * find out its mac address
 * @param ethernet_header the packet's ethernet header
 * @param best_route_entry the matched best route in the rtable
 */
void send_arp_request_packet(struct ether_header* ethernet_header,
	struct route_table_entry* best_route_entry)
{
	// update the internet header
	// the sender mac will be the interface of the best route
	uint8_t mac_aux_sender[6], mac_aux_receiver[6];
	get_interface_mac(best_route_entry->interface, mac_aux_sender);
	memcpy(ethernet_header->ether_shost, mac_aux_sender, 6);

	// the mac destination will be the broadcast address
	for (int i = 0; i < 6; i++) {
		mac_aux_receiver[i] = 0xFF;
	}
	// add the receiver mac to the header and change the ethernet type
	memcpy(ethernet_header->ether_dhost, mac_aux_receiver, 6);
	ethernet_header->ether_type = htons(ETHERTYPE_ARP);

	// keep the ip addresses in auxiliary variables
	uint32_t ip_aux_sender = inet_addr(get_interface_ip
							(best_route_entry->interface));
	uint32_t ip_aux_receiver = best_route_entry->next_hop;
	
	// create a new arp header and add its data
	struct arp_header new_arp_header;
	new_arp_header.htype = htons(ARPHRD_ETHER);
	new_arp_header.ptype = htons(2048);
	new_arp_header.op = htons(ARPOP_REQUEST);
	new_arp_header.hlen = 6;
	new_arp_header.plen = 4;
	memcpy(new_arp_header.sha, mac_aux_sender, 6);
	memcpy(new_arp_header.tha, mac_aux_receiver, 6);
	new_arp_header.spa = ip_aux_sender;
	new_arp_header.tpa = ip_aux_receiver;

	// create a new packet and add its data
	packet new_packet;
	new_packet.interface = best_route_entry->interface;
	// add the ethernet and arp headers
	memcpy(new_packet.payload, ethernet_header, sizeof(struct ether_header));
	memcpy(new_packet.payload + sizeof(struct ether_header), &new_arp_header,
			sizeof(struct arp_header));
	new_packet.len = sizeof(struct arp_header) + sizeof(struct ether_header);
	send_packet(&new_packet);
}

/**
 * @brief When receiving an arp reply, parse the received data (more
 * specifically, the sender mac address) and send the packages within the
 * queue
 * @param arp_header the reply packet's arp header
 * @param rtable the route table
 * @param rtable_size the route table size
 * @param arp_table the arp table
 * @param arp_table_size the arp table size
 * @param packets_queue the queue of packets
 */
void parse_arp_reply_packet(struct arp_header* arp_header,
							struct route_table_entry* rtable,
							int rtable_size, struct arp_entry* arp_table,
							int *arp_table_size, queue packets_queue)
{
	// extract the sender mac and ip addresses (which will be the destination
	// in the to-be-send packet)
	uint8_t mac_destination[6];
	memcpy(mac_destination, arp_header->sha, 6);
	uint32_t ip_destination = arp_header->spa;
	// add the new received mac address in the arp table, if it
	// doesn't already exist
	if (get_arp_entry(ip_destination, *arp_table_size, arp_table) == NULL) {
		arp_table[*arp_table_size].ip = ip_destination;
		memcpy(arp_table[*arp_table_size].mac, mac_destination, 6);
		(*arp_table_size)++;
	}

	// dequeue the packets and send them, if we find the arp entry in the
	// arp table
	while (!queue_empty(packets_queue)) {
		// dequeue the packet from the queue
		packet *current_packet = (packet*) queue_deq(packets_queue);
		// extract the ip header
		struct iphdr* current_ip_header = (struct iphdr *)
					(current_packet->payload + sizeof(struct ether_header));
		// get the best route from the rtable and the matching entry for the
		/// best route in the arp table
		struct route_table_entry* best_route_entry = get_best_route
					(current_ip_header->daddr, rtable_size, rtable);
		struct arp_entry* dest_arp_entry = get_arp_entry
					(best_route_entry->next_hop, *arp_table_size, arp_table);

		// if no arp entry matches, enqueue the packet and end iteration
		if (dest_arp_entry == NULL) {
			queue_enq(packets_queue, current_packet);
			return;
		}
		// extract the ethernet header and copy the destination mac to it
		struct ether_header * current_ethernet_header = (struct ether_header*)
					current_packet->payload;
		memcpy(current_ethernet_header->ether_dhost, dest_arp_entry->mac, 6);
		// send the packet
		send_packet(current_packet);
	}
}
