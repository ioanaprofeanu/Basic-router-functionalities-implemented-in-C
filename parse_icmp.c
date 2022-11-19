// Profeanu Ioana, 323CA
// source file where the ICMP protocol is implemented
#include "implement_router.h"

/**
 * @brief Send an icmp error in case of time limit excedeed or in case of
 * not finding the best route in the rtable
 * @param ethernet_header the packet's ethernet header
 * @param ip_header the packet's ip header
 * @param m the packet
 * @param type the type of the icmp packet
 * @param code the code of the icmp packet
 */
void error_send_icmp(struct ether_header *ethernet_header,
					struct iphdr* ip_header, packet *m,
					u_int8_t type, u_int8_t code)
{
	// retrieve the sender and destination ip and mac addresses;
	// their place will be reversed in the new package (sender will be
	// receiver and receiver will be sender)
	uint32_t ip_aux_sender = ip_header->daddr, ip_aux_receiver =
					ip_header->saddr;
	uint8_t mac_aux_sender[6], mac_aux_receiver[6];
	memcpy(mac_aux_sender, ethernet_header->ether_dhost, 6);
	memcpy(mac_aux_receiver, ethernet_header->ether_shost, 6);

	// change the data of the ethernet header
	ethernet_header->ether_type = htons(ETHERTYPE_IP);
	memcpy(ethernet_header->ether_shost, mac_aux_sender, ETH_ALEN);
	memcpy(ethernet_header->ether_dhost, mac_aux_receiver, ETH_ALEN);

	// change the data of the ip header
	ip_header->protocol = IPPROTO_ICMP;
	// the length will include an additional 64 bytes from the
	// original data
	ip_header->tot_len = htons(sizeof(struct iphdr)
						+ sizeof(struct icmphdr) + 64);
	ip_header->ttl = 64;
	ip_header->daddr = ip_aux_receiver;
	ip_header->saddr = ip_aux_sender;
	ip_header->check = ip_checksum((uint8_t*)&ip_header, sizeof(struct iphdr));

	// create a new icmp header
	// change its data
	struct icmphdr icmp_header;
	icmp_header.type = type;
	icmp_header.code = code;
	// the chesksum will be calculated starting with the header, all the way to
	// the end of the packet (including the 64 bytes from the original data)
	icmp_header.checksum = icmp_checksum((uint16_t*)&icmp_header,
						sizeof(struct icmphdr) + 64);

	// create a new packet
	packet packet;
	void *payload = packet.payload;
	packet.interface = m->interface;
	// add its headers
	memcpy(payload, ethernet_header, sizeof(struct ether_header));
	memcpy(payload + sizeof(struct ether_header),
			ip_header, sizeof(struct iphdr));
	memcpy(payload + sizeof(struct ether_header) + sizeof(struct iphdr),
			&icmp_header, sizeof(struct icmphdr));
	// add the additional 64 bytes from the original message's data
	memcpy(payload + sizeof(struct ether_header) + sizeof(struct iphdr)
			+ sizeof(struct icmphdr), m->payload + sizeof(struct ether_header)
			+ sizeof(struct iphdr), 64);
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr)
			+ sizeof(struct icmphdr) + 64;
	// send the packet
	send_packet(&packet);
}

/**
 * @brief Once receiving a ping request, send a ping reply to the sender
 * @param ethernet_header the packet's ethernet header
 * @param ip_header the packet's ip header
 * @param icmp_header the packet's icmp header
 * @param m the packet
 */
void ping_send_reply_icmp(struct ether_header *ethernet_header,
					struct iphdr* ip_header, struct icmphdr* icmp_header,
					packet *m)
{
	// retrieve the sender and destination ip and mac addresses;
	// their place will be reversed in the new package (sender will be
	// receiver and receiver will be sender) 
	uint32_t ip_aux_sender = ip_header->daddr;
	uint32_t ip_aux_receiver = ip_header->saddr;
	uint8_t mac_aux_sender[6], mac_aux_receiver[6];
	memcpy(mac_aux_sender, ethernet_header->ether_dhost, 6);
	memcpy(mac_aux_receiver, ethernet_header->ether_shost, 6);

	// change the data of the ethernet header
	ethernet_header->ether_type = htons(ETHERTYPE_IP);
	memcpy(ethernet_header->ether_shost, mac_aux_sender, ETH_ALEN);
	memcpy(ethernet_header->ether_dhost, mac_aux_receiver, ETH_ALEN);

	// create a new ip header
	// change its data
	struct iphdr new_ip_header;
	new_ip_header.version = 4;
	new_ip_header.ihl = 5;
	new_ip_header.tos = 0;
	new_ip_header.protocol = IPPROTO_ICMP;
	// the length will include an additional 64 bytes from the
	// original data
	new_ip_header.tot_len = htons(sizeof(struct iphdr)
							+ sizeof(struct icmphdr) + 64);
	new_ip_header.id = htons(1);
	new_ip_header.frag_off = 0;
	new_ip_header.ttl = 64;
	new_ip_header.check = 0;
	new_ip_header.daddr = ip_aux_receiver;
	new_ip_header.saddr = ip_aux_sender;
	new_ip_header.check = ip_checksum((uint8_t*)&new_ip_header,
						sizeof(struct iphdr));

	// create a new icmp header
	// change its data
	struct icmphdr new_icmp_header;
	new_icmp_header.un.echo.id = icmp_header->un.echo.id;
	new_icmp_header.un.echo.sequence = icmp_header->un.echo.id;
	new_icmp_header.type = 0;
	new_icmp_header.code = 0;
	// the chesksum will be calculated starting with the header, all the way to
	// the end of the packet (including the 64 bytes from the original data)
	new_icmp_header.checksum = icmp_checksum((uint16_t*)&new_icmp_header,
						sizeof(struct icmphdr) + 64);

	// create a new packet
	packet packet;
	void *payload = packet.payload;
	packet.interface = m->interface;
	// add its headers
	memcpy(payload, ethernet_header, sizeof(struct ether_header));
	memcpy(payload + sizeof(struct ether_header), &new_ip_header,
						sizeof(struct iphdr));
	memcpy(payload + sizeof(struct ether_header) + sizeof(struct iphdr),
						&new_icmp_header, sizeof(struct icmphdr));
	// add the additional 64 bytes from the original message's data
	memcpy(payload + sizeof(struct ether_header) + sizeof(struct iphdr)
						+ sizeof(struct icmphdr), m->payload
						+ sizeof(struct ether_header)
						+ sizeof(struct iphdr), 64);
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr)
				+ sizeof(struct icmphdr);
	send_packet(&packet);
}
