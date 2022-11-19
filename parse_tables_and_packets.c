// Profeanu Ioana, 323CA
// source file where the parsing of the packages, route and arp tables
// is implemented
#include "implement_router.h"

/**
 * @brief Function which initializes and sorts the rtable
 * 
 * @param rtable_size the size of the rtable
 * @param path the path from which the rtable is parsed
 * @return route_table_entry* the initialized rtable
 */
struct route_table_entry* initialise_rtable(int* rtable_size, char* path)
{
	// allocate memory for the rtable
	struct route_table_entry *rtable = (struct route_table_entry*)
				calloc(ROUTER_MAX_ENTRIES, sizeof(struct route_table_entry));
	DIE(!rtable, "Error calloc rtable");
	// use the read table function
	*rtable_size = read_rtable(path, rtable);

	return rtable;
}

/**
 * @brief Function which initializes the arp table
 * 
 * @return struct arp_entry* the newly created arp table
 */
struct arp_entry* initialise_arp_table()
{
	// allocate memory for the arp table
	struct arp_entry* arp_table = (struct arp_entry*)
				calloc(ARP_TABLE_MAX_ENTRIES, sizeof(struct arp_entry));
	DIE(!arp_table, "Error calloc arp_entry");

	return arp_table;
}

/**
 * @brief Get the arp entry based on a given ip
 * 
 * @param dest_ip the destination ip we want to find the arp entry for
 * @return struct arp_entry* the result arp entry
 */
struct arp_entry* get_arp_entry(uint32_t dest_ip, int arp_table_size,
						struct arp_entry* arp_table)
{
	// iterate through the arp table and check if the ip
	// matches the destination ip
	for (int i = 0; i < arp_table_size; i++) {
		if (dest_ip == arp_table[i].ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

/**
 * @brief Return the best matching route depending on the given ip destination
 * by liniary checking the values within the route table
 * @param dest_ip the destination ip
 * @param rtable_len the length of the rtable
 * @param rtable the rtable
 * @return struct route_table_entry* 
 */
struct route_table_entry *get_best_route(uint32_t dest_ip, int rtable_len,
									struct route_table_entry* rtable)
{
	size_t idx = -1;

	// iterate through the rtable and check if the entry is suitable;
    for (size_t i = 0; i < rtable_len; i++) {
        if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
			// if it is the first match entry we encountered,
			// keep its index 
	    	if (idx == -1) {
				idx = i;
			// if it isn't the first and the previous found match
			// has a lower mask, change the index to the current one
			} else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) {
				idx = i;
			}
		}
    }

	// return the rtable entry (or null if not found)
    if (idx == -1) {
        return NULL;
	} else {
        return &rtable[idx];
	}
}

/**
 * @brief Prepare the packet for sending by changing its sender mac address in
 * the ethernet header and the ip addresses in te ip header
 * @param best_route_entry the matched best route
 * @param dest_arp_entry the matched arp entry
 * @param m the packet
 * @param ethernet_header the packet's ethernet header
 */
void prepare_packet(struct route_table_entry* best_route_entry,
			struct arp_entry* dest_arp_entry, packet* m,
			struct ether_header* ethernet_header)
{
	// get the new sender's mac address from the best route's interface
	// and add it to the ethernet header
	uint8_t mac_aux_sender[6];
	get_interface_mac(best_route_entry->interface, mac_aux_sender);
	memcpy(ethernet_header->ether_shost, mac_aux_sender, 6);
	// if the matched arp entry exists, then change the destination mac address
	// in the ethernet header
	if (dest_arp_entry != NULL) {
		memcpy(ethernet_header->ether_dhost, dest_arp_entry->mac, 6);
	}
	// change the packet's interface
	m->interface = best_route_entry->interface;
}

/**
 * @brief Returns the new checksum calculated according
 * to the RFC1624 algorithm
 * 
 * @param ip_header the packet's ip header
 * @return uint16_t the new checksum
 */
uint16_t bonus_get_new_checksum(struct iphdr* ip_header)
{
	// decrement the ip header's ttl
	ip_header->ttl--;
	// calculate the new checksum using:
	// HC' = ~(~HC + ~m + m'), where HC is the old checksum, HC' the
	// the new checksum, m the old 16 bit ttl and m' the new one
	// cast the ttl value to uint16_t, since it originally is a 8 bit value
	return (~(~ip_header->check +
			~((uint16_t)ip_header->ttl + 1)
			+ (uint16_t)ip_header->ttl) - 1);
}
