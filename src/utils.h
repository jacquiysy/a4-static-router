#ifndef UTILS_RAW_H
#define UTILS_RAW_H

#include <stdint.h>
#include <netinet/in.h>

#include "RouterTypes.h"

uint16_t ethertype(uint8_t* buf);
uint16_t cksum(const void *_data, int len);
mac_addr make_mac_addr(void* addr);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

sr_ethernet_hdr_t createEthernetHeader(const mac_addr& srcMac, const mac_addr& destMac, uint16_t ethType);

sr_arp_hdr_t createArpHeader(uint16_t op, const mac_addr& senderMac, uint32_t senderIp,
                             const mac_addr& targetMac, uint32_t targetIp);

sr_ip_hdr_t createIpHeader(uint16_t totalLen, uint8_t protocol, uint32_t srcIp, uint32_t destIp, uint8_t ttl);

sr_icmp_t3_hdr_t createIcmpType3Header(uint8_t type, uint8_t code, const std::vector<uint8_t>& originalPacket);

Packet createEthernetFrame(const sr_ethernet_hdr_t& ethHeader, const void* payload, size_t payloadSize);

#endif //UTILS_RAW_H
