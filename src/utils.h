#ifndef UTILS_RAW_H
#define UTILS_RAW_H

#include <stdint.h>
#include <netinet/in.h>

#include "RouterTypes.h"

// ICMP message types
inline const uint8_t icmp_type_echo_reply = 0; 
inline const uint8_t icmp_type_unreachable = 3; 
inline const uint8_t icmp_type_echo_request = 8; 
inline const uint8_t icmp_type_ttl_exceeded = 11; 

// ICMP message codes
inline const uint8_t icmp_code_ttl_exceeded = 0; 
inline const uint8_t icmp_code_echo_reply = 0; 
inline const uint8_t icmp_code_net_unreachable = 0; 
inline const uint8_t icmp_code_host_unreachable = 1; 
inline const uint8_t icmp_code_protocol_unreachable = 2; 
inline const uint8_t icmp_code_port_unreachable = 3; 
inline const mac_addr arp_unknown_addr = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
inline const mac_addr eth_broadcast_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


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

Packet createIpPacket(const Packet& payload, uint8_t payload_protocol, uint32_t srcIp, uint32_t destIp, uint8_t ttl);

void decodeIPHeader(sr_ip_hdr_t* ipHeader);

void encodeIPHeader(sr_ip_hdr_t* ipHeader);

Packet makeIcmpEchoReply(Packet& incoming_packet);
Packet makeIcmpUnreachable(const Packet& incoming_packet, uint8_t code, uint32_t ip);
Packet makeIcmpTtlExceed(const Packet& incoming_packet, uint32_t src_ip);
Packet makeIpForwardPacket(const Packet& incoming_packet);

#endif //UTILS_RAW_H
