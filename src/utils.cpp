#include "utils.h"

#include <spdlog/spdlog.h>

#include "protocol.h"

uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = static_cast<const uint8_t*>(_data);
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

/* Converts a MAC address from void* to mac_addr */
mac_addr make_mac_addr(void* addr) {
  mac_addr mac;
  uint8_t* ptr = static_cast<uint8_t*>(addr);
  for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
    mac[i] = ptr[i];
  }

  return mac;
}

uint16_t ethertype(uint8_t* buf) {
  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t* buf) {
  sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(buf);
  return iphdr->ip_p;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t* addr) {
  int pos = 0;
  uint8_t cur;
  std::string eth_addr;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      eth_addr += ":";
    eth_addr += fmt::format("{:02X}", cur);
  }
  spdlog::info("{}", eth_addr);
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, sizeof(buf)) == NULL)
    spdlog::error("inet_ntop error on address conversion");
  else
    spdlog::info("{}", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  spdlog::info("{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t* buf) {
  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)buf;
  spdlog::info("ETHERNET header:");
  spdlog::info("\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  spdlog::info("\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  spdlog::info("\ttype: {}", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t* buf) {
  sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(buf);
  spdlog::info("IP header:");
  spdlog::info("\tversion: {}", static_cast<int>(iphdr->ip_v));
  spdlog::info("\theader length: {}", static_cast<int>(iphdr->ip_hl));
  spdlog::info("\ttype of service: {}", iphdr->ip_tos);
  spdlog::info("\tlength: {}", ntohs(iphdr->ip_len));
  spdlog::info("\tid: {}", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    spdlog::info("\tfragment flag: DF");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    spdlog::info("\tfragment flag: MF");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    spdlog::info("\tfragment flag: R");

  spdlog::info("\tfragment offset: {}", ntohs(iphdr->ip_off) & IP_OFFMASK);
  spdlog::info("\tTTL: {}", iphdr->ip_ttl);
  spdlog::info("\tprotocol: {}", iphdr->ip_p);
  spdlog::info("\tchecksum: {}", static_cast<uint32_t>(iphdr->ip_sum));
  spdlog::info("\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));
  spdlog::info("\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t* buf) {
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(buf);
  spdlog::info("ICMP header:");
  spdlog::info("\ttype: {}", icmp_hdr->icmp_type);
  spdlog::info("\tcode: {}", icmp_hdr->icmp_code);
  spdlog::info("\tchecksum: {}", static_cast<uint32_t>(icmp_hdr->icmp_sum));
}

/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t* buf) {
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(buf);
  spdlog::info("ARP header");
  spdlog::info("\thardware type: {}", ntohs(arp_hdr->ar_hrd));
  spdlog::info("\tprotocol type: {}", ntohs(arp_hdr->ar_pro));
  spdlog::info("\thardware address length: {}", arp_hdr->ar_hln);
  spdlog::info("\tprotocol address length: {}", arp_hdr->ar_pln);
  spdlog::info("\topcode: {}", ntohs(arp_hdr->ar_op));
  spdlog::info("\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  spdlog::info("\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));
  spdlog::info("\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  spdlog::info("\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t* buf, uint32_t length) {
  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    spdlog::error("Failed to print ETHERNET header, insufficient length");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) {
    /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      spdlog::error("Failed to print IP header, insufficient length");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) {
      /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        spdlog::error("Failed to print ICMP header, insufficient length");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) {
    /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      spdlog::error("Failed to print ARP header, insufficient length");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    spdlog::error("Unrecognized Ethernet Type: {}", ethtype);
  }
}

sr_ethernet_hdr_t createEthernetHeader(const mac_addr& srcMac, const mac_addr& destMac, uint16_t ethType) {
    sr_ethernet_hdr_t ethHeader{};
    memcpy(ethHeader.ether_shost, srcMac.data(), ETHER_ADDR_LEN);
    memcpy(ethHeader.ether_dhost, destMac.data(), ETHER_ADDR_LEN);
    ethHeader.ether_type = htons(ethType);
    spdlog::info("Create Ethernet Header");
    // print_hdr_eth(reinterpret_cast<uint8_t*>(&ethHeader));
    return ethHeader;
}

sr_arp_hdr_t createArpHeader(uint16_t op, const mac_addr& senderMac, uint32_t senderIp,
                             const mac_addr& targetMac, uint32_t targetIp) {
    sr_arp_hdr_t arpHeader{};
    arpHeader.ar_hrd = htons(arp_hrd_ethernet);
    arpHeader.ar_pro = htons(ethertype_ip);
    arpHeader.ar_hln = ETHER_ADDR_LEN;
    arpHeader.ar_pln = sizeof(uint32_t);
    arpHeader.ar_op = htons(op);
    memcpy(arpHeader.ar_sha, senderMac.data(), ETHER_ADDR_LEN);
    arpHeader.ar_sip = htonl(senderIp);
    memcpy(arpHeader.ar_tha, targetMac.data(), ETHER_ADDR_LEN);
    arpHeader.ar_tip = htonl(targetIp);

    spdlog::info("Create ARP Header");
    print_hdr_arp(reinterpret_cast<uint8_t*>(&arpHeader));
    return arpHeader;
}

sr_ip_hdr_t createIpHeader(uint16_t totalLen, uint8_t protocol, uint32_t srcIp, uint32_t destIp, uint8_t ttl) {
    sr_ip_hdr_t ipHeader{};
    ipHeader.ip_v = 4;
    ipHeader.ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ipHeader.ip_tos = 0;
    ipHeader.ip_len = totalLen;
    ipHeader.ip_id = 0;
    ipHeader.ip_off = IP_DF;
    ipHeader.ip_ttl = ttl;
    ipHeader.ip_p = protocol;
    ipHeader.ip_src = srcIp;
    ipHeader.ip_dst = destIp;
    encodeIPHeader(&ipHeader);
    ipHeader.ip_sum = 0;
    ipHeader.ip_sum = cksum(&ipHeader, sizeof(sr_ip_hdr_t));

    spdlog::info("Create Ip Header");
    print_hdr_ip(reinterpret_cast<uint8_t*>(&ipHeader));
    return ipHeader;
}

sr_icmp_t3_hdr_t createIcmpType3Header(uint8_t type, uint8_t code, const std::vector<uint8_t>& originalPacket) {
    sr_icmp_t3_hdr_t icmpHeader{};
    icmpHeader.icmp_type = type;
    icmpHeader.icmp_code = code;
    icmpHeader.unused = 0;
    icmpHeader.next_mtu = 0;
    // Copy original IP header and 8 bytes of payload for ICMP error
    const size_t copyLength = std::min(sizeof(sr_ip_hdr_t) + 8, originalPacket.size() - ETHERNET_HEADER_SIZE);
    memcpy(icmpHeader.data, originalPacket.data() + ETHERNET_HEADER_SIZE, copyLength);

    icmpHeader.icmp_sum = 0;
    icmpHeader.icmp_sum = cksum(&icmpHeader, sizeof(sr_icmp_t3_hdr_t));

    spdlog::info("Create Icmp Type 3 Header");
    print_hdr_icmp(reinterpret_cast<uint8_t*>(&icmpHeader));
    return icmpHeader;
}

Packet createIpPacket(const Packet& payload, uint8_t payload_protocol, uint32_t srcIp, uint32_t destIp, uint8_t ttl) {
    auto ip_header = createIpHeader(sizeof(sr_ip_hdr_t) + payload.size(), payload_protocol, srcIp, destIp, ttl);
    Packet ip_packet(sizeof(sr_ip_hdr_t) + payload.size());
    memcpy(ip_packet.data(), &ip_header, sizeof(sr_ip_hdr_t));
    memcpy(ip_packet.data() + sizeof(sr_ip_hdr_t), payload.data(), payload.size());
    return ip_packet;
}

Packet createEthernetFrame(const sr_ethernet_hdr_t& ethHeader, const void* payload, size_t payloadSize) {
    Packet frame(ETHERNET_HEADER_SIZE + payloadSize);
    memcpy(frame.data(), &ethHeader, ETHERNET_HEADER_SIZE);
    memcpy(frame.data() + ETHERNET_HEADER_SIZE, payload, payloadSize);
    return frame;
}

void decodeIPHeader(sr_ip_hdr_t* ipHeader) {
  ipHeader->ip_len = ntohs(ipHeader->ip_len);
  ipHeader->ip_id = ntohs(ipHeader->ip_id);
  ipHeader->ip_off = ntohs(ipHeader->ip_off);
  ipHeader->ip_src = ntohl(ipHeader->ip_src);
  ipHeader->ip_dst = ntohl(ipHeader->ip_dst);
  ipHeader->ip_sum = ntohs(ipHeader->ip_sum);
}

void encodeIPHeader(sr_ip_hdr_t* ipHeader) {
  ipHeader->ip_len = htons(ipHeader->ip_len);
  ipHeader->ip_id = htons(ipHeader->ip_id);
  ipHeader->ip_off = htons(ipHeader->ip_off);
  ipHeader->ip_src = htonl(ipHeader->ip_src);
  ipHeader->ip_dst = htonl(ipHeader->ip_dst);
  // ipHeader->ip_sum = htons(ipHeader->ip_sum);
}

Packet makeIcmpEchoReply(Packet& incoming_packet) {
    spdlog::info("Make Icmp Echo Reply");
     // Extract headers from the incoming packet
    sr_ip_hdr_t* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(incoming_packet.data() + ETHERNET_HEADER_SIZE);

    const sr_icmp_hdr_t* icmp_hdr = reinterpret_cast<const sr_icmp_hdr_t*>(
        incoming_packet.data() + ETHERNET_HEADER_SIZE + sizeof(sr_ip_hdr_t));

    // Calculate the ICMP len & packet
    size_t icmp_payload_len = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t);
    Packet icmp_payload(icmp_payload_len);
    memcpy(icmp_payload.data(), reinterpret_cast<const uint8_t*>(icmp_hdr), icmp_payload_len);

    // Update the ICMP type to echo reply and recalculate checksum
    auto* icmp_reply_hdr = reinterpret_cast<sr_icmp_hdr_t*>(icmp_payload.data());
    icmp_reply_hdr->icmp_type = icmp_type_echo_reply;
    icmp_reply_hdr->icmp_code = icmp_code_echo_reply;
    icmp_reply_hdr->icmp_sum = 0; // Reset checksum
    icmp_reply_hdr->icmp_sum = cksum(icmp_payload.data(), icmp_payload_len);

    Packet ip_packet = createIpPacket(icmp_payload, ip_protocol_icmp, ntohl(ip_hdr->ip_dst), ntohl(ip_hdr->ip_src), INIT_TTL);

    return ip_packet;
}

Packet makeIcmpUnreachable(const Packet& incoming_packet, uint8_t code, uint32_t ip) {
    spdlog::info("Make Icmp Unreachable, code: {}", code);

    const sr_ip_hdr_t* ip_hdr = reinterpret_cast<const sr_ip_hdr_t*>(incoming_packet.data() + ETHERNET_HEADER_SIZE);
    auto icmp_header = createIcmpType3Header(icmp_type_unreachable, code, incoming_packet);
    Packet icmp_packet(sizeof(sr_icmp_t3_hdr_t));
    memcpy(icmp_packet.data(), &icmp_header, sizeof(sr_icmp_t3_hdr_t));

    Packet ip_packet = createIpPacket(icmp_packet, ip_protocol_icmp, ip, ntohl(ip_hdr->ip_src), INIT_TTL);
    return ip_packet;
}

Packet makeIcmpTtlExceed(const Packet& incoming_packet, uint32_t src_ip){
    spdlog::info("Make Icmp TTL Exceeded, ip: {}", src_ip);

    const sr_ip_hdr_t* ip_hdr = reinterpret_cast<const sr_ip_hdr_t*>(incoming_packet.data() + ETHERNET_HEADER_SIZE);
    auto icmp_header = createIcmpType3Header(icmp_type_ttl_exceeded, icmp_code_ttl_exceeded, incoming_packet);
    Packet icmp_packet(sizeof(sr_icmp_t3_hdr_t));
    memcpy(icmp_packet.data(), &icmp_header, sizeof(sr_icmp_t3_hdr_t));

    Packet ip_packet = createIpPacket(icmp_packet, ip_protocol_icmp, src_ip, ntohl(ip_hdr->ip_src), INIT_TTL);
    return ip_packet;
}

Packet makeIpForwardPacket(const Packet& incoming_packet) {
    spdlog::info("Make IP Forward Packet");
    const uint8_t* ip_packet_start = incoming_packet.data() + ETHERNET_HEADER_SIZE;
    size_t ip_packet_length = incoming_packet.size() - ETHERNET_HEADER_SIZE;

    // Create a new Packet to hold the extracted IP packet
    Packet ip_packet(ip_packet_length);
    memcpy(ip_packet.data(), ip_packet_start, ip_packet_length);
    sr_ip_hdr_t* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(ip_packet.data());
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    return ip_packet;
}
