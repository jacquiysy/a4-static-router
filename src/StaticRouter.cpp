#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

// ICMP message types
const uint8_t icmp_type_echo_reply = 0; 
const uint8_t icmp_type_unreachable = 3; 
const uint8_t icmp_type_echo_request = 8; 
const uint8_t icmp_type_ttl_exceeded = 11; 

// ICMP message codes
const uint8_t icmp_code_ttl_exceeded = 0; 
const uint8_t icmp_code_echo_reply = 0; 
const uint8_t icmp_code_net_unreachable = 0; 
const uint8_t icmp_code_host_unreachable = 1; 
const uint8_t icmp_code_protocol_unreachable = 2; 
const uint8_t icmp_code_port_unreachable = 3; 

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
    icmp_reply_hdr->icmp_sum = 0; // Reset checksum
    icmp_reply_hdr->icmp_sum = cksum(icmp_payload.data(), icmp_payload_len);
    icmp_reply_hdr->icmp_sum = htons(icmp_reply_hdr->icmp_sum);

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

Packet makeIcmpTtlExceed(const Packet& incoming_packet, uint32_t ip){
    spdlog::info("Make Icmp TTL Exceeded, ip: {}", ip);

    const sr_ip_hdr_t* ip_hdr = reinterpret_cast<const sr_ip_hdr_t*>(incoming_packet.data() + ETHERNET_HEADER_SIZE);
    auto icmp_header = createIcmpType3Header(icmp_type_ttl_exceeded, icmp_code_ttl_exceeded, incoming_packet);
    Packet icmp_packet(sizeof(sr_icmp_t3_hdr_t));
    memcpy(icmp_packet.data(), &icmp_header, sizeof(sr_icmp_t3_hdr_t));

    Packet ip_packet = createIpPacket(icmp_packet, ip_protocol_icmp, ip, ntohl(ip_hdr->ip_src), INIT_TTL);
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
    decodeIPHeader(ip_hdr);
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    encodeIPHeader(ip_hdr);
    return ip_packet;
}

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
      , packetSender(packetSender)
      , arpCache(std::move(arpCache))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    // TODO: Your code below
    uint16_t ethType = ethertype(packet.data());
    // verify checksum
    
    if (ethType == ethertype_arp) {
        spdlog::info("Packet is ARP type");
        // Handle ARP packet
        sr_arp_hdr_t* arpHdr = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        mac_addr senderMac = make_mac_addr(arpHdr->ar_sha);
        uint32_t senderIp = ntohl(arpHdr->ar_sip);
        if (ntohs(arpHdr->ar_op) == arp_op_reply) {
            // ARP reply
            arpCache->addEntry(senderIp, senderMac);
        } else if (ntohs(arpHdr->ar_op) == arp_op_request) {
            // ARP request
            uint32_t targetIp = ntohl(arpHdr->ar_tip);
            auto myMac = routingTable->getRoutingInterface(iface).mac;
            if (targetIp == routingTable->getRoutingInterface(iface).ip) {
                // Construct ARP reply
                sendArpReply(senderMac, senderIp, iface, myMac, targetIp);
            }
        }
    } else if (ethType == ethertype_ip) {
        spdlog::info("Packet is IP type");
        // check ip checksum
        sr_ip_hdr_t ip_header;
        sr_ip_hdr_t* ipHdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        memcpy(&ip_header, ipHdr, sizeof(sr_ip_hdr_t));
        decodeIPHeader(&ip_header);
        uint16_t ip_checksum = ip_header.ip_sum;
        ip_header.ip_sum = 0;
        if (cksum(&ip_header, sizeof(sr_ip_hdr_t)) != ip_checksum) {
            spdlog::info("IP checksum failure");
            return;
        }
        // Handle IP packet
        Packet packet_to_send;
        uint32_t dstIp = ntohl(ipHdr->ip_dst);
        if (ipHdr->ip_ttl == 0) {
            spdlog::info("IP packet has TTL 0");
            return;
        }
        if (isForMe(dstIp)) {
            spdlog::info("DstIP is for me");
            if (ipHdr->ip_p == ip_protocol_icmp) {
                spdlog::info("IP protocol is ICMP");
                sr_icmp_hdr_t* icmpHdr = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                uint16_t given_checksum = icmpHdr->icmp_sum;
                icmpHdr->icmp_sum = 0;
                uint16_t actual_checksum = cksum(icmpHdr, sizeof(sr_icmp_hdr_t));
                if (actual_checksum != ntohs(given_checksum)) {
                    spdlog::info("ICMP checksum failure");
                    return;
                }
                icmpHdr->icmp_sum = given_checksum;
                if (icmpHdr->icmp_type == icmp_type_echo_request) {
                    packet_to_send = makeIcmpEchoReply(packet);
                } else {
                    spdlog::info("ICMP type is not echo");
                    return;
                }
            } else if(ipHdr->ip_p == ip_protocol_tcp || ipHdr->ip_p == ip_protocol_udp) {
                spdlog::info("IP protocol is TCP/UDP");
                // no such service
                packet_to_send = makeIcmpUnreachable(packet, icmp_code_protocol_unreachable, dstIp);
            } else {
                // ignore
                spdlog::info("IP protocol is not ICMP/TCP/UDP");
                return;
            }
        } else {
            spdlog::info("DstIP is not for me");
            if(ipHdr->ip_ttl == 1) {
                spdlog::info("IP TTL is 1, send ICMP Exceed");
                packet_to_send = makeIcmpTtlExceed(packet, dstIp);
            } else {
                packet_to_send = makeIpForwardPacket(packet);
            }
        }
        std::string outgoing_iface = iface;
        auto route = routingTable->getRoutingEntry(dstIp);
        if (!route) {
            spdlog::info("Did not find route from routing table");
            packet_to_send = makeIcmpUnreachable(packet, icmp_code_net_unreachable, (routingTable->getRoutingInterface(iface)).ip);
        } else {
            iface = route->iface;
        }
        sendIp(packet_to_send, outgoing_iface, dstIp, ethertype_ip);
    }
}

bool StaticRouter::isForMe(uint32_t ip) {
    auto interfaces = routingTable->getRoutingInterfaces();
    for (const auto& [iface, interface] : interfaces) {
        if (interface.ip == ip) {
            return true;
        }
    }
    return false;
}

// same level 
void StaticRouter::sendArpRequest(uint32_t ip, const std::string& iface) {
    spdlog::info("Send ARP Request");
    const mac_addr broadcast_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    auto outgoing_interface = routingTable->getRoutingInterface(iface);
    auto arp = createArpHeader(arp_op_request, outgoing_interface.mac, outgoing_interface.ip, broadcast_addr, ip);
    Packet arp_packet(sizeof(sr_arp_hdr_t));
    memcpy(arp_packet.data(), &arp, sizeof(sr_arp_hdr_t));
    sendEthernetFrame(iface, broadcast_addr, ethertype_arp, arp_packet);
}

void StaticRouter::sendArpReply(const mac_addr sender_mac, uint32_t sender_ip, const std::string& iface, const mac_addr& my_mac, uint32_t my_ip) {
    spdlog::info("Send ARP Reply");
    auto arp_header = createArpHeader(arp_op_reply, my_mac, my_ip, sender_mac, sender_ip);
    Packet arp_packet(sizeof(sr_arp_hdr_t));
    memcpy(arp_packet.data(), &arp_header, sizeof(sr_arp_hdr_t));
    sendEthernetFrame(iface, sender_mac, ethertype_arp, arp_packet);
}

void StaticRouter::sendIp(const Packet& packet, const std::string& iface, uint32_t ip, uint16_t ethType) {
    spdlog::info("Send IP");
    auto nextHopMac = arpCache->getEntry(ip);
    if (!nextHopMac) {
        arpCache->queuePacket(ip, packet, iface);
        sendArpRequest(ip, iface);
    } else {
        sendEthernetFrame(iface, *nextHopMac, ethType, packet);
    }
}

void StaticRouter::sendEthernetFrame(const std::string& iface, const mac_addr& destMac, uint16_t ethType, const Packet& packet) {
    spdlog::info("Create and Send Ethernet Frame");
    auto outgoing_interface = routingTable->getRoutingInterface(iface);
    mac_addr srcMac = outgoing_interface.mac;
    auto header = createEthernetHeader(srcMac, destMac, ethType);
    auto frame = createEthernetFrame(header, packet.data(), packet.size());
    packetSender->sendPacket(frame, iface);
}
