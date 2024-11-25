#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

// ICMP message types
const uint8_t icmp_type_echo_reply = 0; 
const uint8_t icmp_type_echo_request = 8; 

// ICMP message codes
const uint8_t icmp_code_ttl_exceeded = 0; 
const uint8_t icmp_code_net_unreachable = 0; 
const uint8_t icmp_code_host_unreachable = 1; 
const uint8_t icmp_code_protocol_unreachable = 2; 
const uint8_t icmp_code_port_unreachable = 3; 


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
    if (ethType == ethertype_arp) {
        // Handle ARP packet
        sr_arp_hdr_t* arpHdr = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        if (ntohs(arpHdr->ar_op) == arp_op_reply) {
            // ARP reply
            mac_addr senderMac = make_mac_addr(arpHdr->ar_sha);
            uint32_t senderIp = ntohl(arpHdr->ar_sip);
            arpCache->addEntry(senderIp, senderMac);
        } else if (ntohs(arpHdr->ar_op) == arp_op_request) {
            // ARP request
            uint32_t targetIp = ntohl(arpHdr->ar_tip);
            auto myMac = routingTable->getRoutingInterface(iface).mac;
            if (targetIp == routingTable->getRoutingInterface(iface).ip) {
                // Construct ARP reply
                sendArpReply(arpHdr, iface, myMac);
            }
        }
    } else if (ethType == ethertype_ip) {
        // Handle IP packet
        sr_ip_hdr_t* ipHdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        uint32_t dstIp = ntohl(ipHdr->ip_dst);
        Packet packet_to_send;
        if (isForMe(dstIp)) {
            if (ipHdr->ip_p == ip_protocol_icmp) {
                sr_icmp_hdr_t* icmpHdr = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                if (icmpHdr->icmp_type == icmp_type_echo_request) {
                    packet_to_send = makeIcmpEchoReply(packet);
                } else {
                    return;
                }
            } else {
                packet_to_send = makeIcmpUnreachable(packet, icmp_code_protocol_unreachable, dstIp);
            }
        } else {
            auto route = routingTable->getRoutingEntry(dstIp);
            if (!route) {
                packet_to_send = makeIcmpUnreachable(packet, icmp_code_net_unreachable, (routingTable->getRoutingInterface(iface)).ip);
            } else {
                packet_to_send = makeIpForwardPacket(packet);
            }
        }
        sendIp(packet_to_send, iface, dstIp, ethertype_ip);
    }
}

bool StaticRouter::isForMe(uint32_t ip) {
   auto interfaces = routingTable->getRoutingInterfaces();
}

Packet makeIcmpEchoReply(const Packet& incoming_packet) {}

Packet makeIcmpUnreachable(const Packet& incoming_packet, uint8_t code, uint32_t ip) {}

Packet makeIpForwardPacket(const Packet& incoming_packet) {}

void StaticRouter::sendEthernetFrame(const mac_addr& srcMac, const mac_addr& destMac, uint16_t ethType, const Packet& packet) {
}

// same level 
void sendArpRequest(uint32_t ip, const std::string& iface) {
    
}

void sendArpReply(const sr_arp_hdr_t* header, const std::string& iface, const mac_addr& my_mac) {
}

void StaticRouter::sendIp(const Packet& packet, const std::string& iface, uint32_t ip, uint16_t ethType) {
    auto nextHopMac = arpCache->getEntry(ip);
    if (!nextHopMac) {
        arpCache->queuePacket(ip, packet, iface);
        sendArpRequest(ip, iface);
    } else {
        sendEthernetFrame((routingTable->getRoutingInterface(iface)).mac, *nextHopMac, ethType, packet);
    }
}