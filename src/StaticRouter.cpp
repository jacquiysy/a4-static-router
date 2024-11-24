#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

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
            auto targetMac = routingTable->getRoutingInterface(iface).mac;
            if (targetIp == routingTable->getRoutingInterface(iface).ip) {
                // Construct ARP reply
                sendArpReply(arpHdr, iface, targetMac);
            }
        }
    } else if (ethType == ethertype_ip) {
        // Handle IP packet
        sr_ip_hdr_t* ipHdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        uint32_t dstIp = ntohl(ipHdr->ip_dst);
        
        if (isForMe(dstIp)) {
            if (ipHdr->ip_p == ip_protocol_icmp) {
                sr_icmp_hdr_t* icmpHdr = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                if (icmpHdr->icmp_type == icmp_type_echo_request) {
                    sendIcmpEchoReply(packet, iface);
                }
            } else {
                sendIcmpUnreachable(packet, iface, icmp_type_dest_unreachable, icmp_code_protocol);
            }
        } else {
            auto route = routingTable->getRoutingEntry(dstIp);
            if (!route) {
                sendIcmpUnreachable(packet, iface, icmp_type_dest_unreachable, icmp_code_net_unreachable);
                return;
            }

            auto nextHopMac = arpCache->getEntry(route->nextHop);
            if (!nextHopMac) {
                arpCache->queuePacket(route->nextHop, packet, iface);
                sendArpRequest(route->nextHop, iface);
            } else {
                forwardPacket(packet, *nextHopMac, route->iface);
            }
        }
    }
}
