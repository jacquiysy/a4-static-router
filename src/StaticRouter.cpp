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
    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());

    spdlog::info("-----------------------Handle Packet----------------------");
    
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
            if (targetIp == ntohl(routingTable->getRoutingInterface(iface).ip)) {
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
        // decodeIPHeader(&ip_header);
        uint16_t ip_checksum = ip_header.ip_sum;
        ip_header.ip_sum = 0;
        if (cksum(&ip_header, sizeof(sr_ip_hdr_t)) != ip_checksum) {
            spdlog::info("IP checksum failure");
            return;
        }
        // Handle IP packet
        Packet packet_to_send;
        uint32_t ip_to_send;
        std::optional<mac_addr> mac_to_send = std::nullopt;
        uint32_t dstIp = ntohl(ipHdr->ip_dst);
        if (ipHdr->ip_ttl == 0) {
            spdlog::info("IP packet has TTL 0");
            return;
        }
        if (isForMe(dstIp)) {
            ip_to_send = ntohl(ipHdr->ip_src);
            mac_to_send = make_mac_addr(reinterpret_cast<sr_ethernet_hdr_t*>(packet.data())->ether_shost);

            spdlog::info("DstIP is for me");
            if (ipHdr->ip_p == ip_protocol_icmp) {
                spdlog::info("IP protocol is ICMP");
                sr_icmp_hdr_t* icmpHdr = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                uint16_t given_checksum = icmpHdr->icmp_sum;
                icmpHdr->icmp_sum = 0;
                uint16_t actual_checksum = cksum(icmpHdr, packet.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
                if (actual_checksum != given_checksum) {
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
                packet_to_send = makeIcmpUnreachable(packet, icmp_code_port_unreachable, dstIp);
            } else {
                // ignore
                spdlog::info("IP protocol is not ICMP/TCP/UDP");
                return;
            }
        } else {
            spdlog::info("DstIP is not for me");
            if(ipHdr->ip_ttl == 1) {
                ip_to_send = ntohl(ipHdr->ip_src);
                mac_to_send = make_mac_addr(reinterpret_cast<sr_ethernet_hdr_t*>(packet.data())->ether_shost);
                spdlog::info("IP TTL is 1, send ICMP Exceed");
                RoutingInterface routing_iface = routingTable->getRoutingInterface(iface);
                packet_to_send = makeIcmpTtlExceed(packet, ntohl(routing_iface.ip));
            } else {
                ip_to_send = dstIp;
                packet_to_send = makeIpForwardPacket(packet);
            }
        }
        std::string outgoing_iface = iface;
        auto route = routingTable->getRoutingEntry(htonl(ip_to_send));
        if (!route) {
            spdlog::info("Did not find route from routing table");
            mac_to_send = make_mac_addr(reinterpret_cast<sr_ethernet_hdr_t*>(packet.data())->ether_shost);
            packet_to_send = makeIcmpUnreachable(packet, icmp_code_net_unreachable, ntohl((routingTable->getRoutingInterface(iface)).ip));
        } else {
            outgoing_iface = route->iface;
        }
        sendIp(packet_to_send, outgoing_iface, iface, ip_to_send, ethertype_ip, mac_to_send, eth_hdr);
    }
}

bool StaticRouter::isForMe(uint32_t ip) {
    auto interfaces = routingTable->getRoutingInterfaces();
    for (const auto& [iface, interface] : interfaces) {
        if (ntohl(interface.ip) == ip) {
            return true;
        }
    }
    return false;
}

// same level 

void StaticRouter::sendArpReply(const mac_addr sender_mac, uint32_t sender_ip, const std::string& iface, const mac_addr& my_mac, uint32_t my_ip) {
    spdlog::info("Send ARP Reply");
    auto arp_header = createArpHeader(arp_op_reply, my_mac, my_ip, sender_mac, sender_ip);
    Packet arp_packet(sizeof(sr_arp_hdr_t));
    memcpy(arp_packet.data(), &arp_header, sizeof(sr_arp_hdr_t));
    sendEthernetFrame(iface, sender_mac, ethertype_arp, arp_packet);
}

void StaticRouter::sendIp(const Packet& packet, const std::string& out_iface, const std::string& in_iface, uint32_t ip, uint16_t ethType, std::optional<mac_addr> nextMac, sr_ethernet_hdr_t* eth_hdr) {
    spdlog::info("Send IP");
    if (nextMac) {
        sendEthernetFrame(out_iface, *nextMac, ethType, packet);
        return;
    }
    auto nextHopMac = arpCache->getEntry(ip);
    if (!nextHopMac) {
        auto frame = createEthernetFrame(*eth_hdr, packet.data(), packet.size());
        arpCache->queuePacket(ip, frame, in_iface);
    } else {
        sendEthernetFrame(out_iface, *nextHopMac, ethType, packet);
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
