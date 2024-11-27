#include "ArpCache.h"

#include <cstring>
#include <spdlog/spdlog.h>
#include <thread>

#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(std::chrono::milliseconds timeout, std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable)
    : timeout(timeout), packetSender(std::move(packetSender)), routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);

}

ArpCache::~ArpCache() {
    shutdown = true;
    if(thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while(!shutdown) {
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    // TODO: Your code here
    spdlog::info("-----------------------TICK----------------------");
    for(auto it = requests.begin(); it != requests.end();) {
        ArpRequest& request = it->second;

        if(std::chrono::steady_clock::now() - request.lastSent >= std::chrono::seconds(1)) {
            if(request.timesSent >= 7) {
                spdlog::warn("ARP request for IP {} failed after 7 retries. Sending ICMP Host Unreachable.", it->first);

                for(auto& awaitingPacket : request.awaitingPackets) {
                    spdlog::info("Send Icmp Host Unreachable for awaiting packet");
                    sendIcmpHostUnreachable(awaitingPacket.packet, awaitingPacket.iface);
                }

                it = requests.erase(it);
                continue;
            }
            spdlog::info("In Arp Cache, Send Arp Request");
            sendArpRequest(it->first);
            request.lastSent = std::chrono::steady_clock::now();
            request.timesSent++;
        }

        ++it;
    }

    // TODO: Your code should end here

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // TODO: Your code below
    ArpEntry entry = { ip, mac, std::chrono::steady_clock::now() };

    auto it = requests.find(ip);
    if(it != requests.end()) {
        ArpRequest& request = it->second;
        // forward packet
        for(auto& awaitingPacket : request.awaitingPackets) {
            Packet packet_to_send = awaitingPacket.packet;
            uint32_t ip_to_send = reinterpret_cast<sr_ip_hdr_t*>(packet_to_send.data())->ip_dst; // network order
            auto route = routingTable->getRoutingEntry(ip_to_send);
            sendEthernetFrame(route->iface, mac, ethertype_ip, awaitingPacket.packet);
        }

        requests.erase(it);
        entries[ip] = entry;
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    // TODO: Your code below
    auto it = entries.find(ip);
    if(it != entries.end()) {
        return it->second.mac;
    }

    return std::nullopt;  // Placeholder
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    // TODO: Your code below
    if(requests.find(ip) == requests.end()) {
        requests[ip] = ArpRequest { ip, std::chrono::steady_clock::now(), 0, {} };
    }

    requests[ip].awaitingPackets.push_back({ packet, iface });
}

void ArpCache::sendArpRequest(uint32_t ip) {
    spdlog::info("Sending ARP request for IP:");
    print_addr_ip_int(ip);

    auto route = routingTable->getRoutingEntry(htonl(ip));
    if(!route) {
        spdlog::error("No route found for ARP request for IP");
        return;
    }

    auto ifaceInfo = routingTable->getRoutingInterface(route->iface);

    auto ethHeader = createEthernetHeader(
        ifaceInfo.mac,
        eth_broadcast_addr,
        ethertype_arp);

    auto arpHeader = createArpHeader(
        arp_op_request,
        ifaceInfo.mac,
        ntohl(ifaceInfo.ip),
        arp_unknown_addr,
        ip);

    auto request = createEthernetFrame(ethHeader, &arpHeader, sizeof(arpHeader));

    packetSender->sendPacket(request, route->iface);
}

void ArpCache::sendIcmpHostUnreachable(Packet& packet, const std::string& iface) {
    auto ifaceInfo = routingTable->getRoutingInterface(iface);
    uint32_t src_ip = ntohl(ifaceInfo.ip);
    Packet icmp_packet = makeIcmpUnreachable(packet, icmp_code_host_unreachable, src_ip);
    mac_addr dest_mac = make_mac_addr(reinterpret_cast<uint8_t*>(packet.data()));
    sendEthernetFrame(iface, dest_mac, ethertype_ip, icmp_packet);
}

void ArpCache::sendEthernetFrame(const std::string& iface, const mac_addr& destMac, uint16_t ethType, const Packet& packet) {
    spdlog::info("Create and Send Ethernet Frame");
    auto outgoing_interface = routingTable->getRoutingInterface(iface);
    mac_addr srcMac = outgoing_interface.mac;
    auto header = createEthernetHeader(srcMac, destMac, ethType);
    auto frame = createEthernetFrame(header, packet.data(), packet.size());
    packetSender->sendPacket(frame, iface);
}