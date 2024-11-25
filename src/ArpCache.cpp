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
    for(auto it = requests.begin(); it != requests.end();) {
        ArpRequest& request = it->second;

        if(std::chrono::steady_clock::now() - request.lastSent >= std::chrono::seconds(1)) {
            if(request.timesSent >= 7) {
                spdlog::warn("ARP request for IP {} failed after 7 retries. Sending ICMP Host Unreachable.", it->first);

                for(auto& awaitingPacket : request.awaitingPackets) {
                    sendIcmpHostUnreachable(awaitingPacket.packet, awaitingPacket.iface);
                }

                it = requests.erase(it);
                continue;
            }

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
    entries[ip] = entry;

    auto it = requests.find(ip);
    if(it != requests.end()) {
        ArpRequest& request = it->second;

        for(auto& awaitingPacket : request.awaitingPackets) {
            auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(awaitingPacket.packet.data());
            memcpy(ethHeader->ether_dhost, mac.data(), ETHER_ADDR_LEN);

            auto ifaceInfo = routingTable->getRoutingInterface(awaitingPacket.iface);
            memcpy(ethHeader->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);

            packetSender->sendPacket(awaitingPacket.packet, awaitingPacket.iface);
        }

        requests.erase(it);
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
    spdlog::info("Sending ARP request for IP: {}", ip);

    auto route = routingTable->getRoutingEntry(ip);
    if(!route) {
        spdlog::error("No route found for ARP request for IP: {}", ip);
        return;
    }

    auto ifaceInfo = routingTable->getRoutingInterface(route->iface);

    auto ethHeader = createEthernetHeader(
        ifaceInfo.mac,
        mac_addr { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        ethertype_arp);

    auto arpHeader = createArpHeader(
        arp_op_request,
        ifaceInfo.mac,
        ifaceInfo.ip,
        mac_addr {},
        ip);

    auto request = createEthernetFrame(ethHeader, &arpHeader, sizeof(arpHeader));

    packetSender->sendPacket(request, route->iface);
}

void ArpCache::sendIcmpHostUnreachable(Packet& packet, const std::string& iface) {
    auto ifaceInfo = routingTable->getRoutingInterface(iface);
    auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + ETHERNET_HEADER_SIZE);

    auto icmpHeader = createIcmpType3Header(3, 1, packet);  // Type 3, Code 1: Host Unreachable
    auto ipHeaderResponse = createIpHeader(
        sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
        ip_protocol_icmp,
        ifaceInfo.ip,
        ntohl(ipHeader->ip_src),
        INIT_TTL);

    Packet icmpPacket = createEthernetFrame(
        createEthernetHeader(
            ifaceInfo.mac,
            make_mac_addr(reinterpret_cast<sr_ethernet_hdr_t*>(packet.data())->ether_shost),
            ethertype_ip),
        &icmpHeader, sizeof(icmpHeader));

    icmpPacket.insert(icmpPacket.begin() + ETHERNET_HEADER_SIZE,
        reinterpret_cast<uint8_t*>(&ipHeaderResponse),
        reinterpret_cast<uint8_t*>(&ipHeaderResponse) + sizeof(sr_ip_hdr_t));

    packetSender->sendPacket(icmpPacket, iface);
}