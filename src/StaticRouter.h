#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <vector>
#include <memory>
#include <mutex>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"


class StaticRouter {
public:
    StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                 std::shared_ptr<IPacketSender> packetSender);

    /**
     * @brief Handles an incoming packet, telling the switch to send out the necessary packets.
     * @param packet The incoming packet.
     * @param iface The interface on which the packet was received.
     */
    void handlePacket(std::vector<uint8_t> packet, std::string iface);

private:
    std::mutex mutex;

    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<IArpCache> arpCache;

    bool isForMe(uint32_t ip);
    void sendIp(const Packet& packet, const std::string& iface, uint32_t ip, uint16_t ethType, std::optional<mac_addr> nextMac);
    void sendEthernetFrame(const std::string& iface, const mac_addr& destMac, uint16_t ethType, const Packet& packet) ;
    void sendArpRequest(uint32_t ip, const std::string& iface);
    void sendArpReply(const mac_addr sender_mac, uint32_t sender_ip, const std::string& iface, const mac_addr& my_mac, uint32_t my_ip);
};


#endif //STATICROUTER_H
