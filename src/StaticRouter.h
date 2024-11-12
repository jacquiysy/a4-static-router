#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <vector>

#include "ArpCache.h"


class StaticRouter {
public:
    StaticRouter(std::unique_ptr<ArpCache> arpCache, std::shared_ptr<RoutingTable> routingTable, std::shared_ptr<IPacketSender> packetSender);

    /**
     * @brief Handles an incoming packet, telling the switch to send out the necessary packets.
     * @param packet The incoming packet.
     * @param iface The interface on which the packet was received.
     */
    void handlePacket(std::vector<uint8_t> packet, std::string iface);

private:
    std::mutex mutex;

    std::shared_ptr<RoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<ArpCache> arpCache;
};



#endif //STATICROUTER_H
