#pragma once
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket
{
    EthHdr eth_;
    ArpHdr arp_;

    static EthArpPacket spoofDefaultPacket();
    static EthArpPacket broadcastPacket(Mac attackerMac, Ip attackerIp, Ip destIp);
    // frommac tomac toip fromip??
    // src dest
    static EthArpPacket infectPacket(Mac attackerMac, Mac senderMac, Ip senderIp, Ip targetIp);

    void send(pcap_t *handle);
};
#pragma pack(pop)

void getDeviceAddress(const char *dev, Ip *ip, Mac *mac);
void usage();
Mac receiveArpReply(pcap_t *handle, Ip ip_from, int *receivedFlag);
void spoof(pcap_t *handle, Ip destIp, Mac atkMac, Mac destMac);
void *producePacket(void *handle);
void registerIp(Ip ip, pthread_cond_t *cond, pthread_mutex_t *mutex);