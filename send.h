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
    static EthArpPacket infectPacket(Mac attackerMac, Mac senderMac, Ip senderIp, Ip targetIp);

    void send(pcap_t *handle);
};
#pragma pack(pop)

void getDeviceAddress(const char *dev, Ip *ip, Mac *mac);
void usage();
Mac receiveArpReply(pcap_t *handle, Ip ip_from, int *receivedFlag);

struct SpoofParams
{
    pcap_t *handle;
    Mac amac;
    Mac smac;
    Mac dmac;
};
void *spoof(void *param);

struct ProduceParam
{
    pcap_t *handle;
    Mac attackerMac;
};
void *producePacket(void *handle);
void registerMac(Mac mac, pthread_cond_t *cond, pthread_mutex_t *mutex);
