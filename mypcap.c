#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h" // myheader.h 에서 구조체 참조

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet; // 이더넷 헤더 구조체
    struct ipheader *ip; // IP 헤더 구조체
    struct tcpheader *tcp; // TCP 헤더 구조체
    int ip_header_length; // IP 헤더 길이

    // 페킷이 IP 패킷인지 확인
    if (ntohs(eth->ether_type) == 0x0800)
    {
        ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        ip_header_length = ip->iph_ihl * 4; // IP 헤더 길이 계산

        // 페킷이 TCP 패킷인지 확인
        if (ip->iph_protocol == IPPROTO_TCP)
        {
            // TCP 헤더 구조체
            tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_length);

            
            // 패킷 정보 출력
            printf("Ethernet Header\n\n");
            printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("IP Header\n\n");
            printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

            printf("TCP Header\n\n");
            printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
            
            // 패킷 데이터 출력
            printf("Packet Data: ");
            int data_start = ip_header_length + sizeof(struct ethheader) + (TH_OFF(tcp) * 4); // 데이터 세그먼트의 시작 위치 계산

            int data_length = pkthdr->caplen - data_start; // 데이터 세그먼트의 길이 계산

            // 데이터 세그먼트 출력
            int max_length = data_start + 30;
            for (int i = data_start; i < pkthdr->caplen && i < max_length; ++i)
                printf("%02x ", packet[i]);
            printf("\n");
        }
    }
}

int main()
{
    pcap_t *handle; // 핸들러
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // wsl 리눅스 내의 lan카드인 eth0 사용
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    // 패킷 캡쳐 컴파일을 통해 BPF 코드로 변환
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0)
    {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // 패킷 캡쳐
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle); // 핸들러 종료
    return 0;
}
