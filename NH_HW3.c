#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <pcap.h>

#define PCAP_BUF_SIZE	10240
#define PCAP_SRC_FILE	2

struct STD
{
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[1024][INET_ADDRSTRLEN];
    int countPacket[1024];
    int cnt;
};

int sumsum = 0;
int icmpCount = 0;
int tcpCount = 0;
int udpCount = 0;
int dnsCount = 0;
int synCount[PCAP_BUF_SIZE];
int synIdx = 0;
char synIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];
int httpCount[PCAP_BUF_SIZE];
int httpIdx = 0;
char httpIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];
struct STD std[1024];
int cntSTD = 0;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv)
{

    pcap_t *fp = NULL;
    char errbuf[PCAP_BUF_SIZE];
    char source[PCAP_BUF_SIZE];

    //線上獲取封包
    if(argc == 1)
    {
        char *p_net_interface_name = NULL; //接口名字

        //獲取接口名字
        p_net_interface_name = pcap_lookupdev(errbuf);
	    if(p_net_interface_name == NULL)
	    {
            printf("%s\n", errbuf);
            return -1;
	    }

        //打開網路接口
        fp = pcap_open_live(p_net_interface_name, 65535, 1, 0, errbuf);

        if (pcap_loop(fp, 0, packetHandler, NULL) < 0)
        {
            printf("\npcap_loop() failed: %s\n", pcap_geterr(fp));
            return 0;
        }

        pcap_close(fp);
	    return 0;
    }

    if(argc == 3 && strlen(argv[1]) == 2 && !strcmp(argv[1], "-r"))
    {
        fp = pcap_open_offline(argv[2], errbuf);
        if (fp == NULL)
        {
	        printf("\npcap_open_offline() failed: %s\n", errbuf);
	        return 0;
        }
        
        if (pcap_loop(fp, 0, packetHandler, NULL) < 0)
        {
            printf("\npcap_loop() failed: %s\n", pcap_geterr(fp));
            return 0;
        }

        printf("Protocol Summary：%d TCP packets, %d UDP packets\n\n", tcpCount, udpCount);
        printf("Source to Destination Packet Count：\n");
        int i;
        int sum = 0;
        for (i = 0; i < cntSTD; i++)
        {
            int j;
            for (j = 0; j < std[i].cnt; j++)
            {
                printf("From %s to %s：%d\n", std[i].sourceIP, std[i].destIP[j], std[i].countPacket[j]);
                sum += std[i].countPacket[j];
            }
        }
        //printf("sumsum：%d\n", sumsum);
        //printf("SUM：%d\n", sum);
        return 0;
    }

}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    //printf("test\n");
    //計算目前是第幾個packet
    static int packetNum = 0;
    packetNum++;
    printf("Packet Num:%d\n", packetNum);

    //印出時間戳記
    time_t captureTime = pkthdr->ts.tv_sec;
    printf("Capture Time：%s", ctime(&captureTime));

    //乙太網數據包格式
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    int i;

    ethernetHeader = (struct ether_header*)packet;

    //獲取來源與目的mac地址
    unsigned char *macString; //為何使用unsigned char：https://www.cnblogs.com/qytan36/archive/2010/09/27/1836569.html
    macString = (unsigned char *)ethernetHeader->ether_shost;//获取源mac地址
	printf("Mac Address of Source is %02x:%02x:%02x:%02x:%02x:%02x\n",*(macString+0),*(macString+1),*(macString+2),*(macString+3),*(macString+4),*(macString+5));
	macString = (unsigned char *)ethernetHeader->ether_dhost;//获取目的mac
	printf("Mac Address of Destination is %02x:%02x:%02x:%02x:%02x:%02x\n",*(macString+0),*(macString+1),*(macString+2),*(macString+3),*(macString+4),*(macString+5));

    //如果封包是IP封包
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
    {
        sumsum++;
        printf("Is it IP packet？：Yes\n");

        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        printf("Source IP：%s\n", sourceIP);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
        printf("Destination IP：%s\n", destIP);

        int flag = 1;
        //判斷當前的souceIP是否已存過
        for (i = 0; i < cntSTD; i++)
        {
            if(!strcmp(std[i].sourceIP, sourceIP))
            {
                flag = 0;
                break;
            }
        }
        //若沒有，將其以及其destIP存入
        if(flag)
        {
            strcpy(std[cntSTD].sourceIP, sourceIP);
            strcpy(std[cntSTD].destIP[0], destIP);
            std[cntSTD].countPacket[0]++;
            std[cntSTD].cnt++;
            cntSTD++;
        }
        //若有，判斷當前destIP是否為新的
        else
        {
            int j;
            int flag2 = 1;
            for (j = 0; j < std[i].cnt; j++)
            {
                if(!strcmp(std[i].destIP[j], destIP))
                {
                    flag2 = 0;
                    break;
                }
            }
            //當前destIP是新的，將其存入
            if(flag2)
            {
                strcpy(std[i].destIP[std[i].cnt], destIP);
                std[i].countPacket[std[i].cnt]++;
                std[i].cnt++;
            }
            //當前destIP已出現過，記數+1
            else
            {
                std[i].countPacket[j]++;
            }
        }

            //如果是TCP
            if (ipHeader->ip_p == IPPROTO_TCP)
            {
                printf("TCP or UDP：TCP\n");
                tcpCount = tcpCount + 1;
                tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                sourcePort = ntohs(tcpHeader->source);
                printf("Port of Source：%d\n", sourcePort);
                destPort = ntohs(tcpHeader->dest);
                printf("Port of Destination：%d\n", destPort);

                //data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
                //dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            }
            //如果是UDP
            else if (ipHeader->ip_p == IPPROTO_UDP)
            {
                printf("TCP or UDP：UDP\n");
                udpCount = udpCount + 1;
                udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                sourcePort = ntohs(udpHeader->source);
                printf("Port of Source：%d\n", sourcePort);
                destPort = ntohs(udpHeader->dest);
                printf("Port of Destination：%d\n", destPort);
            }
    }
    else
        printf("Is it IP packet？：No\n");
    printf("\n");
    return ;
}