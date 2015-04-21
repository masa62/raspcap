#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

char *my_ether_ntoa_r(u_char *hwaddr,char *buf,socklen_t size)
{
    snprintf(buf,size,"%02x:%02x:%02x*%02x:%02x:%02x",hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5]);
    return(buf);
}

char *arp_ip2str(u_int8_t *ip,char *buf,socklen_t size)
{
    snprintf(buf,size, "%u.%u.%u.%u",ip[0],ip[1],ip[2],ip[3]);
    return(buf);
}

char *ip_ip2str(u_int32_t ip,char *buf,socklen_t size)
{
    struct in_addr  *addr;

    addr=(struct in_addr *)&ip;
    inet_ntop(AF_INET,addr,buf,size);

    return(buf);
}

int PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
    char buf[80];

    fprintf(fp,"ether_header---------------------------------\n");
    fprintf(fp,"ether_dhost=%s\n",my_ether_ntoa_r(eh->ether_dhost,buf,sizeof(buf)));
    fprintf(fp,"ether_shost=%s\n",my_ether_ntoa_r(eh->ether_shost,buf,sizeof(buf)));
    fprintf(fp,"ether_type=%s\n",ntohs(eh->ether_type));
    switch(ntohs(eh->ether_type)){
        case    ETH_P_IP:
            fprintf(fp,"(IP)\n");
            break;
        case    ETH_P_IPV6:
            fprintf(fp,"(IPv6)\n");
            break;
        case    ETH_P_ARP:
            fprintf(fp,"(ARP)\n");
            break;
        default:
            fprintf(fp,"(unknown)\n");
            break;
    }

    return(0);
}

int PrintArp(struct ether_arp *arp,FILE *fp)
{
    static char *hdr[]={
        "From KA9Q: NET/ROM pseudo.",
        "Ethernet 10/100Mbps.",
        "Experimental Ethernet.",
        "AX.25 Level 2.",
        "PROnet token ring.",
        "Chaosnet.",
        "IEEE 802.2 Ethernet/TR/TB.",
        "ARCnet.",
        "APPLEtalk.",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "Frame Relay DLCI.",
        "undefined",
        "undefined",
        "undefined",
        "ATM.",
        "undefined",
        "undefined",
        "undefined",
        "Metricom STRIP (new IANA id)."
    };

    static char *op[]={
        "undefined",
        "ARP request.",
        "ARP reply.",
        "RARP request.",
        "RARP reply.",
        "undefined",
        "undefined",
        "undefined",
        "InARP request.",
        "InARP reply.",
        "(ATM)ARP NAK."
    };

    char buf[80];

    fprintf(fp,"arp--------------------------------\n");
    fprintf(fp,"arp_hdr=%u",ntohs(arp->arp_hdr));
    if(ntohs(arp->arp_hdr)<=23){
        fprintf(fp,"(%s),",hdr[ntohs(arp->arp_hdr)]);
    }
    else{
        fprintf(fp,"(undefined),");
    }
    fprintf(fp,"arp_pro=%u",ntohs(arp->arp_pro));
    switch(ntohs(arp->arp_pro)){
        case    ETHERTYPE_IP:
            fprintf(fp,"(IP)\n");
            break
        case    ETHERTYPE_ARP:
            fprintf(fp,"(Address resolution)\n");
            break;
        case    ETHERTYPE_REVARP:
            fprintf(fp,"(Reverse ARP)\n");
            break;
        case    ETHERTYPE_IPV6:
            fprintf(fp,"(IPv6)\n");
            break;
        default:
            fprintf(fp,"(unknown)\n");
            break;
    }
    fprintf(fp,"arp_hln=%u,",arp->arp_hln);
    fprintf(fp,"arp_pln=%u,",arp->arp_pln);
    fprintf(fp,"arp_op=%u",ntohs(arp->arp_op));
    if(ntohs(arp->arp_op)<=10){
        fprintf(fp,"(%s)\n",op[ntohs(arp->arp_op)]);
    }
    else{
        fprintf(fp,"(undefined)\n");
    }
    fprintf(fp,"arp_sha=%s\n",my_ether_ntoa_r(arp->arp_sha,buf,sizeof(buf)));
    fprintf(fp,"arp_spa=%s\n",arp_ip2str(arp->arp_spa,buf,sizeof(buf)));
    fprintf(fp,"arp_tha=%s\n",my_ether_ntoa_r(arp->arp_sha,buf,sizeof(buf)));
    fprintf(fp,"arp_tpa=%s\n",arp_ip2str(arp->arp_tpa,buf,sizeof(buf)));
    return(0);
}
