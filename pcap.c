#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#define MAC_ADDRSTRLEN 2*6+5+1
#define NONE "\033[m"

#define RED "\033[0;32;31m"

#define LIGHT_RED "\033[1;31m"

#define GREEN "\033[0;32;32m"

#define LIGHT_GREEN "\033[1;32m"

#define BLUE "\033[0;32;34m"

#define LIGHT_BLUE "\033[1;34m"

#define DARY_GRAY "\033[1;30m"

#define CYAN "\033[0;36m"

#define LIGHT_CYAN "\033[1;36m"

#define PURPLE "\033[0;35m"

#define LIGHT_PURPLE "\033[1;35m"

#define BROWN "\033[0;33m"

#define YELLOW "\033[1;33m"

#define LIGHT_GRAY "\033[0;37m"

#define WHITE "\033[1;37m"
int color ;
int openfile;
void dump_ethernet(u_int32_t length, const u_char *content);
void dump_ip(struct ip *ip);
void dump_tcp_mini(struct tcphdr *tcp);
void dump_tcp(struct tcphdr *tcp);
void dump_udp(struct udphdr *udp);
void dump_icmp(struct icmp *icmp);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);
char *mac_ntoa(u_char *d);
char *ip_ntoa(void *i);
char *ip_ttoa(u_int8_t flag);
char *ip_ftoa(u_int16_t flag);
char *tcp_ftoa(u_int8_t flag);
struct _ {
	int num;
	char ip[200];
};
struct _ count[1000];
int t=0;
char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDRSTRLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}//end mac_ntoa
char *ip_ntoa(void *i) {
    static char str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, i, str, sizeof(str));

    return str;
}//end ip_ntoa
char *ip_ttoa(u_int8_t flag) {
    static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
#define TOS_MAX (sizeof(f)/sizeof(f[0]))
    static char str[TOS_MAX + 1]; //return buffer
    u_int8_t mask = 1 << 7; //mask
    int i;

    for(i = 0 ; i < TOS_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;

    return str;
}//end ip_ttoa

char *ip_ftoa(u_int16_t flag) {
    static int f[] = {'R', 'D', 'M'}; //flag
#define IP_FLG_MAX (sizeof(f)/sizeof(f[0]))
    static char str[IP_FLG_MAX + 1]; //return buffer
    u_int16_t mask = 1 << 15; //mask
    int i;

    for(i = 0 ; i < IP_FLG_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;

    return str;
}//end ip_ftoa
char *tcp_ftoa(u_int8_t flag) {
    static int  f[] = {'W', 'E', 'U', 'A', 'P', 'R', 'S', 'F'};
#define TCP_FLG_MAX (sizeof f / sizeof f[0])
    static char str[TCP_FLG_MAX + 1];
    u_int32_t mask = 1 << 7;
    int i;

    for (i = 0; i < TCP_FLG_MAX; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = '\0';

    return str;
}//end tcp_ftoa
void dump_icmp(struct icmp *icmp);
void dump_ip(struct ip *ip) {

    //copy header
    u_int version = ip->ip_v;
    u_int header_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);
    u_int16_t id = ntohs(ip->ip_id);
    u_int16_t offset = ntohs(ip->ip_off);
    u_char ttl = ip->ip_ttl;
    u_char protocol = ip->ip_p;
    u_int16_t checksum = ntohs(ip->ip_sum);
    if(color)
        printf(RED);
    //print
    printf("Protocol: IP\n");
    printf("+-----+------+------------+-------------------------+\n");
    printf("| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|\n",
           version, header_len, ip_ttoa(tos), total_len);
    printf("+-----+------+------------+-------+-----------------+\n");
    printf("| Identifier:        %5u| FF:%3s| FO:        %5u|\n",
           id, ip_ftoa(offset), offset & IP_OFFMASK);
    printf("+------------+------------+-------+-----------------+\n");
    printf("| TTL:    %3u| Pro:    %3u| Header Checksum:   %5u|\n",
           ttl, protocol, checksum);
    printf("+------------+------------+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n",  ip_ntoa(&ip->ip_src));
    printf("+---------------------------------------------------+\n");
    printf("| Destination IP Address:            %15s|\n", ip_ntoa(&ip->ip_dst));
    printf("*****************************************************\n");

    char *p = (char *)ip + (ip->ip_hl << 2);
    switch (protocol) {
        case IPPROTO_UDP:
            dump_udp((struct udphdr *)p);
            break;

        case IPPROTO_TCP:
            dump_tcp((struct tcphdr *)p);
            break;

        case IPPROTO_ICMP:
            dump_icmp((struct icmp *)p);
            break;

        default:
            printf("Next is %d\n", protocol);
            break;
    }//end switch
}//end dump_ip
void dump_tcp(struct tcphdr *tcp) {
    if(color)
        printf(YELLOW);
    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);
    u_int32_t ack = ntohl(tcp->th_ack);
    u_int8_t header_len = tcp->th_off << 2;
    u_int8_t flags = tcp->th_flags;
    u_int16_t window = ntohs(tcp->th_win);
    u_int16_t checksum = ntohs(tcp->th_sum);
    u_int16_t urgent = ntohs(tcp->th_urp);

    //print
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10u|\n", sequence);
    printf("+---------------------------------------------------+\n");
    printf("| Acknowledgement Number:                 %10u|\n", ack);
    printf("+------+-------+----------+-------------------------+\n");
    printf("| HL:%2u|  RSV  |F:%8s| Window Size:       %5u|\n", header_len, tcp_ftoa(flags), window);
    printf("+------+-------+----------+-------------------------+\n");
    printf("| Checksum:          %5u| Urgent Pointer:    %5u|\n", checksum, urgent);
    printf("*****************************************************\n");
    printf(NONE);
}//end dump_tcp
void dump_udp(struct udphdr *udp) {
    if(color)
        printf(YELLOW);
    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);

    printf("Protocol: UDP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Length:            %5u| Checksum:          %5u|\n", len, checksum);
    printf("*****************************************************\n");
    printf(NONE);
}//end dump_udp
void dump_tcp_mini(struct tcphdr *tcp) {
    if(color)
        printf(PURPLE);
    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);

    //print
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10u|\n", sequence);
    printf("*****************************************************\n");
    printf(NONE);
}//end dump_tcp_mini
void dump_icmp(struct icmp *icmp) {
    if(color)
        printf(YELLOW);
    //copy header
    u_char type = icmp->icmp_type;
    u_char code = icmp->icmp_code;
    u_char checksum = ntohs(icmp->icmp_cksum);

    static char *type_name[] = {
        "Echo Reply",               /* Type  0 */
        "Undefine",                 /* Type  1 */
        "Undefine",                 /* Type  2 */
        "Destination Unreachable",  /* Type  3 */
        "Source Quench",            /* Type  4 */
        "Redirect (change route)",  /* Type  5 */
        "Undefine",                 /* Type  6 */
        "Undefine",                 /* Type  7 */
        "Echo Request",             /* Type  8 */
        "Undefine",                 /* Type  9 */
        "Undefine",                 /* Type 10 */
        "Time Exceeded",            /* Type 11 */
        "Parameter Problem",        /* Type 12 */
        "Timestamp Request",        /* Type 13 */
        "Timestamp Reply",          /* Type 14 */
        "Information Request",      /* Type 15 */
        "Information Reply",        /* Type 16 */
        "Address Mask Request",     /* Type 17 */
        "Address Mask Reply",       /* Type 18 */
        "Unknown"                   /* Type 19 */
    }; //icmp type
#define ICMP_TYPE_MAX (sizeof type_name / sizeof type_name[0])

    if (type < 0 || ICMP_TYPE_MAX <= type)
        type = ICMP_TYPE_MAX - 1;

    printf("Protocol: ICMP (%s)\n", type_name[type]);

    printf("+------------+------------+-------------------------+\n");
    printf("| Type:   %3u| Code:   %3u| Checksum:          %5u|\n", type, code, checksum);
    printf("+------------+------------+-------------------------+\n");

    if (type == ICMP_ECHOREPLY || type == ICMP_ECHO) {
        printf("| Identification:    %5u| Sequence Number:   %5u|\n", ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
        printf("+-------------------------+-------------------------+\n");
    }//end if
    else if (type == ICMP_UNREACH) {
        if (code == ICMP_UNREACH_NEEDFRAG) {
            printf("| void:          %5u| Next MTU:          %5u|\n", ntohs(icmp->icmp_pmvoid), ntohs(icmp->icmp_nextmtu));
            printf("+-------------------------+-------------------------+\n");
        }//end if
        else {
            printf("| Unused:                                 %10lu|\n", (unsigned long) ntohl(icmp->icmp_void));
            printf("+-------------------------+-------------------------+\n");
        }//end else
    }//end if
    else if (type == ICMP_REDIRECT) {
        printf("| Router IP Address:                 %15s|\n", ip_ntoa(&(icmp->icmp_gwaddr)));
        printf("+---------------------------------------------------+\n");
    }//end if
    else if (type == ICMP_TIMXCEED) {
        printf("| Unused:                                 %10lu|\n", (unsigned long)ntohl(icmp->icmp_void));
        printf("+---------------------------------------------------+\n");
    }//end else

    //if the icmp packet carry ip header
    if (type == ICMP_UNREACH || type == ICMP_REDIRECT || type == ICMP_TIMXCEED) {
        struct ip *ip = (struct ip *)icmp->icmp_data;
        char *p = (char *)ip + (ip->ip_hl << 2);
        dump_ip(ip);

        switch (ip->ip_p) {
            case IPPROTO_TCP:
                if(type == ICMP_REDIRECT) {
                    dump_tcp_mini((struct tcphdr *)p);
                }//end if
                else {
                    dump_tcp((struct tcphdr *)p);
                }//end else
                break;
            case IPPROTO_UDP:
                dump_udp((struct udphdr *)p);
                break;
        }//end switch
    }//end if
    printf(NONE);
}//end dump_icmp

void dump_ethernet(u_int32_t length, const u_char *content) {
    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[MAC_ADDRSTRLEN] = {'\0'};
    char src_mac_addr[MAC_ADDRSTRLEN] = {'\0'};
    u_int16_t type;

    //copy header
    strncpy(dst_mac_addr, mac_ntoa(ethernet->ether_dhost), sizeof(dst_mac_addr));
    strncpy(src_mac_addr, mac_ntoa(ethernet->ether_shost), sizeof(src_mac_addr));
    type = ntohs(ethernet->ether_type);
    if(color)
        printf(BLUE);
    //print
    if(type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");

    printf("+-------------------------+----------------+-------------------------+\n");
    printf("| Destination MAC Address:                     %17s|\n", dst_mac_addr);
    printf("+-------------------------+----------------+-------------------------+\n");
    printf("| Source MAC Address:                          %17s|\n", src_mac_addr);
    printf("+-------------------------+----------------+-------------------------+\n");
    if (type < 1500)
        printf("| Length:            %5u|\n", type);
    else
        printf("| Ethernet Type:    0x%04x|\n", type);
    printf("***************************\n");
    
    switch (type) {
        case ETHERTYPE_ARP:
            printf("Next is ARP\n");
            break;

        case ETHERTYPE_IP:
            dump_ip((struct ip *)(content + ETHER_HDR_LEN));
            break;

        case ETHERTYPE_REVARP:
            printf("Next is RARP\n");
            break;

        case ETHERTYPE_IPV6:
            printf("Next is IPv6\n");
            break;

        default:
            printf("Next is %#06x", type);
            break;
    }//end switch

}//end dump_ethernet
void pcap_callback_for_read(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("No. %d\n", ++d);

    //print header
    printf("\tTime: %s.%.6ld\n", timestr, header->ts.tv_usec);
    printf("\tLength: %d bytes\n", header->len);
    printf("\tCapture length: %d bytes\n", header->caplen);

    //dump ethernet
    dump_ethernet(header->caplen, content);

    printf("\n");
}//end pcap_callback
void pcap_callback(u_char * arg, const struct pcap_pkthdr * header, const u_char * content)
{
	static int d = 0;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("No. %d\n", ++d);

    //print header
    printf("\tTime: %s.%.6ld\n", timestr, header->ts.tv_usec);
    printf("\tLength: %d bytes\n", header->len);
    printf("\tCapture length: %d bytes\n", header->caplen);

    //dump ethernet
    dump_ethernet(header->caplen, content);
	fflush(stdout);
	//dump to file
	pcap_dump(arg, header, content);
}

int main(int argc , char** argv) {
    color = 0;
    openfile = 0;
    int cmd_opt = 0;
    // get the argv
    fprintf(stderr, "argc:%d\n", argc);
    int l=1;
    int n=0;
    int N=-1;
    while(1) {
        cmd_opt = getopt(argc, argv, "N::n::fc");

        /* End condition always first */
        if (cmd_opt == -1) {
            break;
        }
        /* Lets parse */
        switch (cmd_opt) {
            case 'c' :
                color = 1;
                break;
            case 'f' :
                openfile = 1;
                break;
            case 'n': {
                printf("input your filename !");
                char filename[100] = {'\0'};
                scanf("%s",filename);
                if (optarg) {
                    fprintf(stderr, "Try to capture #arg:%s\n", optarg);
                    n = atoi(optarg);
                }
                else {
                    n = 10;
                }
                char errbuf[PCAP_ERRBUF_SIZE];
                char * device = NULL;
                pcap_if_t *div;
                int ret = 0;

                //get default interface name
                ret = pcap_findalldevs(&div,errbuf);
                if(ret == PCAP_ERROR) {
                    fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
                    exit(1);
                }//end if
                device = div[0].name;
                //show divice name
                printf("device: %s\n", device);

                //get IP info
                bpf_u_int32 netp = 0, maskp = 0;
                ret = pcap_lookupnet(device, &netp, &maskp, errbuf);
                if(ret == -1)
                {
                    perror(errbuf);
                    exit(-1);
                }
                //show info
                struct in_addr ip_addr,mask;
                ip_addr.s_addr = netp;
                mask.s_addr = maskp;
                if(l)
                    printf("Net : %s\nMask : %s\n",inet_ntoa(ip_addr) ,inet_ntoa(mask));
                
                //open interface
                pcap_t *handle = pcap_open_live(device, 65535, 1, 1, errbuf);
                if(!handle) {
                    fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
                    exit(1);
                }//end if

                int i=0;
                //open file handler
            
                
                pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
                if(!dumper) {
                    fprintf(stderr, "pcap_dump_open(): %s\n", pcap_geterr(handle));
                    pcap_close(handle);
                    exit(1);
                }//end if
                
                printf("file : %sn", filename);
                pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);
                //start capture loop
                if(0 != pcap_loop(handle, n, pcap_callback, (u_char *)dumper)) {
                    fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(handle));
                }//end if
                //flush and close
                
                pcap_dump_flush(dumper);
                pcap_dump_close(dumper);
                printf("\nDone\n");
                //free
                pcap_close(handle);
                break;
            }
            case 'N':{
                if (optarg) {
                    fprintf(stderr, "Try to capture #arg:%s\n", optarg);
                    N = atoi(optarg);
                }
                else {
                    N = -1;
                }
                //printf("argc=%d\n",argc);
                char errBuf[PCAP_ERRBUF_SIZE], * devStr;
                char filename[100]= {'\0'};
                memset(count,0,sizeof(count));
                /* get a device */
                pcap_if_t *div;
                int ret = pcap_findalldevs(&div,errBuf);
                if(ret == PCAP_ERROR) {
                    fprintf(stderr, "pcap_findalldevs(): %s\n", errBuf);
                        exit(1);
                }//end if
                devStr = div[0].name;

                if(devStr)
                {
                    printf("success: device: %s\n", devStr);
                }
                else
                {
                    printf("error: %s\n", errBuf);
                    exit(1);
                }
                pcap_t *handle = NULL;
                handle = pcap_open_live(devStr, 65535, 1, 1, errBuf);
                if(openfile){
                    printf("input filename\n");
                    scanf("%s",filename);
                    handle = pcap_open_offline(filename, errBuf);
                }
                    
                if(!handle) {
                    fprintf(stderr, "pcap_open_live: %s\n", errBuf);
                    exit(1);
                }//end if

                //ethernet only
                if(pcap_datalink(handle) != DLT_EN10MB) {
                    fprintf(stderr, "Sorry, Ethernet only.\n");
                    pcap_close(handle);
                    exit(1);
                }//end if

                //start capture
                pcap_loop(handle, N, pcap_callback_for_read, NULL);

                //free
                pcap_close(handle);
                return 0;
                break;
            }
            /* Error handle: Mainly missing arg or illegal option */
            case '?':
                fprintf(stderr, "Illegal option:-%c\n", isprint(optopt)?optopt:'#');
                break;
            default:
                fprintf(stderr, "Not supported option\n");
                break;
        }
    }	
}