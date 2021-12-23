#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h> 
#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
#include <ctype.h>
#include <errno.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h> 
#include <arpa/inet.h> 
#include <unistd.h>


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define DATA_SIZE  100
#define PCKT_LEN 4096


#define TH_SYN 0x02
#define SRC_IP "10.0.2.4"
#define DST_IP "10.0.2.6"
#define SRC_ETHER_ADDR	"aa:aa:aa:aa:aa:aa"
#define DST_ETHER_ADDR	"ff:ff:ff:ff:ff:ff"
#define SRC_PORT	25
#define DST_PORT	10000
#define THE_DATA "Hello, you've been spoofed!"

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


struct ipheader {
 unsigned char ip_hl:4, ip_v:4; /* this means that each member is 4 bits */
 unsigned char ip_tos;
 unsigned short int ip_len;
 unsigned short int ip_id;
 unsigned short int ip_off;
 unsigned char ip_ttl;
 unsigned char ip_p;
 unsigned short int ip_sum;
 unsigned int ip_src;
 unsigned int ip_dst;
}; /* total ip header length: 20 bytes (=160 bits) */

struct icmpheader { //correct
 unsigned char icmp_type;
 unsigned char icmp_code;
 unsigned short int icmp_cksum;
 unsigned short int icmp_id;
 unsigned short int icmp_seq;
}; /* total icmp header length: 8 bytes (=64 bits) */


char password[0];
int offline;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

unsigned short csum2(unsigned short *addr, int len){
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1){
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_tcp *tcp;            /* The TCP header */
	struct ipheader *ip; 				// instead use my own ip header
	struct icmpheader *icmp;           // instead use my own icmp header

	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct ipheader*)(packet + SIZE_ETHERNET);
	size_ip = ip->ip_hl*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}


	/* print source and destination IP addresses */
	printf("       From: %d\n", ntohl(ip->ip_src));
	printf("         To: %d\n", ntohl(ip->ip_dst));


	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			return;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is ICMP packet so now we want to send a spoofed packet.
	 */
    if(ip->ip_p == IPPROTO_ICMP){
        //do socket stuff

        char buffer[PCKT_LEN]; 
        memset(buffer, 0, PCKT_LEN);
        
        int sd;
        struct sockaddr_in sin;

        struct ipheader *iphr = (struct ipheader *) buffer;
        struct icmpheader *icmpr = (struct icmpheader *)(buffer + sizeof(struct ipheader));

		icmp = (struct icmpheader*)(packet + SIZE_ETHERNET + size_ip);

        sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // creating the raw socket
        if(sd < 0) {
            perror("socket() error"); 
            exit(-1);
        }else{
            printf("socket() - Using SOCK_RAW socket and it is working.\n");
        }
        

        sin.sin_family = AF_INET;
        sin.sin_port = htons(25); 
        sin.sin_addr.s_addr = inet_addr("10.0.2.6");

		// char *data = buffer + sizeof(struct ipheader) + sizeof(struct icmpheader);
		// const char *msg = THE_DATA;
		// int data_len = strlen(msg);
		// strcpy(data, msg);

		//Setting the IP and ICMP HEADERS for Spoofed packet
        iphr->ip_hl = 5;
        iphr->ip_v = 4;
        iphr->ip_tos = 0;
        iphr->ip_len = sizeof(struct ipheader) + sizeof(struct icmpheader);
        iphr->ip_id = ip->ip_id; 
        iphr->ip_off = ip->ip_off; 
        iphr->ip_ttl = ip->ip_ttl;
        iphr->ip_p = IPPROTO_ICMP;
        iphr->ip_sum= 0; //Set to 0 before calculating checksum
		iphr->ip_src = ip->ip_dst; //
        iphr->ip_dst = sin.sin_addr.s_addr;


        icmpr->icmp_type = 0; //0 is echo reply and 8 is echo
		icmpr->icmp_code = 0;
		icmpr->icmp_id  = icmp->icmp_id;
		icmpr->icmp_seq = icmp->icmp_seq;
        icmpr->icmp_cksum = 0;
        icmpr->icmp_cksum = csum2((unsigned short *)icmpr, (sizeof(struct icmpheader)));

        int one = 1;
        const int *val = &one;

        if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, val, 1) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }

        iphr->ip_sum = csum2((unsigned short *) buffer, iphr->ip_len >> 1);

        // sending the spoofed packet out
        if(sendto(sd, buffer, iphr->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto() error"); exit(-1);
        } else{
            printf("sendto() - is working.\n");
        }
        
        close(sd);

    }	
    return;
}


int main(int argc, char **argv)
{
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "icmp and (src host 10.0.2.6)";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;		/* number of packets to capture */

	print_app_banner();
	
	char* fname;

	/* check for capture device name on command-line */
	if (argc == 2) {
		//dev = argv[1];
		fname = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */  //
		//sniffex tstsionpcap > output
		dev = pcap_lookupdev(errbuf);

		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);

		}
		printf("found DEvice\n");
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);
	
	

	/* open capture device */
	if(argc == 2){ 
		offline = 1;
		handle = pcap_open_offline(fname, errbuf);
	} else{
		offline = 0;
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	}
	
	//printf("Test - Handle: %d\n", SNAP_LEN);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);
	// I want to spoof when we call got_packets

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

    return 0;


}

