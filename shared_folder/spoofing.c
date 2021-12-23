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


#define DATA_SIZE  100
#define PCKT_LEN 4096
#define TH_SYN 0x02
#define SRC_IP "10.0.2.4"
#define DST_IP "10.0.2.6"
#define SRC_PORT	25
#define DST_PORT	10000
#define THE_DATA "Hello, you've been spoofed!"


// headers referenced from  https://people.engr.tamu.edu/guofei/csce465/rawip.txt
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

struct udpheader { //correct
 unsigned short int udph_srcport;
 unsigned short int udph_destport;
 unsigned short int udph_len;
 unsigned short int udph_chksum;

}; /* total udp header length: 8 bytes (=64 bits) */


struct tcpheader {
 unsigned short int th_sport;
 unsigned short int th_dport;
 unsigned int th_seq;
 unsigned int th_ack;
 unsigned char th_x2:4, th_off:4;
 unsigned char th_flags;
 unsigned short int th_win;
 unsigned short int th_sum;
 unsigned short int th_urp;
}; /* total tcp header length: 20 bytes (=160 bits) */
 
 
/* this function generates header checksums */
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

/*****************************************************************************************************************/
/*                                                                                                               */
/*         The Checksum function above is referenced from: http://www.cplusplus.com/forum/unices/168391/         */
/*                                                                                                               */
/*****************************************************************************************************************/

int main(int argc, char **argv)
{

	char buffer[4096]; 
	memset(buffer, 0, 4096);
	
	int sd;
	struct sockaddr_in sin;

	struct ipheader *iph = (struct ipheader *) buffer;
	struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
	struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
		
	/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
	CSCE 465 Computer and Network Security 3
	* tells the sytem that the IP header is already included;
	* this prevents the OS from adding another IP header. */

	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // creating the raw socket
	if(sd < 0) {
		perror("socket() error"); 
		exit(-1);
	}else{
		printf("socket() - Using SOCK_RAW socket and it is working.\n");
	}
	
	/* This data structure is needed when sending the packets
	* using sockets. Normally, we need to fill out several
	* fields, but for raw sockets, we only need to fill out
	* this one field */

	sin.sin_family = AF_INET;
	sin.sin_port = htons(25); 
	sin.sin_addr.s_addr = inet_addr("10.0.2.6");

/*************************************************************************************************************************************/

	//Constructin IP header

	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;
	iph->ip_len = sizeof(struct ipheader) + sizeof(struct icmpheader); 
	iph->ip_id = htonl(54321); //Id of this packet
	iph->ip_off = 0;
	iph->ip_ttl = 255;
	iph->ip_p = IPPROTO_ICMP;
	iph->ip_sum= 0; //Set to 0 before calculating checksum
	iph->ip_src = inet_addr ("10.0.2.4"); //Spoof the source ip address
	iph->ip_dst = sin.sin_addr.s_addr;


	//Constructin ICMP header

	icmp->icmp_type = 8; 
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = csum2((unsigned short *)icmp, (sizeof(struct icmpheader)));
	
	
/*******************************************TCP_HEADER CODE*****************************************************************/
 
//Used for part 2a of task 2
// 	// Constructing the TCP header
// 	// The TCP structure. The source port, spoofed, we accept through the command line

	// tcp->th_sport = htons(1234);
	// // The destination port, we accept through command line
	// tcp->th_dport = htons(25);
	// tcp->th_seq = random();
	// tcp->th_ack = 0;
	// tcp->th_off = 5;
	// tcp->th_ack = 0;
	// tcp->th_win = htonl(65535);
	// tcp->th_sum = 0; // Done by kernel
	// tcp->th_urp = 0;
	// // IP checksum calculation
/*******************************************TCP_HEADER CODE*****************************************************************/


	iph->ip_sum = csum2((unsigned short *) buffer, iph->ip_len >> 1);
	

	int one = 1;
	const int *val = &one;

	if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, val, 1) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

	// sending the spoofed packet out
	if(sendto(sd, buffer, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("sendto() error"); exit(-1);
	} else{
		printf("sendto() - is working.\n");
	}
	
	close(sd);
	return 0;

}

