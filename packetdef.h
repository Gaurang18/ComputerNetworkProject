#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>	
#include <string.h>	
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <stdint.h>
#include <signal.h>
#define octet_in_eth 6
#define ARP_REQUEST 1   
#define ARP_REPLY 2     
struct sockaddr_in source,dest;

int tcp=0,udp=0,icmp=0,others=0,igmp=0,sctp=0,irtp=0,ipv6=0,total=0,httpp = 0,dnsp = 0;

int flagtime = 1; 
int packetnumber = 1;

struct my_ethhdr {
	__u8 destaddr[6];
	__u8 sourceaddr[6];
	__u16 protocol;
};

struct my_iphdr{
  __u8    headerlength:4;
  __u8    version:4;
  __u8    servicetype;
  __u16   tot_len;
  __u16   id;
  __u16   frag_off;
  __u8    ttl;
  __u8    protocol;
  __u16   checksum;
  __u32   sourceaddr;
  __u32   destaddr;
};

struct my_dnshdr
{
    __u16 id; 
 
    __u8 rd :1; 
    __u8 tc :1; 
    __u8 aa :1; 
    __u8 opcode :4; 
    __u8 qr :1;
 
    __u8 rcode :4; 
    __u8 cd :1; 
    __u8 ad :1; 
    __u8 z :1;
    __u8 ra :1; 
 
    __u16 q_count; 
    __u16 ans_count; 
    __u16 auth_count; 
    __u16 add_count; 
};

struct arphdr { 
    u_int16_t hardwarwtype;    /* Hardware Type           */ 
    u_int16_t protocoltype;    /* Protocol Type           */ 
    u_char hardwareaddrlen;        /* Hardware Address Length */ 
    u_char protocoladdrlen;        /* Protocol Address Length */ 
    u_int16_t operation;     /* Operation Code          */ 
    u_char senderhaddr[6];      /* Sender hardware address */ 
    u_char senderIPaddr[4];      /* Sender IP address       */ 
    u_char desthaddr[6];      /* Target hardware address */ 
    u_char destIPaddr[4];      /* Target IP address       */ 
}; 

struct my_icmphdr
{
  __u8 type;		
  __u8 code;	
  __u16 checksum;
};

struct my_igmphdr {
	__u8	type;	
	__u8	code;	
	__u16 checksum;
};	

struct my_tcphdr
{
    __u16 sourceport; 
    __u16 destport;   
    __u32 seqno; 
    __u32 ackno; 
    __u16 res:4;
    __u16 offset : 4;    
    __u16 fin:1;
    __u16 syn:1;
    __u16 rst:1;
    __u16 psh:1;
    __u16 ack:1;
    __u16 urg:1;
    __u16 ece:1;
    __u16 cwr:1;
    __u16 window;
    __u16 checksum;
    __u16 urgentp;
};

struct my_udphdr {
	__u16 sourceport;    
  __u16 destport;
	__u16 length;
	__u16 checksum;
};
