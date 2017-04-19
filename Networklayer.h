#include "Datalinklayer.h"

#define endline fprintf(logfile , "\n\n")
#define networkpacket(S,A) fprintf(logfile, "%s: %d\n",S,(unsigned int)A);

void init_source_dest_addr(){
	memset(&source, 0, sizeof(source));	
	memset(&dest, 0, sizeof(dest));
}

void ip_header(unsigned char* buffer)
{
	ethernet_header(buffer);
	endline;

	init_source_dest_addr();
	struct my_iphdr *iph = (struct my_iphdr *)(buffer + sizeof(struct my_ethhdr) );

	source.sin_addr.s_addr = iph->sourceaddr;
	dest.sin_addr.s_addr = iph->destaddr;
	endline;

	
	fprintf(logfile , "\n\t\tIP Header\n");
	networkpacket("Version", iph->version);
	networkpacket("Header Length in Bytes ", (iph->headerlength)*4);
	networkpacket("Type Of Service", iph->servicetype);
	networkpacket("Packet Total Length", ntohs(iph->tot_len));
	networkpacket("Id", ntohs(iph->id));
	networkpacket("Fragment offset", iph->frag_off);
	networkpacket("Time To Live (Number of Hops)", iph->ttl);
	networkpacket("Protocol", iph->protocol);
	networkpacket("Checksum", ntohs(iph->checksum));
	fprintf(logfile , "Source IP Address  : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile , "Destination IP Address  : %s\n",inet_ntoa(dest.sin_addr));
	endline;
}

void icmp_packet(unsigned char* buffer){

	init_source_dest_addr();
	struct my_iphdr *iph = (struct my_iphdr *)(buffer + sizeof(struct my_ethhdr));
	struct my_icmphdr *icmph = (struct my_icmphdr *)(buffer + (iph->headerlength*4)  + sizeof(struct my_ethhdr));
	endline;
	ip_header(buffer);

	fprintf(logfile , "\n\t\tICMP Header\n");
	fprintf(logfile , "ICMP Type  : ");
	switch((unsigned int)(icmph->type)){
		case 11:
			fprintf(logfile , " (TTL Expired)\n");
			break;
		case 3:
			fprintf(logfile , " (Destination Unreachable)\n");
			break;
		case 13:
			fprintf(logfile , " (Timestamp)\n");
			break;
		case 5:
			fprintf(logfile , " (Redirect)\n");
			break;
		case 0:
			fprintf(logfile , " (ICMP Echo Reply)\n");
			break;
		default:
			break;
	}			
	networkpacket("Code",(icmph->code));
	networkpacket("Checksum",ntohs(icmph->checksum));
	endline;
}

void igmp_packet(unsigned char* buffer)
{
	init_source_dest_addr();
	struct my_iphdr *iph = (struct my_iphdr *)(buffer + sizeof(struct my_ethhdr));
	struct my_igmphdr *igmph = (struct my_igmphdr *)(buffer + (iph->headerlength*4)  + sizeof(struct my_ethhdr));
	endline;
	ip_header(buffer);
	fprintf(logfile , "\n\t\tIGMP Header\n");
	
	switch((unsigned int)(igmph->type)){
		case 17:
			fprintf(logfile , " (IGMP Membership Query)\n");
			break;
		case 18:
			fprintf(logfile , " ((IGMPv1 Membership Report)\n");
			break;
		case 30:
			fprintf(logfile , " (Multicast Traceroute Response)\n");
			break;
		default:
			break;
	}			
	networkpacket("Code",(igmph->code));
	networkpacket("Checksum",ntohs(igmph->checksum));
	endline;
}