#include "Networklayer.h"
#define tcppacket(S,A) fprintf(logfile, "%s%u\n",S,A);
#define tcppacketi(S,A) fprintf(logfile, "%s%d\n",S,(unsigned int)A);
#define udppacket(S,A) fprintf(logfile, "%s%d\n",S,(unsigned int)A);

void tcp_packet(unsigned char* buffer,int total_size)
{
	
	init_source_dest_addr();
	struct my_iphdr *iph = (struct my_iphdr *)(buffer + sizeof(struct my_ethhdr) );
	struct my_tcphdr *tcph=(struct my_tcphdr*)(buffer + iph->headerlength*4 + sizeof(struct my_ethhdr));		
	int header_size =  sizeof(struct my_ethhdr) + iph->headerlength*4 + tcph->offset*4;

	endline;
	ip_header(buffer);
			
	
	fprintf(logfile , "\n\t\tTCP Header\n");
	tcppacket("Source Port: ",ntohs(tcph->sourceport))
	tcppacket("Destination Port: ",ntohs(tcph->destport));
	tcppacket("Sequence Number: ",ntohl(tcph->seqno));
	tcppacket("Acknowledge Number: ",ntohl(tcph->ackno));
	tcppacketi("Header Length (BYTES): ",tcph->offset*4);
	tcppacketi("CWR Flag:",tcph->cwr);
	tcppacketi("ECN Flag: ",tcph->ece);
	tcppacketi("Urgent Flag: ",tcph->urg);
	tcppacketi("Acknowledgement Flag: ",tcph->ack);
	tcppacketi("Push Flag: ",tcph->psh);
	tcppacketi("Reset Flag: ",tcph->rst);
	tcppacketi("Synchronise Flag: ",tcph->syn);
	tcppacketi("Finish Flag: ",tcph->fin);
	tcppacket("Window: ",ntohs(tcph->window));
	tcppacket("Checksum: ",ntohs(tcph->checksum));
	tcppacket("Urgent Pointer: ",tcph->urgentp);
	endline;
	if(ntohs(tcph->sourceport) == 80 || ntohs(tcph->destport) == 80){
		http_packet(buffer,total_size,header_size);

	}
}

void udp_packet(unsigned char *buffer,int total_size){
	init_source_dest_addr();
	struct my_iphdr *iph = (struct my_iphdr *)(buffer + sizeof(struct my_ethhdr) );	
	struct my_udphdr *udph = (struct my_udphdr*)(buffer + iph->headerlength*4  + sizeof(struct my_ethhdr));
	int header_size =  sizeof(struct my_ethhdr) + iph->headerlength*4 + sizeof(udph);
	endline;
	ip_header(buffer);			
	
	fprintf(logfile , "\n\t\tUDP Header\n");
	udppacket("Source Port: " , ntohs(udph->sourceport));
	udppacket("Destination Port: " , ntohs(udph->destport));
	udppacket("UDP Length: " , ntohs(udph->length));
	udppacket("UDP Checksum: " , ntohs(udph->checksum));
	if(ntohs(udph->sourceport) == 53 || ntohs(udph->destport) == 53){
		dns_packet(buffer,total_size);
	}
}