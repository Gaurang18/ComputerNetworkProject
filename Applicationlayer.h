#include "Transportlayer.h"
#define dnsnetworkc(S,A) fprintf(logfile, "%s%d\n",S,(unsigned char)A);
#define dnsnetworki(S,A) fprintf(logfile, "%s%d\n",S,(unsigned int)A);

void http_packet(unsigned char* buffer,int data_size,int header_size){
	httpp++;

	int i = header_size+1;
	fprintf(logfile , "\n\t\tHTTP Header\n");
	fprintf(logfile," %d %d\n",i,data_size);
	if(i>data_size)
		fprintf(logfile,"The HTTP payload is empty");
	while(!(buffer[i] == '\r' && buffer[i+1] == '\n' && buffer[i+2] == '\r' && buffer[i+3] == '\n') && i < data_size)
	{
		if(buffer[i] >= 32 && buffer[i] <= 128)
		fprintf(logfile,"%c",buffer[i]);
		i++;
	}
    fprintf(logfile,"\n");
	
}

void dns_packet(unsigned char* buffer, int total_size){
    
    dnsp++;
    unsigned short iphdrlength;
    init_source_dest_addr();
    struct my_iphdr *iph = (struct my_iphdr *)(buffer + sizeof(struct my_ethhdr) );
    iphdrlength =iph->headerlength*4;   
    struct my_udphdr *udph = (struct my_udphdr*)(buffer + iphdrlength  + sizeof(struct my_ethhdr));
    int header_size =  sizeof(struct my_ethhdr) + iphdrlength + sizeof(udph);
    struct my_dnshdr *dnshdr = (struct my_dnshdr*)(buffer + iphdrlength  + sizeof(udph) + sizeof(struct my_ethhdr));
    endline;
    //fprintf(logfile , "***********************DNS Header**********************\n"); 
    fprintf(logfile , "\n\t\tDNS Header\n");        
    fprintf(logfile , "DNS ID  : %u\n",dnshdr->id);
    dnsnetworkc("Recursion Flag: ",dnshdr->rd);
    dnsnetworkc("Truncation Flag: ",dnshdr->tc);
    dnsnetworkc("Authoritative Flag: ",dnshdr->aa);
    dnsnetworkc("Opcode: ",dnshdr->opcode);
    dnsnetworkc("Query: ",dnshdr->qr);
    dnsnetworkc("Response code: ",dnshdr->rcode);
    dnsnetworkc("Checking disabled: ",dnshdr->cd);
    dnsnetworkc("Authenticated data: ",dnshdr->ad);
    dnsnetworkc("Recursion available: ",dnshdr->ra);
    dnsnetworki("Question Count: ",dnshdr->q_count);
    dnsnetworki("Answer Count: ",dnshdr->ans_count);
    dnsnetworki("Authoritative Count: ",dnshdr->auth_count);
    dnsnetworki("Addn Count: ",dnshdr->add_count);
    endline;
}