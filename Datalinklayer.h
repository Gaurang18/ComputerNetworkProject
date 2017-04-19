#include "packetdef.h"
FILE* logfile;

#define linklayer(S,A) fprintf(logfile, "%s: %d\n",S,A);

void arppacket(unsigned char* buffer){
	struct arphdr *arpheader = (struct arphdr *)(buffer+14);
		fprintf(logfile , "\n\t\tARP Header\n");
	  linklayer("Hardware type",ntohs(arpheader->hardwarwtype));
	  linklayer("Protocol type",ntohs(arpheader->protocoltype));
	  linklayer("Operation",ntohs(arpheader->operation));
	  linklayer("Hardware address length",ntohs(arpheader->hardwareaddrlen));
	  linklayer("Protocol address length",ntohs(arpheader->protocoladdrlen));

	  if (ntohs(arpheader->hardwarwtype) == 1 && ntohs(arpheader->protocoltype) == 0x0800){ 
	  	int i;
	    /*printf("Sender MAC: "); 
	    int i;
	    for(i=0; i<6;i++)
	        printf("%02X:", arpheader->senderhaddr[i]); 

	    printf("\nSender IP: "); 

	    for(i=0; i<4;i++)
	        printf("%d.", arpheader->senderIPaddr[i]); 

	    printf("\nDestination MAC: "); 

	    for(i=0; i<6;i++)
	        printf("%02X:", arpheader->desthaddr[i]); 

	    printf("\nDestination IP: "); 

	    for(i=0; i<4; i++)
	        printf("%d.", arpheader->destIPaddr[i]); 
	    
	    printf("\n"); */
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	    fprintf(logfile,"Sender MAC: "); 
	    
	    for(i=0; i<6;i++)
	        fprintf(logfile,"%02X:", arpheader->senderhaddr[i]); 

	    fprintf(logfile,"\nSender IP: "); 

	    for(i=0; i<4;i++)
	        fprintf(logfile,"%d.", arpheader->senderIPaddr[i]); 

	    fprintf(logfile,"\nDestination MAC: "); 

	    for(i=0; i<6;i++)
	        fprintf(logfile,"%02X:", arpheader->desthaddr[i]); 

	    fprintf(logfile,"\nDestination IP: "); 

	    for(i=0; i<4; i++)
	        fprintf(logfile,"%d.", arpheader->destIPaddr[i]); 
	    
	    fprintf(logfile,"\n");
	  } 
}
void ethernet_header(unsigned char* buffer){
	fprintf(logfile , "********************Analysing Packet %d******************\n\n",packetnumber++);
		fprintf(logfile , "\n\t\tEthernet Header\n");
	struct my_ethhdr *eth = (struct my_ethhdr *)buffer;
	fprintf(logfile , "\n");
	fprintf(logfile , "Source MAC Address  : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->sourceaddr[0] , eth->sourceaddr[1] , eth->sourceaddr[2] , eth->sourceaddr[3] , eth->sourceaddr[4] , eth->sourceaddr[5] );
	fprintf(logfile , "Destination MAC Address  : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->destaddr[0] , eth->destaddr[1] , eth->destaddr[2] , eth->destaddr[3] , eth->destaddr[4] , eth->destaddr[5] );
	fprintf(logfile , "Protocol Number : %u \n",eth->protocol);
	arppacket(buffer);
}


