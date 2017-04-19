#include "Applicationlayer.h"



char* flush(char *str){
	int i;
	for(i=0;i<strlen(str);i++){
		str[i] = '\0';
	}
	return str;
}

void handler(int signo)
{
	flagtime = 0;
}

void Packetanalysis(unsigned char* buffer,int total_size)
{
	struct my_iphdr *iph = (struct my_iphdr*)(buffer + sizeof(struct my_ethhdr));
		++total;
		if(iph->protocol == 1 ){
			++icmp;
			icmp_packet(buffer);
			
		}
		else if(iph->protocol == 2 ){
			++igmp;
			igmp_packet( buffer);
		}
		else if(iph->protocol == 6 ){
			++tcp;
			tcp_packet(buffer,total_size);
		}
		else if(iph->protocol == 17){
			++udp;
			udp_packet(buffer,total_size);
		}
		else{ 
			++others;
		}

	printf("\nTCP  : %d   UDP  : %d   ICMP  : %d   IGMP  : %d   DNS  : %d 	HTTP:%d  Others  : %d\nTotal number of packets captured  : %d\r", tcp,udp,icmp,igmp,dnsp,httpp,others,total);
}
void filter()
{
	FILE *customfile;
	FILE *newfile;
	int i = 0,opt,lines = 0,k = 0;
	char temp[1500],option[15];
	printf("Enter the protocol number\n");
	printf(" 1.TCP Header \n 2.UDP Header \n 3. ICMP Header \n 4.IGMP Header \n 5.IP Header");
	scanf("%d",&opt);
	switch(opt)
	{
		case 1: strcpy(option,"TCP Header");
				k = 20;
				break;
		case 2: strcpy(option,"UDP Header");
				k = 7;
				break;
		case 3: strcpy(option,"ICMP Header");
				k = 8;
				break;
		case 4: strcpy(option,"IGMP Header");
				k = 7;
				break;
		case 5: strcpy(option,"IP Header");
				k = 15;
				break;
		default:
				break;
	}
	newfile = fopen("packetlog.txt","r");
	fseek(newfile,0,SEEK_SET);
	customfile = fopen("customlog.txt","w");
	while(fgets(temp,1024,newfile) != NULL) {
	if((strstr(temp, option)) != NULL) {
			//fprintf(customfile,"%s\n",temp);
			//fprintf(customfile, "%s\n",temp);
		//fprintf(customfile,"hello");
				lines = k;
	}
		if(lines){
			fprintf(customfile,"%s\n", temp);
			lines--;
		}
	}
	fclose(newfile);
	fclose(customfile);

}
int main(){

	int addrsize , datasize;
	int a;
	struct sockaddr saddr;	
	unsigned char *buffer = (unsigned char *) malloc(65536);
	
	logfile = fopen("packetlog.txt","w");
	printf("*************PROTOCOL ANALYST *****************\n");
	if(logfile==NULL) 
	{
		printf("Unable to create packetlog.txt file!");
		exit(0);
	}
	printf("Starting the Analyser\n");
	printf("The Output will be printed in file called as \"packetlog.txt\"\n");
	printf("Protocol Analyst :: Please Open any network Application, keeping the Program running.\n");
	
	int sock = socket( AF_PACKET ,SOCK_RAW , htons(ETH_P_ALL)) ;
	
	if(sock < 0)
	{
		perror("Can't open the socket!\n");
		return -1;
	}
	printf("How do you want to Analyse packets. PLease Enter \n");
	printf("1. To analyse a fixed number of packets\n2. To analyse for a particular time\n3. Press Ctrl + C to terminate, output is in packetlog file\n");

	int gh;
	scanf("%d",&gh);
	if(gh == 1)
	{
		int count;
		printf("Enter the number of packets you want to capture and analyse...\n");
		scanf("%d",&count);
		while(count--)
		{
			addrsize = sizeof(saddr);
			datasize = recvfrom(sock , buffer , 65536 , 0 , &saddr , (socklen_t*) &addrsize);
			if(datasize < 0 )
			{
				printf("Could not get any packets from interface\n");
				return -1;
			}
			//arppacket(buffer);
			Packetanalysis(buffer,datasize);

		}
	}
	else if (gh == 2)
	{
		signal(SIGALRM,handler);
		printf("Enter the amount of time you wish to capture packets for(in seconds)");
    	scanf("%d",&a);
    	alarm(a);
		while(flagtime)
		{
			//printf("going?");
			addrsize = sizeof(saddr);
			datasize = recvfrom(sock , buffer , 65536 , 0 , &saddr , (socklen_t*) &addrsize);
			if(datasize < 0 )
			{
				printf("Could not get any packets from interface\n");
				return -1;
			}
			Packetanalysis(buffer,datasize);
		}
	}
	else if (gh == 3)
	{
		printf("Please press Ctrl + C to exit");
		while(flagtime)
		{
			addrsize = sizeof(saddr);
			datasize = recvfrom(sock , buffer , 65536 , 0 , &saddr , (socklen_t*) &addrsize);
			if(datasize < 0 )
			{
				printf("Could not get any packets from interface\n");
				return -1;
			}
			Packetanalysis(buffer,datasize);
		}
	}else{
		printf("Please Enter a valid option\n");
	}
	
	close(sock);
	buffer = flush(buffer);
	printf("\nYour Output in files created in your directory\n");
	//printf("hello");
	/*printf("Do you wish to get Protocol Statistics\n Press 1 as Yes and 0 for No\n");
	int pl;
	scanf("%d",&pl);
	if(pl == 1){
		printf("percentage of TCP Packets : %.2f\n",tcp/total*100);
		printf("percentage of UDP Packets : %.2f\n",udp/total*100);
		printf("percentage of HTTP Packets : %.2f\n",httpp/total*100);
		printf("percentage of DNS Packets : %.2f\n",dnsp/total*100);
		printf("percentage of ICMP Packets : %.2f\n",icmp/total*100);
		printf("percentage of IGMP Packets : %.2f\n",igmp/total*100);
	}*/
	printf("\nDo you wish to filter the log file for specific entries? 1 for yes or 0 for no\n");
	int pl;
	scanf("%d",&pl);
	fclose(logfile);
	while(pl == 1)
	{
		filter();
		pl = 0;
		printf("\n Do you want to filter again? 1 for yes or 0 for no\n");
		scanf("%d",&pl);
		if(pl != 1){
			break;
		}
	}
	printf("\nThank You for Using Protocol Analyst\n");
	return 0;
}