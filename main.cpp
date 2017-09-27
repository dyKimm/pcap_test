#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#define SIZE_ETHERNET 14
void usage(){};
	int main(int argc, char *argv[])
 	{
		if (argc != 2) {
 		   	usage();
			return -1;
		}
		char* dev = argv[1];
  		char errbuf[PCAP_ERRBUF_SIZE];
 		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  		if (handle == NULL) {
    			fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
  	}

  	while (true) {
    		struct pcap_pkthdr* header;
    		const u_char* packet;
		struct libnet_ethernet_hdr *ethernet;
		struct libnet_ipv4_hdr *ip;
		struct libnet_tcp_hdr *tcp;
		const u_char *payload;
		u_int size_ip;
		u_int size_tcp;
		int n=0;
    		int res = pcap_next_ex(handle, &header, &packet);
		ethernet=(struct libnet_ethernet_hdr*)(packet);
		ip=(struct libnet_ipv4_hdr*)(packet+SIZE_ETHERNET);
		size_ip = (ip->ip_hl)*4;
		tcp=(struct libnet_tcp_hdr*)(packet+SIZE_ETHERNET+size_ip);
		size_tcp = (tcp->th_off)*4;
		payload=(u_char*)(packet+SIZE_ETHERNET+size_ip+size_tcp);
    		if (res == 0) continue;
    		if (res == -1 || res == -2) break;
    		printf("------------------------------\n");
		printf("%u bytes captured\n\n", header->caplen);
		
		if (header->caplen!=0){
			//ethernet
			printf("ethernet src \n");
			
			for(n=0;n<6;n++){
				printf(":%.2x",ethernet->ether_shost[n]);
			}
			printf("\n");
			printf("ethernet dst: \n");
			
			for(n=0;n<6;n++){
				printf(":%.2x",ethernet->ether_dhost[n]);
			}
			printf("\n\n");
			//ip
			if(ntohs(ethernet->ether_type)==0x0800){
				printf("ip src: %s\n",inet_ntoa(ip->ip_src));
				printf("ip dst: %s\n\n",inet_ntoa(ip->ip_dst));
			}
			else{
				printf("No ip packet!\n\n");
			}
			//tcp
			if(ip->ip_p == 0x06){
				printf("tcp src port: %d\ntcp dst port: %d\n\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));
			}
			else{
				printf("No tcp packet!\n\n");
			}
			//payload
			n=0;
			if(payload[n]!='\0'){
				printf("payloads: \n");
				for(n=0;n<10;n++){
					printf("%02x\n",payload[n]);
				}
			}
			else{
				printf("No payload!\n\n");
  			}
		}	
	}

  	pcap_close(handle);
  	return 0; 

	}

