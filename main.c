#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <errno.h>
#include <linux/if_packet.h>

struct {
	u_char dst[6];
	u_char src[6];
	u_short hw_proto;
	u_short hw_type;
	u_short proto;
	u_char hw_size;
	u_char proto_size;
	u_short opcode;
	struct ether_addr my_mac;
	struct in_addr my_ip;
	struct ether_addr your_mac;
	struct in_addr your_ip;
	
}__attribute__((packed)) arp;

typedef struct ds_device{
	struct ds_device *next;
	char mac[6];
	struct in_addr ip;
	char orig_name[128];
	char mod_name[128];
	char *extra_info;
} ds_device;

int sock_arp;
ds_device * devices = NULL;

void init_socket()
{
	struct sockaddr addr;


#define WAN "wlp3s0"
#if 1

	sock_arp = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(sock_arp < 0) {
		perror("socket");
		exit(-1);
	}
	struct ifreq ifr;
	strncpy(ifr.ifr_name, WAN, sizeof WAN);
	if(ioctl(sock_arp, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(-1);
	}
	struct sockaddr_ll local_addr;
	memset(&local_addr, 0x00, sizeof(local_addr));
	local_addr.sll_family = PF_PACKET;
	local_addr.sll_ifindex = ifr.ifr_ifindex;
	//local_addr.sll_ifindex = IFF_BROADCAST;
	local_addr.sll_protocol = htons(ETH_P_ARP);
	if (bind(sock_arp, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
		perror("bind");
		exit(-1);
	}

#else

	/* AF_INET or AP_PACKET does no matter here */
	sock_arp = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
	if(sock_arp < 0) {
		perror("socket");
		exit(-1);
	}
	memset(&addr, 0x0, sizeof (addr));
	addr.sa_family = AF_INET;
	strncpy(addr.sa_data, WAN, sizeof(WAN) );

	if (bind(sock_arp, &addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(-1);
	}

#endif
}

void loop_check()
{
	int times = 0;

	memset(&arp, 0x0, sizeof arp);

	fd_set reads;
	FD_ZERO( &reads);
	FD_SET(sock_arp, &reads);

	while(select(sock_arp + 1, &reads, NULL, NULL, NULL) >= 0 || errno == EINTR) {

		if(FD_ISSET(sock_arp, &reads)) {
			if (recv(sock_arp, &arp, sizeof (arp), 0) < 0){
				perror("recv");
				exit(-1);
			}
			printf("ARP  %s from %s - %s", ntohs(arp.opcode) == 1 ? "request" : "reply", ether_ntoa(&arp.my_mac), inet_ntoa(arp.my_ip));
			printf(" to %s\n",  inet_ntoa(arp.your_ip));

		}

	}

	exit(0);

}

int main(int argc, char *argv[])
{
	char c;
	struct in_addr dip;
	struct ether_addr dmac;
	char dhost[128];
	char *optstr="m:i:h:";
	while ((c = getopt(argc, argv, optstr)) != -1) {

		switch(c) {

			case 'i':
				if(inet_aton(optarg, &dip))
					printf("Use IP %s to scan.\n", optarg);
				else {
					printf("Fatal: %s is not a valid IP address.\n", optarg);
					exit(-1);
				}
				break;

			case 'm':
				if(ether_aton_r(optarg, &dmac))
					printf("Use MAC %s to scan.\n", optarg);
				else {
					printf("Fatal: %s is not a valid MAC address.\n", optarg);
					exit(-1);
				}
				break;

			case 'h':
				strncpy(dhost, optarg, sizeof(dhost));
				printf("Use host %s to scan.\n", optarg);
				break;
		}
	}

	init_socket();
	loop_check();

	return 0;
}
