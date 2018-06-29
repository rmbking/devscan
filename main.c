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
#include <signal.h>
#include <time.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

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
	struct ether_addr mac;
	struct in_addr ip;
	char ori_name[128];
	char mod_name[128];
	int live;
	long update;
	char *extra_info;
} ds_device;

int sock_arp;

ds_device * devices[256] = {0};

struct ether_addr DUTmac;
struct in_addr DUTip;

int hash_map(void *addr)
{

#define RANDOM 0x12345678
	char *ori = (char *) addr;

	unsigned int ret = 0;
	ret += ori[0] & RANDOM;
	ret <<= 8;
	ret += ori[1] & RANDOM;
	ret <<= 8;
	ret += ori[2] & RANDOM;
	ret <<= 8;
	ret += ori[3] & RANDOM;

	ori = (char *) &ret;
	ret = ori[0] + ori[1] + ori[2] + ori[3];

	return ret % 256;

}

void insert_new_device(int key, ds_device * new)
{
	ds_device *dp;
	dp = devices[key];
	while (dp) {
		if (memcmp(&dp->mac, &new->mac, sizeof(struct ether_addr)) == 0) {
			memcpy(&dp->ip, &new->ip, sizeof(struct in_addr));
			memcpy(&dp->update, &new->update, sizeof(long));
			dp->live = 1;
			free(new);
			return;
		}
		dp = dp->next;
	}
	new->next = devices[key];
	devices[key] = new;
	printf("successfully inserted one iterm!\n");
}

void arp_check()
{
	int hval;
	long now = 0;

	if( time(&now) < 0 ) {
		perror("time");
	}

	ds_device* device = (ds_device *) malloc(sizeof(ds_device));
	memset(device, 0x0, sizeof(*device));

	memcpy(&device->mac, &arp.my_mac, sizeof(struct ether_addr));
	memcpy(&device->ip, &arp.my_ip, sizeof(struct in_addr));
	memcpy(&device->update, &now, sizeof(int));
	device->live = 1;

	hval = hash_map(&device->mac);
	insert_new_device(hval, device);

}

void init_socket()
{
	struct sockaddr addr;

#define WAN "wlp3s0"
#if 1
	struct ifreq ifr;
	struct sockaddr_ll local_addr;

	sock_arp = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(sock_arp < 0) {
		perror("socket");
		exit(-1);
	}
	strncpy(ifr.ifr_name, WAN, sizeof WAN);
	/* read the MAC and IP for sending ARP requiest later */
	if(ioctl(sock_arp, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl");
		exit(-1);
	}
	memcpy(&DUTmac, ifr.ifr_hwaddr.sa_data, sizeof(struct ether_addr));

	if(ioctl(sock_arp, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl");
		exit(-1);
	}
	memcpy(&DUTip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(struct in_addr));

	if(ioctl(sock_arp, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(-1);
	}
	memset(&local_addr, 0x00, sizeof(local_addr));
	local_addr.sll_family = PF_PACKET;
	local_addr.sll_ifindex = ifr.ifr_ifindex;
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
			printf("ARP  %s from %s - %s", ntohs(arp.opcode) == ARP_REQUEST ? "request" : "reply", ether_ntoa(&arp.my_mac), inet_ntoa(arp.my_ip));
			printf(" to %s\n",  inet_ntoa(arp.your_ip));

			arp_check();

		}

	}

	exit(0);

}

void print_devices(int signal)
{

	int i = 0;
	int count = 0;

	ds_device *dp = NULL;
	printf("================== devices ================ \n");
	printf("%-16s\t%-18s\t%-16s\t%s\n", "Device", "MAC", "IP", "Update time");
	for(i = 0; i < 256; i ++) {

		char name[16];
		char mac[18];
		char ip[16];
		char utime[64];

		dp = devices[i];
		while(dp) {

			count++;
			if(dp->mod_name[0] != '\0')
				strncpy(name, dp->mod_name, sizeof(name));
			else if(dp->ori_name[0] != '\0')
				strncpy(name, dp->ori_name, sizeof(name));
			else
				sprintf(name, "device%d", count);

			ether_ntoa_r(&dp->mac, mac);
			strncpy(ip, inet_ntoa(dp->ip), sizeof ip);
			strncpy(utime, ctime(&dp->update), sizeof utime);

			printf("%-16s\t%-18s\t%-16s\t%s\n", name, mac, ip, utime);
			dp = dp->next;
		}

	}
}

void send_arp(ds_device *dp)
{
	memcpy(arp.dst, &dp->mac, 6);
	memcpy(arp.src, &DUTmac, 6);
	arp.hw_proto = htons(0x806);
	arp.hw_type = htons(0x01);
	arp.proto = htons(0x0800);
	arp.hw_size = 6;
	arp.proto_size = 4;
	arp.opcode = htons(ARP_REQUEST);
	memcpy(&arp.my_mac, &DUTmac, 6);
	memcpy(&arp.my_ip, &DUTip, 6);
	memset(&arp.your_mac, 0x00, 6);
	memcpy(&arp.your_ip, &dp->ip, 6);

	send(sock_arp, &arp, sizeof arp, 0);

}
#define PID_FILE	"/var/run/devscan.pid"
void safe_quit(int signal)
{
	unlink(PID_FILE);
	exit(0);
}

void renew(int signal)
{
	int i;
	ds_device *dp;
	for (i = 0; i < 256; i++) {
		dp = devices[i];
		while (dp) {
			send_arp(dp);
			dp = dp->next;
		}
	}
}

int main(int argc, char *argv[])
{
	char c;
	struct in_addr dip;
	struct ether_addr dmac;
	char dhost[128]; char *optstr="m:i:h:l";
	int duplicate = 0;
	int master;

	if ( access(PID_FILE, F_OK) == 0) {

		duplicate = 1;

		FILE *fp = fopen(PID_FILE, "r");
		if(!fp){
			perror("fopen");
			exit(-1);
		}

		fscanf(fp, "%d", &master);
		fclose(fp);
	}
	else {

		daemon(1, 1);

		FILE *fp = fopen(PID_FILE, "w");
		if(!fp){
			perror("fopen");
			exit(-1);
		}

		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	if(!duplicate) {
		signal(SIGUSR1, print_devices);
		signal(SIGUSR2, renew);
		signal(SIGTERM, safe_quit);
	}


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
			case 'l':
				if(duplicate)
					kill(master, SIGUSR1);
				exit(0);
			default:
				printf("optstring=\"m:i:h:l\"!\n");
				break;
		}
	}

	init_socket();
	loop_check();

	return 0;
}
