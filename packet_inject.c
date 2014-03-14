#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <features.h>
#include <net/if.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

#define MAX_SIZE 1024
#define TTL 255

typedef struct pseudo_header {
	unsigned long int src_ip;
	unsigned long int dst_ip;
	unsigned char resv;
	unsigned char proto;
	unsigned short int tcp_size;
} psdhdr;

//
int raw_socket_init(int sniff_proto) {
	int rsck;
	if ((rsck = socket(PF_PACKET, SOCK_RAW, htons(sniff_proto))) < 0)
		perror("socket() failure: ");
	return rsck;
}

int raw_socket_bind(char *device, int fd, int proto) {
	struct sockaddr_ll sll;
	struct ifreq ifr;
	memcpy(&sll, 0, sizeof(sll));
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl() failure: ");
		return -1;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(proto);

	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind() failure: ");
		return -1;
	}
	return 0;
}

int raw_socket_send(int fd, unsigned char *data, size_t data_size) {
	size_t nbyte = 0;
	if ((nbyte = write(fd, data, data_size)) != data_size)
		fprintf(stderr, "write() failure: sent %d bytes but the"
				"length should be %d\n", nbyte, data_size);
	return nbyte;
}

struct ethhdr *eth_header_init(char *src_mac, char *dst_mac, int proto) {
	struct ethhdr *header = malloc(sizeof(struct ethhdr));
	if (header == NULL) {
		perror("malloc() failure: ");
		return NULL;
	}

	memcpy(header->h_source, (void *)ether_aton(src_mac), ETH_ALEN);
	memcpy(header->h_dest, (void *)ether_aton(dst_mac), ETH_ALEN);
	header->h_proto = htons(proto);

	return header;
}

struct tcphdr *tcp_header_init(int seq, int win_size, uint16_t s, uint16_t d) {
	struct tcphdr *header = malloc(sizeof(struct tcphdr));
	if (header == NULL) {
		perror("malloc() failure: ");
		return NULL;
	}

	header->source = htons(s);
	header->dest = htons(d);
	header->seq = htonl(seq); // the `seq` is random at SYN
	header->ack_seq = 0;
	header->window = htons(win_size);
	header->urg_ptr = 0;
	header->res1 = 0;
	header->doff = sizeof(struct tcphdr)/IPVERSION;
	header->syn = 1;
	header->check = 0; // kernel's ip stack fills the correct checksum
	return header;	
}

struct iphdr *ip_header_init(int id, int ttl, const char *s, const char *d) {
	struct iphdr *header = malloc(sizeof(struct iphdr));
	if (header == NULL) {
		perror("malloc() failure: ");
		return NULL;
	}
	
	header->version = IPVERSION;
	header->ihl = sizeof(struct iphdr)/IPVERSION;
	header->tos = 0;
	header->tot_len = htons(sizeof(struct iphdr) + 
				sizeof(struct tcphdr) + MAX_SIZE);
	header->id = htons(id);
	header->frag_off = 0;
	header->ttl = ttl;
	header->protocol = IPPROTO_TCP;
	header->saddr = inet_addr(s);
	header->daddr = inet_addr(d);
	
	// TODO: checksum calculation
	header->check = 0;

	return header;	
}

psdhdr *pseudo_header_init(struct tcphdr *tcph, struct iphdr *iph,
		unsigned char *data) {
	int seg_size = ntohs(iph->tot_len) - iph->ihl * IPVERSION;
	int hdr_size = sizeof(psdhdr) + seg_size;
	unsigned char *raw_header = malloc(hdr_size);
	psdhdr *header = (psdhdr *)raw_header;

	if (header == NULL) {
		perror("malloc() failure: ");
		return NULL;
	}

	header->src_ip = iph->saddr;
	header->dst_ip = iph->daddr;
	header->resv = 0;
	header->proto = iph->protocol;
	header->tcp_size = htons(seg_size);
	memcpy(raw_header + sizeof(psdhdr), tcph, tcph->doff * IPVERSION);
	memcpy(raw_header + sizeof(psdhdr) + tcph->doff * IPVERSION, 
		data, MAX_SIZE);

	tcph->check = 0;
	return header;
}

int main(int argc, char *argv[]) {

	return 0;
}
