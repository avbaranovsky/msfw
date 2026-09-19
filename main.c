#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define MAX_RULES 10000
#define STRESS_PACKETS 50000000

typedef enum {
	ACTION_DROP,
	ACTION_ACCEPT
} action_t;

typedef struct {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint8_t  protocol;
	action_t action;
} rule_t;

typedef struct {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint8_t  protocol;
} packet_info_t;

rule_t acl[MAX_RULES];

#define IP_MIN_HEADER_LEN 20
#define IP_VERSION_IPV4   4
#define MAKE_VER_IHL(ver,ihl) ((((ver) & 0x0F) << 4) | ((ihl) & 0x0F))
#define MAKE_IP(b1,b2,b3,b4) ((b1) | (b2 >> 8) | (b3 >> 16) | (b4 >> 24)) 

enum IPv4_Offsets {
	IP_OFF_VER_IHL = 0,  // версия и длина заголовка (1 байт)
	IP_OFF_PROTOCOL = 9, // протокол (1 байт)
	IP_OFF_SRC_IP = 12,  // IP источника (4 байта)
	IP_OFF_DST_IP = 16   // IP приемника (4 байта)
};


#define TCP_MIN_HEADER_LEN 20

enum TCP_Offsets {
	TCP_OFF_DST_PORT = 2 //destination port
};


#define PROTO_TCP 6
#define PROTO_UDP 17

void generate_huge_acl() {
	for (int i=0; i< MAX_RULES -1; i++) {
		acl[i].src_ip = 0x10000000 + i;
		acl[i].dst_ip = 0x20000000 + i;
		acl[i].dst_port = i % 256;
		acl[i].protocol = PROTO_TCP;
		acl[i].action = ACTION_DROP;
	}
	acl[MAX_RULES - 1].src_ip = 0x0A000001;
	acl[MAX_RULES - 1].dst_ip = 0x0A000003;
	acl[MAX_RULES - 1].dst_port = 443;
	acl[MAX_RULES - 1].action = ACTION_DROP;
}

//функция парсинга
__attribute__((noinline)) bool parse_packet(const uint8_t *raw, size_t len, packet_info_t *pkt) {
	//validate min length
	if (len < IP_MIN_HEADER_LEN) {
		return false;
	}

	uint8_t version = (raw[IP_OFF_VER_IHL] & 0xF0) >> 4;
	if (version != IP_VERSION_IPV4) {
		return false;
	}

	uint8_t ihl = (raw[IP_OFF_VER_IHL] & 0x0F) * 4;

	if (ihl < IP_MIN_HEADER_LEN || len < ihl) {
		return false;
	}

	pkt->protocol = raw[IP_OFF_PROTOCOL];
	if (pkt->protocol != PROTO_TCP) {
		return false; //мы пока не поддерживаем протоколы, отличные от TCP
	}

	memcpy(&pkt->src_ip, &raw[IP_OFF_SRC_IP], sizeof(pkt->src_ip));
	memcpy(&pkt->dst_ip, &raw[IP_OFF_DST_IP], sizeof(pkt->dst_ip));

	if (len < (size_t)(ihl + TCP_MIN_HEADER_LEN)) {
		return false;
	}

	uint16_t raw_port; 
	size_t dst_port_offset = ihl + TCP_OFF_DST_PORT;

	memcpy(&raw_port, &raw[dst_port_offset], sizeof(raw_port));
	pkt->dst_port = ((raw_port & 0xFF00) >> 8) | ((raw_port & 0x00FF) << 8);

	return true;
}

__attribute__((noinline)) action_t evaluate_packet(const packet_info_t *pkt) {
	for (int i = 0; i < MAX_RULES; i++) {
		if (acl[i].protocol != 0 && acl[i].protocol != pkt->protocol) continue;
		if (acl[i].src_ip != 0 && acl[i].src_ip != pkt->src_ip) continue;
		if (acl[i].dst_ip != 0 && acl[i].dst_ip != pkt->dst_ip) continue;
		if (acl[i].dst_port !=0 && acl[i].dst_ip != pkt->dst_port) continue;
		return acl[i].action;
	}
	return ACTION_DROP;
}

int main() {
	const uint8_t ihl = 20;

	printf("Starting stress test...\n");
	generate_huge_acl();

	uint8_t dummy_raw_packet[40] = {0};
	dummy_raw_packet[IP_OFF_VER_IHL] = MAKE_VER_IHL(4, ihl / 4); //IPv4, IHL=5
	dummy_raw_packet[IP_OFF_PROTOCOL] = PROTO_TCP;
	*((uint32_t*)(dummy_raw_packet + IP_OFF_SRC_IP)) = MAKE_IP(10,0,0,1);
	*((uint32_t*)(dummy_raw_packet + IP_OFF_DST_IP)) = MAKE_IP(10,0,0,3);
	*((uint16_t*)(dummy_raw_packet + ihl + TCP_OFF_DST_PORT)) = 0x01BB;

	uint64_t drops = 0;
	uint64_t accepts = 0;

	for (uint64_t i=0; i < STRESS_PACKETS; i++) {
		packet_info_t pkt;

		dummy_raw_packet[15] = (uint8_t)(i % 256); 
		if (parse_packet(dummy_raw_packet, sizeof(dummy_raw_packet), &pkt)) {
			if (evaluate_packet(&pkt) == ACTION_DROP) {
				drops++;
			} else {
				accepts++;
			}
		}
	}
	
	printf("Test complete, Packets processed: %lu\n", (uint64_t)STRESS_PACKETS);
	printf("Allowed: %lu, dropped: %lu\n", accepts, drops);
	return 0;
}

