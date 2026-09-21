#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define MAX_RULES 10000
#define STRESS_PACKETS 50000000

#define TCP_MIN_HEADER_LEN 20
#define PROTO_TCP 6
#define PROTO_UDP 17
#define IP_MIN_HEADER_LEN 20
#define IP_VERSION_IPV4   4
#define MAKE_VER_IHL(ver,ihl) ((((ver) & 0x0F) << 4) | ((ihl) & 0x0F))
#define MAKE_IP(b1,b2,b3,b4) ((b1) | (b2 >> 8) | (b3 >> 16) | (b4 >> 24)) 
#define HASH_SIZE 16384
#define HASH_MASK (HASH_SIZE - 1)
#define CONN_HASH_SIZE 32768
#define CONN_HASH_MASK (CONN_HASH_SIZE - 1)
#define MAX_CONNECTIONS 50000

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
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  protocol;
	uint8_t  tcp_flags;
} packet_info_t;

enum IPv4_Offsets {
	IP_OFF_VER_IHL = 0,  // версия и длина заголовка (1 байт)
	IP_OFF_PROTOCOL = 9, // протокол (1 байт)
	IP_OFF_SRC_IP = 12,  // IP источника (4 байта)
	IP_OFF_DST_IP = 16   // IP приемника (4 байта)
};

enum TCP_Offsets {
	TCP_OFF_SRC_PORT = 0, // source port
	TCP_OFF_DST_PORT = 2, //destination port
	TCP_OFF_FLAGS    = 13 // TCP flags
};

typedef struct {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint8_t protocol;
} __attribute__((packed)) hash_key_t;

typedef struct hash_node {
	hash_key_t key;
	action_t action;
	struct hash_node *next;
} hash_node_t;

typedef enum {
	STATE_NONE,
	STATE_TCP_SYN_SENT,
	STATE_TCP_ESTABILISHED,
	STATE_TCP_CLOSED,
	STATE_TCP_ACTIVE,
	STATE_UDP_ACTIVE
} conn_state_t;

typedef struct {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
} __attribute__((packed)) conn_key_t;

typedef struct conn_node {
	conn_key_t key;
	conn_state_t state;
	uint64_t last_seen; //for seesion cleanup timeouts
	struct conn_node *next;
} conn_node_t;

conn_node_t *conntrack_table[CONN_HASH_SIZE] = {NULL};
conn_node_t conn_pool[MAX_CONNECTIONS];
int conn_pool_index = 0;

rule_t acl[MAX_RULES];
hash_node_t *hash_table[HASH_SIZE] = {NULL};
hash_node_t node_pool[MAX_RULES];
int pool_index = 0;

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

	uint16_t raw_src_port, raw_dst_port; 

	memcpy(&raw_src_port, &raw[ihl + TCP_OFF_SRC_PORT], 2);
	pkt->src_port = ((raw_src_port & 0xFF00) >> 8) | ((raw_src_port & 0x00FF) << 8);


	memcpy(&raw_dst_port, &raw[ihl + TCP_OFF_DST_PORT], 2);
	pkt->dst_port = ((raw_dst_port & 0xFF00) >> 8) | ((raw_dst_port & 0x00FF) << 8);

	pkt->tcp_flags = raw[ihl + TCP_OFF_FLAGS];

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


static inline uint32_t calculate_hash(const hash_key_t *key) {
	/*base on Knuth's Multiplicative Hash with Murmur hash finalyzer*/
	uint32_t h = key->src_ip ^ key->dst_ip ^ (key->dst_port << 16) ^ key->protocol;
	h = (h ^ (h >> 16)) * 0x45d9f3b;
	h = (h ^ (h >> 16)) * 0x45d9f3b;
	h = h ^ (h >> 16);
	return h & HASH_MASK;
}

void hash_add_rule(uint32_t src, uint32_t dst, uint16_t port, uint8_t proto, action_t action) {
	if(pool_index >= MAX_RULES) return;

	//take clean node from static pool
	hash_node_t *node = &node_pool[pool_index++];
	node->key.src_ip = src;
	node->key.dst_ip = dst;
	node->key.dst_port = port;
	node->key.protocol = proto;
	node->action = action;
	node->next = NULL;

	uint32_t slot = calculate_hash(&node->key);

	node->next = hash_table[slot];
	hash_table[slot] = node;
}

void generate_huge_acl_hash() {
	for (uint32_t i = 0; i< MAX_RULES -1 ; i++) {
		hash_add_rule(0x10000000 + i, 0x20000000 + i, (int16_t)(1000 + i), PROTO_TCP, ACTION_DROP);
	}
	hash_add_rule(0x0A000001, 0x0A000003, 443, PROTO_TCP, ACTION_DROP);
}

static inline uint32_t calculate_conn_hash(const conn_key_t *key) {
	uint32_t ip_mix = key->src_ip ^ key->dst_ip;
	uint32_t port_mix = key->src_port ^ key->dst_port;

	uint32_t h = ip_mix ^ (port_mix << 16) ^ key->protocol;

	h = (h ^ (h >> 16)) * 0x45d9f3b;
	h = (h ^ (h >> 16)) * 0x45d9f3b;
	h = h ^ (h >> 16);
	return h & CONN_HASH_MASK;
}

static inline bool match_connection(const conn_key_t *session, const conn_key_t *pkt) {
	if (session->protocol != pkt->protocol)
		return false;
	if (session->src_ip == pkt->src_ip && session->dst_ip == pkt->dst_ip &&
		session->src_port == pkt->src_port && session->dst_port == pkt->dst_port)
		return true;
	if (session->src_ip == pkt->dst_ip && session->dst_ip == pkt->src_ip &&
		session->src_port == pkt->dst_ip && session->dst_port == pkt->src_port )
		return true;
	return false;
}

__attribute__((noinline)) action_t evaluate_packet_fast(const packet_info_t *pkt) {
	hash_key_t key = {
		.src_ip = pkt->src_ip,
		.dst_ip = pkt->dst_ip,
		.dst_port = pkt->dst_port,
		.protocol = pkt->protocol
	};

	uint32_t slot = calculate_hash(&key);
	hash_node_t *current = hash_table[slot];

	while(current != NULL) {
		if (current->key.src_ip = key.src_ip &&
			current->key.dst_ip == key.dst_ip &&
			current->key.dst_port == key.dst_port &&
			current->key.protocol == key.protocol ) {
			return current->action;
		}
		current = current->next;
	}
	return ACTION_DROP;
}

__attribute((noinline)) action_t evaluate_stateful(const packet_info_t *pkt, rule_t *acl_rules, int acl_count) {
	conn_key_t key = {
		.src_ip = pkt->src_ip,
		.dst_ip = pkt->dst_ip,
		.src_port = pkt->src_port,
		.dst_port = pkt->dst_port,
		.protocol = pkt->protocol
	};

	uint32_t slot = calculate_conn_hash(&key);
	conn_node_t *current = conntrack_table[slot];

	while(current != NULL) {
		if(match_connection(&current->key, &key)) {
			if (current->state == STATE_TCP_SYN_SENT && (pkt->tcp_flags & 0x10)) {
				current->state = STATE_TCP_ESTABILISHED;
			}
			return ACTION_ACCEPT;
		}
		current = current->next;
	}

	packet_info_t acl_pkt = {
		.src_ip = pkt->src_ip, 
		.dst_ip = pkt->dst_ip,
		.src_port = pkt->src_port,
		.dst_port = pkt->dst_port, 
		.protocol = pkt->protocol
	};

	action_t acl_action = evaluate_packet_fast(&acl_pkt);
	if(acl_action == ACTION_ACCEPT){
		conn_state_t init_state = (pkt->protocol == PROTO_TCP) ? STATE_TCP_SYN_SENT : STATE_UDP_ACTIVE;
	}
}

bool conntrack_add_session(const conn_key_t *pkt_key, conn_state_t initial_state) {
	if (conn_pool_index >= MAX_CONNECTIONS)
		return false;
	
	conn_node_t *node = &conn_pool[conn_pool_index++];
	memcpy(&node->key, pkt_key, sizeof(conn_key_t));
	node->state = initial_state;
	node->last_seen = 0;
	node->next = NULL;

	uint32_t slot = calculate_conn_hash(pkt_key);
	node->next = conntrack_table[slot];
	conntrack_table[slot] = node;
	return true;
}

int main() {
	const uint8_t ihl = 20;

	printf("Starting stress test...\n");
	generate_huge_acl_hash();

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
			if (evaluate_stateful(&pkt, NULL, 0) == ACTION_DROP) {
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

