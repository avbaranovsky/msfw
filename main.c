#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#define MAX_RULES 10000
#define STRESS_PACKETS 50000000
#define IP_ANY   0x00000000
#define PORT_ANY 0x0000
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

// Ключ для поиска правила в хэш-таблице (5-Tuple)
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol; // 6 = TCP, 17 = UDP
} __attribute__((packed)) hash_key_t;

typedef struct hash_node {
	struct hash_node *next;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t src_mask;
	uint8_t dst_mask;
	uint8_t protocol;
	action_t action;
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

static inline uint32_t calculate_hash(const hash_key_t *key) {
	/*base on Knuth's Multiplicative Hash with Murmur hash finalyzer*/
	uint32_t h = key->src_ip ^ key->dst_ip ^ (key->dst_port << 16) ^ key->protocol;
	h = (h ^ (h >> 16)) * 0x45d9f3b;
	h = (h ^ (h >> 16)) * 0x45d9f3b;
	h = h ^ (h >> 16);
	return h & HASH_MASK;
}

static inline bool validate_ip_mask(uint32_t rule_ip, uint8_t rule_mask, uint32_t packet_ip) {
	if (rule_mask == 0) return true;
	uint32_t mask = (rule_mask == 32) ? 0xFFFFFFFF : ~(0xFFFFFFFF >> rule_mask);
	return (rule_ip & mask) == (packet_ip & mask);
}

void hash_add_rule(	uint32_t src_ip, uint8_t src_mask, uint16_t src_port,
					uint32_t dst_ip, uint8_t dst_mask, uint16_t dst_port,
					uint8_t proto, action_t action) {
	if(pool_index >= MAX_RULES) return;

	hash_node_t *node = &node_pool[pool_index++];
	node->src_ip = src_ip;
	node->dst_ip = dst_ip;
	node->src_port = src_port;
	node->dst_port = dst_port;
	node->src_mask = src_mask;
	node->dst_mask = dst_mask;
	node->protocol = proto;
	node->action = action;

	hash_key_t tmp_key = {.src_ip = src_ip, .dst_ip = dst_ip, .dst_port = dst_port, .protocol = proto};
	uint32_t slot = calculate_hash(&tmp_key);

	node->next = hash_table[slot];
	hash_table[slot] = node;
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
		if (current->protocol != 0 && current->protocol != pkt->protocol) {
			current = current->next;
			continue;
		}

		if (!validate_ip_mask(current->src_ip, current->src_mask, pkt->src_ip)) {
			current = current->next;
			continue;
		}

		if (!validate_ip_mask(current->dst_ip, current->dst_mask, pkt->dst_ip)) {
			current = current->next;
			continue;
		}

		if ((current->src_port == PORT_ANY || current->src_port == pkt->src_port) &&
			(current->dst_port == PORT_ANY || current->dst_port == pkt->dst_port)) {
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

static bool parse_address_port(const char *str, uint32_t *ip, uint8_t *mask, uint16_t *port) {
	char ip_part[64]={0};
	char port_part[16]={0};

	const char *colon = strchr(str, ':');
	if(!colon) return false;

	size_t ip_len = colon - str;
	if(ip_len >= sizeof(ip_part))
		return false;

	strncpy(ip_part, str, ip_len);

	if(strlen(colon + 1) >= sizeof (port_part))
		return false;
	strcpy(port_part, colon + 1);

	//1. Parse IP and mask
	if (strcmp(ip_part, "*") == 0) {
		*ip = IP_ANY;
		*mask = 0;
	} else {
		char *slash = strchr(ip_part, '/');
		unsigned int b1=0, b2=0, b3=0, b4=0, m=32;
		if(slash) {
			if(sscanf(ip_part, "%u.%u.%u.%u/%u", &b1, &b2, &b3, &b4, &m) != 5)
				return false;
		} else {
			if(sscanf(ip_part, "%u.%u.%u.%u", &b1, &b2, &b3, &b4) != 4)
				return false;
		}
		if(b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255 || m > 32)
			return false;
		*ip = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
		*mask = m;
	}
	//2. parse port
	if (strcmp(port_part, "*") == 0) {
		*port = PORT_ANY;
	} else {
		unsigned int p;
		if(sscanf(port_part, "%u", &p) != 1 || p >65535)
			return false;
		*port = p;
	}
}

bool load_acl(const char *filename) {
	FILE *f = fopen(filename, "rt");
	if(!f) {
		perror("Error opening acl file");
		return false;
	}
	char line[256];
	uint32_t loaded_count = 0;
	unsigned int line_number=0;

	while(fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\r\n")] = 0;
		line_number++;

		if (line[0] == '#' || strlen(line) == 0)
			continue;

		char src[64] = {0};
		char dst[64] = {0};
		char act[16] = {0};

		if(sscanf(line, "%[^- \t]%*[ \t]->%s %s", src, dst, act) != 3) {
			printf("error scaning rule at line %d [%s]\n", line_number, line);
			continue;
		}
			
		uint32_t src_ip = 0, dst_ip = 0;
		uint8_t src_mask = 0, dst_mask = 0;
		uint16_t src_port = 0, dst_port = 0;

		if (!parse_address_port(src, &src_ip, &src_mask, &src_port)) {
			printf("SRC parse error in line %d: %s\n", line_number, src);
			continue;
		}
		if (!parse_address_port(dst, &dst_ip, &dst_mask, &dst_port)) {
			printf("DST parse error in line %d: %s\n", line_number, dst);
			continue;
		}

		action_t action;
		if (strcasecmp(act, "allow") == 0)
			action = ACTION_ACCEPT;
		else if (strcasecmp(act, "deny") == 0)
			action = ACTION_DROP;
		else {
			printf("Unknown action %s in line %d\n", act, line_number);
			continue;
		}
		hash_add_rule(src_ip, src_mask, src_port, dst_ip, dst_mask, dst_port, PROTO_TCP, action);
		printf("Загружено правило #%u: (IP:%08X/%u:%u -> IP:%08X/%u:%u) [%s]\n", 
				loaded_count, 
				src_ip, src_mask, src_port, 
				dst_ip, dst_mask, dst_port, 
				act);
	}
}

int main() {
	const uint8_t ihl = 20;

	printf("Starting stress test...\n");
	load_acl("rules.txt");

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

