#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdbool.h>



int main(int argc, char *argv[]) {
	uint16_t src_port;
	uint16_t dst_port;

	struct ifaddrs *ifaddr_list = NULL;
	struct ifaddrs *ifa = NULL;
	int black_ip_count = 1, total_rules_count = 0;

	if(argc > 1)
		black_ip_count = atoi(argv[1]);
	else {
		printf("usage: %s <black ip count>\n", argv[0]);
		return 1;
	}
	FILE *f = fopen("rules.txt", "w");
	if(!f) {
		perror("Cannot create file rules.txt\n");
		return 1;
	}

	if(getifaddrs(&ifaddr_list) == -1) {
		perror("cannot get list of IP addresses\n");
		return 1;
	}

	fprintf(f, "# ==================================================\n");
	fprintf(f, "# Автоматически сгенерированная база правил файрвола\n");
	fprintf(f, "# ==================================================\n\n");
	fprintf(f, "# -- Section 1 - black IP list\n\n");

	time_t t = time(NULL);

	for (int i=0; i < black_ip_count; i++) {
		bool is_local;
		uint32_t b = t + i;
		uint8_t b1 = (uint8_t)((b / (254 * 254 * 254)) % 254 + 1);
		uint8_t b2 = (uint8_t)((b / (254 * 254))       % 254 + 1);
		uint8_t b3 = (uint8_t)((b / (254))             % 254 + 1);
		uint8_t b4 = (uint8_t)((b)                     % 254 + 1);
		uint32_t my_generated_ip = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;

		//now check that generated ip is not equal to any of local host addresses
		is_local = false;
		for (ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL) continue;
			if (ifa->ifa_addr->sa_family != AF_INET) continue;
			struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
			uint32_t local_ip = ntohl(sa->sin_addr.s_addr);
			if (local_ip == my_generated_ip) {
				is_local = true;
				break;
			}
		}
		if (is_local) continue;

		//now generate rules to deny access from generated fake ip to our local ip addresses
		src_port = (uint16_t)(1024 + (b % 60000));
		dst_port = (uint16_t)(80 + (i % 1000));
		for (ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL) continue;
			if (ifa->ifa_addr->sa_family != AF_INET) continue;
			struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
			uint32_t local_ip = ntohl(sa->sin_addr.s_addr);

			fprintf(f, "%d.%d.%d.%d/32:%u -> %d.%d.%d.%d/32:%u\n",
				b1,b2,b3,b4,src_port,
				((local_ip >> 24) & 0xFF),
				((local_ip >> 16) & 0xFF),
				((local_ip >> 8)  & 0xFF),
				(local_ip & 0xFF),
				dst_port);
			total_rules_count++;
		}
	}
	fprintf(f, "\n\n# -- Section 2 - white IP list\n\n");
	for (ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next) {
		struct ifaddrs *ifa_int = NULL;
		if (ifa->ifa_addr == NULL) continue;
		if (ifa->ifa_addr->sa_family != AF_INET) continue;
		struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
		uint32_t src_ip = ntohl(sa->sin_addr.s_addr);
		for (ifa_int = ifaddr_list; ifa_int != NULL; ifa_int = ifa_int->ifa_next) {
			if (ifa_int->ifa_addr == NULL) continue;
			if (ifa_int->ifa_addr->sa_family != AF_INET) continue;
			struct sockaddr_in *sa = (struct sockaddr_in *)ifa_int->ifa_addr;
			uint32_t dst_ip = ntohl(sa->sin_addr.s_addr);

			fprintf(f, "%d.%d.%d.%d/32:%u -> %d.%d.%d.%d/32:%u\n",
				((src_ip >> 24) & 0xFF),
				((src_ip >> 16) & 0xFF),
				((src_ip >> 8)  & 0xFF),
				(src_ip & 0xFF),
				666,
				((dst_ip >> 24) & 0xFF),
				((dst_ip >> 16) & 0xFF),
				((dst_ip >> 8)  & 0xFF),
				(dst_ip & 0xFF),
				777);
			total_rules_count++;
		}
	}
	freeifaddrs(ifaddr_list);
	fclose(f);
	return 0;
}