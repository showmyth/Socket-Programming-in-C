//Working on the mobile client today

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main() {
				printf("UDP Message Receiver\n");
				int sock = socket(AF_INET, SOCK_DGRAM, 0);
				if (sock < 0) {
								perror("socket");
								exit(EXIT_FAILURE);
				}

				printf("Socket %d\n", sock);

				struct sockaddr_in sin;
				sin.sin_family = AF_INET;
				sin.sin_port = htons(12345);    
				sin.sin_addr.s_addr = INADDR_ANY;

				if (bind(sock, (struct sockaddr*)&sin, sizeof(sin)) < 0){
								printf("bind failed");
								close(sock);
								exit(EXIT_FAILURE);

				}
				while(1) {
								char buf[1024];
								int n = recvfrom(sock, buf, sizeof(buf)-1, 0, NULL, NULL);
								if (n < 0) {
												printf("binding faliure");
												continue;
								}
								buf[n] = '\0';
								printf("Packet: %s\n", buf);	

				}

				return 0;
}
 
