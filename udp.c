//Making an UDP sender????

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

//we need sendto() and recvfrom() functions to make an udp connection.

int main(){
				printf("UDP Mesage Sender\n");
				const char* mssg = "Hello World";
				int sock = socket(AF_INET, SOCK_DGRAM, 0); //for udp we use type as SOCK_DGRAM and protocol as 0

				if (sock < 0) {
								perror("socket");
								exit(EXIT_FAILURE);
				}

				printf("Socket %d\n", sock);


				struct sockaddr_in sin;
				sin.sin_family = AF_INET;
				sin.sin_port = htons(12345);
				sin.sin_addr.s_addr = inet_addr("127.0.0.1");

				//const struct sockaddr address = (const struct sockaddr) {};
				
				//Send message to listener
				sendto(sock, mssg, strlen(mssg), 0, (struct sockaddr *)&sin, sizeof(sin));

				close(sock);
				return 0;
				

}
