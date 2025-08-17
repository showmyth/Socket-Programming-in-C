//Making a UDP sender????

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

//we need sendto() and recvfrom() functions to make an udp connection.

int main(){
				printf("UDP Mesage Sender\n");
				const char* mssg = "Hello";
				//Send message to listener
				sendto(int socketID, mssg, sizeof(char*)*5, 0, ) {
				}

}
