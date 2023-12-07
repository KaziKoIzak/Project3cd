/****************************************************
*
*    Basic minimal socket client program for use
*    in CSc 487 final projects.  You will have to
*    enhance this for your projects!!
*
*                                  RSF    11/14/20
*
****************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "FME.h"
#include "SDES.h"
#include<stdlib.h>
#include "Rand.h"
#include "RSA.h"
#include "Cert.h"

void deserializeCertificate(const char *buffer, Certificate *cert)
{
	memcpy(cert, buffer, sizeof(Certificate));
}

void intToBinaryArray(unsigned int num, int* binaryArray) {
    for(int i = 9; i >= 0; i--) {
        binaryArray[i] = num & 1;
        num >>= 1;
    }
}

void send_unsigned_int(int sockfd, uint32_t num) {
    // Convert to network byte order
    uint32_t num_n = htonl(num);

    // Send the data
    send(sockfd, &num_n, sizeof(uint32_t), 0);
}

uint32_t receive_unsigned_int(int sockfd) {
    uint32_t received_num;

    // Receive the data
    recv(sockfd, &received_num, sizeof(uint32_t), 0);

    // Convert back to host byte order
    return ntohl(received_num);
}


int main(int argc , char *argv[])
{
	unsigned int e, p, q, n;
	int d;
	int array[10];
	p = randomPrime();
	q = randomPrime();
	unsigned int exponentPrivate = randomPrime();
	printf("I am the CLIENT\n");
	printf("my p: %u (randomly generated)\n", p);
	printf("my q: %u (randomly generated)", q);

	e = basicallyRSA(p, q);
	d = DRSA(p, q, e);
	n = p * q;

	printf("\nmy e: %u\n", e);
	printf("my d: %u\n", d);

	int socket_desc;    // file descripter returned by socket command
	int read_size;
	struct sockaddr_in server;    // in arpa/inet.h
	char  server_reply[100], client_message[100];   // will need to be bigger
	char encrypted_message[100];
	
	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);

	printf("Trying to create socket\n");
	if (socket_desc == -1)
	{
		printf("Unable to create socket\n");
	}
		
// *********** This is the line you need to edit ****************
	server.sin_addr.s_addr = inet_addr("169.254.44.150");  // doesn't like localhost?
	server.sin_family = AF_INET;
	server.sin_port = htons( 8421 );    // random "high"  port number

	//Connect to remote server
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0) {
		printf(" connect error");
		return 1;
	}

	unsigned int base = receive_unsigned_int(socket_desc);
	unsigned int modulus = receive_unsigned_int(socket_desc);
	unsigned int serverPublicKey = receive_unsigned_int(socket_desc);
	unsigned int serverE = receive_unsigned_int(socket_desc);
	unsigned int serverN = receive_unsigned_int(socket_desc);

	unsigned int publicKey1 = FME(base, exponentPrivate, modulus);
	unsigned int publicKey = FME(publicKey1, d, n); 

	send_unsigned_int(socket_desc, publicKey);
	send_unsigned_int(socket_desc, e);
	send_unsigned_int(socket_desc, n);

	printf("Base: %u (received from server)\n", base);
	printf("Modulus: %u (received from server)\n", modulus);
	printf("Server's E %u\n", serverE);
	printf("Server's N %u\n", serverN);
	printf("My RSA Public Key: %u\n", publicKey);
	printf("My D-H Public Key: %u\n", publicKey1);
	printf("Server's RSA Public Key: %u\n", serverPublicKey);
	
	unsigned int authentication = FME(serverPublicKey, serverE, serverN);

	//printf("auth: %u\n", authentication);

	unsigned int sharedKey = FME(authentication, exponentPrivate, modulus);
	printf("Shared D-H Key: %u\n", sharedKey);

	intToBinaryArray(sharedKey, array);
	copyerArray(array);
	keys();


	//receive certificate from Server and write to file "certificate.txt"
	Certificate recievedCertificat;
	char buffend[sizeof(Certificate)];
	recv(socket_desc, buffend, sizeof(buffend), 0);
	deserializeCertificate(buffend, &recievedCertificat);
	//printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", recievedCertificat.version, recievedCertificat.serialNumber, recievedCertificat.signatureAlgorithm, recievedCertificat.issuer, recievedCertificat.validityNotBefore, recievedCertificat.validityNotAfter, recievedCertificat.subject, recievedCertificat.subjectPublicKeyInfo, recievedCertificat.trustLevel);
	writeCertificate("certificate.txt", &recievedCertificat);


	
	//receive CRL from Server and write to file "CRL.txt"
	FILE *file = fopen("CRL.txt", "w");
	char buffede[1024];
	ssize_t recievedChars;
	recievedChars = recv(socket_desc, buffede, sizeof(buffede), 0);
	//printf("received %zd chars: %s\n", recievedChars, buffede);
	fprintf(file, "%s", buffede);
	int CRLsize = sizeof(buffede);
	printf("CRL size: %d", CRLsize);

	fprintf(file, "%c", '\0');
	
	fclose(file);


	//certify certificate
	Certifier(&recievedCertificat, CRLsize);

	//Get data from keyboard and send  to server
	printf("What do you want to send to the server. (b for bye)\n");
	while(strncmp(client_message,"b",1))      // quit on "b" for "bye"
	{
		memset(client_message,'\0',100);
		memset(encrypted_message,'\0',100);

		fgets(client_message, sizeof(client_message), stdin);
		
		// Remove the newline character at the end (if present)
		client_message[strcspn(client_message, "\n")] = '\0';

		printf("\nPre-Encypted Message: %s", client_message);
		
		for(int i = 0; i < strlen(client_message); i++) {
			encrypted_message[i] = encryptPixels(client_message[i]);
		}

		if( send(socket_desc , &encrypted_message, strlen(encrypted_message) , 0) < 0)
		{
			printf("Send failed");
			return 1;
		}

		printf("\nSending Encrypted Message: %.*s\n", (int) strlen(encrypted_message),encrypted_message);
	
		//Receive a reply from the server
		if( (read_size = recv(socket_desc, server_reply , 100 , 0)) < 0)
		{
			printf("recv failed");
		}
		printf("Servers Decrypted Message Replies: %.*s\n\n", read_size,server_reply);
	}

	
	return 0;
}
