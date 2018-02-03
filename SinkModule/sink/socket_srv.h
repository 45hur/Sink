#pragma once
#ifndef SOCKET_SRV_H
#define SOCKET_SRV_H

#include <stdio.h>
#include <string.h>    //strlen
#include <stdlib.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <pthread.h> //for threading , link with lpthread

struct Header 
{
    uint64_t action:64;
    uint64_t msgsize:64;
    uint64_t msgcrc:64;
    uint64_t headercrc:64;
};

void *connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char client_message[4096];
    struct Header header;
    int bytesRead = 0;

    char *bufferPtr = (char *)&header;     
    //Receive a header from client
    while((read_size = recv(sock, client_message, 4096, 0)) > 0)
    {
        bytesRead += read_size;
        memcpy(bufferPtr, client_message, read_size);
        bufferPtr += read_size;
        if (read_size == -1 || read_size == 0 || bytesRead >= 32)
            break; 
    }

    //Send the header response back to client
    uint64_t crc = crc64(0, (const unsigned char *)&header, 24);
    sprintf(client_message, (header.headercrc == crc) ? "1" : "0");
    write(sock , client_message , 1);

    //Receive the message
    char *bufferMsg = (char *)malloc(header.msgsize);
    if (bufferMsg == NULL)
    {
      puts("not enough memory to create message buffer");
      return (void *)-1;
    }
    char *bufferMsgPtr = bufferMsg;
    bytesRead = 0;
    while( (read_size = recv(sock , client_message , 4096 , 0)) > 0 )
    {
        bytesRead += read_size;
        memcpy(bufferMsgPtr, client_message, read_size);
        bufferMsgPtr += read_size; 

        if (read_size == -1 || read_size == 0 || bytesRead >= header.msgsize)
            break; 
    }

    //Verify and acknowledge the message to the sender
    uint64_t msgcrc = crc64(0, (const unsigned char *)bufferMsg, header.msgsize);
    sprintf(client_message, (header.msgcrc == msgcrc) ? "1" : "0");
    write(sock , client_message , 1);

    //Free the socket pointer
    close(sock);
    free(socket_desc);

    if (header.msgcrc == msgcrc)
    {
        //Update the hash table
        if (header.action == 0)
        {
            //hashcontainer_reinit((int)header.msgsize / 8, bufferMsg, 0, bufferMsg);
            puts("reinit");
            loader_init();
        }
    }
    
    free (bufferMsg);

    return 0;
}

static void* socket_server(void *arg)
{
    int socket_desc , new_socket , c , *new_sock;
    struct sockaddr_in server , client;
    char *message;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );
     
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("bind failed");
        return (void*)-1;
    }
    puts("bind succeeded");
     
    //Listen
    listen(socket_desc , 3);
     
    //Accept and incoming connection
    puts("waiting for incoming connections");
    c = sizeof(struct sockaddr_in);
    while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        puts("connection accepted");
         
        pthread_t sniffer_thread;
        new_sock = malloc(1);
        *new_sock = new_socket;
         
        if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_sock) < 0)
        {
            perror("could not create thread");
            return (void*)-1;
        }
         
        pthread_join( sniffer_thread , NULL);
        puts("Handler assigned");
    }
     
    if (new_socket < 0)
    {
        perror("accept failed");
        return (void*)-1;
    }
    
    return 0;
}
 


#endif