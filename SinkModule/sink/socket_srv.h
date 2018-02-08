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

//cache_domain* swap_domain = NULL;
unsigned long long *swapdomain_crc;
unsigned long long swapdomain_crc_len;
short *swapdomain_accuracy;
unsigned long long swapdomain_accuracy_len;
unsigned long long *swapdomain_flags;
unsigned long long swapdomain_flags_len;

struct ip_addr **swapiprange_low;
unsigned long long swapiprange_low_len = 0;
struct ip_addr **swapiprange_high;
unsigned long long swapiprange_high_len = 0;
char **swapiprange_identity;
unsigned long long swapiprange_identity_len = 0;
int **swapiprange_policy_id;
unsigned long long swapiprange_policy_id_len = 0;
  
cache_policy* swap_policy = NULL;
cache_customlist* swap_customlist = NULL;

struct PrimeHeader 
{
    uint32_t action:32;
    uint32_t buffercount:32;
    uint64_t headercrc:64;
};

struct MessageHeader 
{
    uint64_t length:64;
    uint64_t msgcrc:64;
};

enum 
{
    bufferType_swapcache = 0,
    bufferType_domainCrcBuffer = 1,
    bufferType_domainAccuracyBuffer = 2,
    bufferType_domainFlagsBuffer = 3,
    bufferType_iprangeipfrom = 4,
    bufferType_iprangeipto = 5,
    bufferType_iprangeidentity = 6,
    bufferType_iprangepolicyid = 7, 
    bufferType_policyid = 8,
    bufferType_policystrategy = 9,
    bufferType_policyaudit = 10,
    bufferType_policyblock = 11,
    bufferType_identitybuffer = 12,
    bufferType_identitybufferwhitelist = 13,
    bufferType_identitybufferblacklist = 14,
    bufferType_freeswaps = 15,
} bufferType;

void *connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char client_message[4096];
    struct PrimeHeader primeHeader;
    struct MessageHeader messageHeader; 
    int bytesRead = 0;

    char *bufferPtr = (char *)&primeHeader;     
    //Receive a header from client
    while((read_size = recv(sock, client_message, sizeof(struct PrimeHeader), 0)) > 0)
    {
        bytesRead += read_size;
        memcpy(bufferPtr, client_message, read_size);
        bufferPtr += read_size;
        if (read_size == -1 || read_size == 0 || bytesRead >= sizeof(struct PrimeHeader))
            break; 
    }
    /*
    unsigned char* p = (unsigned char*)&primeHeader;
    printf("%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
         p[0],p[1],p[2],p[3], 
         p[4],p[5],p[6],p[7], 
         p[8],p[9],p[10],p[11], 
         p[12],p[13],p[14],p[15]);    */
    printf("necv1 %d \n", bytesRead);
    if (bytesRead == 0)
    {
       goto flush;
    }                    

    //Send the header response back to client
                                                                                      
    uint64_t crc = crc64(0, (const unsigned char *)&primeHeader, sizeof(struct PrimeHeader) - sizeof(uint64_t));
    sprintf(client_message, (primeHeader.headercrc == crc) ? "1" : "0");            
    if (primeHeader.headercrc == crc)
    {
      printf("crc1 succ\n");
      write(sock , client_message , 1);
    }
    else
    {
      printf("crc1 failed\n");
      write(sock , client_message , 1);

      goto flush;
    }

    printf("buffercount %d\n", primeHeader.buffercount);
    printf("action %d\n", primeHeader.action);

    //Receive the messages
    for (int i = 0; 0 < primeHeader.buffercount; i++)
    {
      printf(" cycle %d - %u\n", i, primeHeader.buffercount);
      bufferPtr = (char *)&messageHeader;  
      bytesRead = 0;   
      //Receive a header from client
      while((read_size = recv(sock, client_message, 16, 0)) > 0)
      {
          bytesRead += read_size;
          memcpy(bufferPtr, client_message, read_size);
          bufferPtr += read_size;
          if (read_size == -1 || read_size == 0 || bytesRead >= 16)
              break; 
      }
      printf(" recv2 %d \n", bytesRead);
      if (bytesRead == 0)
      {
         goto flush;
      } 
         
      //Calculate crc
      /*
      crc = crc64(0, (const unsigned char *)bufferPtr, sizeof(uint64_t));
      printf("crc %" PRIx64 "\n", crc);    
      printf("hdr %" PRIx64 "\n", messageHeader.msgcrc);
      sprintf(client_message, (messageHeader.msgcrc == crc) ? "1" : "0");
      if (messageHeader.msgcrc == crc)                                
      {                     
          printf("crc2 succ\n");
          write(sock , client_message , 1);
      }
      else
      {
          printf("crc2 failed\n");
          write(sock , client_message , 1);
          
          goto flush; 
      }
      printf("malloc %d - %llu - %d\n", i, messageHeader.length, bytesRead);
      if (messageHeader.length == 0)
      {
        continue;
      }
      */
      
      char *bufferMsg = (char *)malloc(messageHeader.length);
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
  
          if (read_size == -1 || read_size == 0 || bytesRead >= messageHeader.length)
              break; 
      }
      printf("  recv2 bytes read %d, expecting %lu\n", bytesRead, messageHeader.length);
  
      //Verify and acknowledge the message to the sender
      crc = crc64(0, (const unsigned char *)bufferMsg, messageHeader.length);
      printf("  crc %" PRIx64 "\n", crc);    
      printf("  hdr %" PRIx64 "\n", messageHeader.msgcrc);
      sprintf(client_message, (messageHeader.msgcrc == crc) ? "1" : "0");
      if (messageHeader.msgcrc == crc)
      {
          printf("   crc3 succ\n");
          write(sock , client_message , 1);
      }
      else
      {
          printf("   crc3 fail\n");
          write(sock , client_message , 1);
          goto flush;
      }
      
      printf("action: %d\n", primeHeader.action);
      switch (primeHeader.action)
      {
        case bufferType_domainCrcBuffer:
        {
          swapdomain_crc = (unsigned long long *)bufferMsg; 
          swapdomain_crc_len = messageHeader.length / sizeof(unsigned long long); 
          break;
        }
        case bufferType_domainAccuracyBuffer:
        {
          swapdomain_accuracy = (short *)bufferMsg;
          swapdomain_accuracy_len = messageHeader.length / sizeof(short);  
          break;
        }
        case bufferType_domainFlagsBuffer:
        {
          swapdomain_flags = (unsigned long long *)bufferMsg;
          swapdomain_flags_len = messageHeader.length / sizeof(unsigned long long);  
          break;               
        }
        case bufferType_iprangeipfrom:
        {
          if (swapiprange_low == NULL)
          {
            printf("malloc ip %d\n", primeHeader.buffercount);
            swapiprange_low = (struct ip_addr **)malloc(sizeof(struct ip_addr *) * primeHeader.buffercount);
          }
          printf("access %llu\n", swapiprange_low_len);
          swapiprange_low[swapiprange_low_len++] = (struct ip_addr *)bufferMsg;
          break;
        }
        case bufferType_iprangeipto:
        {
          if (swapiprange_high == NULL)
          {
            swapiprange_high = (struct ip_addr **)malloc(sizeof(struct ip_addr *) * primeHeader.buffercount);
          }
          swapiprange_high[swapiprange_high_len++] = (struct ip_addr *)bufferMsg; 
          break;
        }
        case bufferType_iprangeidentity:
        {
          if (swapiprange_identity == NULL)   
          {
            swapiprange_identity = (char **)malloc(sizeof(char *) * primeHeader.buffercount);
          }
          swapiprange_identity[swapiprange_identity_len++] = bufferMsg;
          break;
        }
        case bufferType_iprangepolicyid:
        {
          if (swapiprange_policy_id == NULL)   
          {
            swapiprange_policy_id = (int **)malloc(sizeof(int *) * primeHeader.buffercount);
          }
          swapiprange_policy_id[swapiprange_policy_id_len++] = (int *)bufferMsg;  
          break;
        }                
      }
    }
    
    if (primeHeader.action == bufferType_swapcache)
    {
        puts("reinit");
        if ((swapdomain_crc_len != swapdomain_accuracy_len) || (swapdomain_crc_len != swapdomain_flags_len))
        {
          printf("domain cache is corrupted");
          goto flush;          
        }
        printf(" domain init %llu items\n", swapdomain_crc_len);
        if ((swapiprange_identity_len != swapiprange_high_len) || (swapiprange_low_len != swapiprange_high_len) || (swapiprange_low_len != swapiprange_policy_id_len))
        {
          printf("iprange cache is corrupted\n identity=%llu\n high=%llu\n low=%llu\n policy=%llu",
            swapiprange_identity_len,
            swapiprange_high_len,
            swapiprange_low_len,
            swapiprange_policy_id_len);
          goto flush;          
        }
        printf(" iprange init %llu'items\n", swapiprange_low_len);
        
        
        puts("init domain");
        cache_domain *old_domain = cached_domain;
        cached_domain = cache_domain_init_ex(swapdomain_crc, swapdomain_accuracy, swapdomain_flags, swapdomain_crc_len);
        
        puts("init iprange");
        cache_iprange *old_iprange = cached_iprange;
        cached_iprange = cache_iprange_init_ex(swapiprange_low, swapiprange_high, swapiprange_identity, swapiprange_policy_id, swapiprange_high_len); 
        
        puts("init policy");
        swapdomain_crc = NULL;
        swapdomain_accuracy = NULL;
        swapdomain_flags = NULL;
        
        swapiprange_low = NULL;
        swapiprange_high = NULL; 
        swapiprange_identity = NULL; 
        swapiprange_policy_id = NULL;  
        swapiprange_low_len = 0;
        swapiprange_high_len = 0;
        swapiprange_identity_len = 0;
        swapiprange_policy_id_len = 0;
        
        puts("destroy domain");
        cache_domain_destroy(old_domain);
        puts("destroy policy");
        //cache_iprange_destroy(old_iprange);
                
    }
    if (primeHeader.action == bufferType_freeswaps)
    {
        printf("free\n");
        
        if (swapdomain_crc != NULL)
        {
          printf(" domain crc\n");
          free (swapdomain_crc);
          swapdomain_crc = NULL;
          swapdomain_crc_len = 0;
        }
        if (swapdomain_accuracy != NULL)
        {          
          printf(" domain accuracy\n");
          free (swapdomain_accuracy);
          swapdomain_accuracy = NULL;
          swapdomain_accuracy_len = 0;
        }
        if (swapdomain_flags != NULL)
        {
          printf(" domain flags\n");
          free (swapdomain_flags);
          swapdomain_flags = NULL;
          swapdomain_flags_len = 0;          
        }

        if (swapiprange_low != NULL)
        {
          printf(" iprange low\n");
          for (int i = 0; i < swapiprange_low_len; i++)
          {
            free (swapiprange_low[i]);
          }
          
          free (swapiprange_low);
          swapiprange_low = NULL;
          swapiprange_low_len = 0;
        }
        if (swapiprange_high != NULL)
        {
          printf(" iprange high\n");  
          for (int i = 0; i < swapiprange_high_len; i++)
          {
            free (swapiprange_high[i]);
          }
          
          free (swapiprange_high);
          swapiprange_high = NULL;
          swapiprange_high_len = 0;
        }
        if (swapiprange_identity != NULL)
        {
          printf(" iprange identity\n");
          for (int i = 0; i < swapiprange_identity_len; i++)
          {
            free (swapiprange_identity[i]);
          }
                                   
          free (swapiprange_identity);
          swapiprange_identity = NULL;
          swapiprange_identity_len = 0;
        } 
        if (swapiprange_policy_id != NULL)
        {
          printf(" iprange policy_id\n");
          free (swapiprange_policy_id);
                      
          swapiprange_policy_id = NULL;
          swapiprange_policy_id_len = 0;
        }
    }
    
flush:    
    
    //Free the socket pointer
    close(sock);
    free(socket_desc);

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
        puts("handler assigned");
    }
     
    if (new_socket < 0)
    {
        perror("accept failed");
        return (void*)-1;
    }
    
    return 0;
}
 


#endif