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


#include "cache_domains.h"

//Buffers to help to fetch data from socket
//Can be assinged outside to the cache_ structures
unsigned long long *swapdomain_crc;
unsigned long long swapdomain_crc_len = 0;
short *swapdomain_accuracy;
unsigned long long swapdomain_accuracy_len = 0;
unsigned long long *swapdomain_flags;
unsigned long long swapdomain_flags_len = 0;

struct ip_addr **swapiprange_low;
unsigned long long swapiprange_low_len = 0;
struct ip_addr **swapiprange_high;
unsigned long long swapiprange_high_len = 0;
char **swapiprange_identity;
unsigned long long swapiprange_identity_len = 0;
int *swapiprange_policy_id;
unsigned long long swapiprange_policy_id_len = 0;
                                               
int * swappolicy_policy_id;
unsigned long long swappolicy_policy_id_len = 0;
int * swappolicy_strategy;
unsigned long long swappolicy_strategy_len = 0;
int * swappolicy_audit;
unsigned long long swappolicy_audit_len = 0;
int * swappolicy_block;
unsigned long long swappolicy_block_len = 0;

char **swapcustomlist_identity;
unsigned long long swapcustomlist_identity_len = 0;
struct cache_domain **swapcustomlist_whitelist;
unsigned long long swapcustomlist_whitelist_len = 0;
struct cache_domain **swapcustomlist_blacklist;
unsigned long long swapcustomlist_blacklist_len = 0;
int * swapcustomlist_policyid;
unsigned long long swapcustomlist_policyid_len = 0;

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
    bufferType_identitybufferpolicyid = 15,
    bufferType_freeswaps = 16,
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
    //printf("necv1 %d \n", bytesRead);
    if (bytesRead == 0)
    {
       goto flush;
    }                    

    //Send the header response back to client
                                                                                      
    uint64_t crc = crc64(0, (const unsigned char *)&primeHeader, sizeof(struct PrimeHeader) - sizeof(uint64_t));
    sprintf(client_message, (primeHeader.headercrc == crc) ? "1" : "0");            
    if (primeHeader.headercrc == crc)
    {
      //printf("crc1 succ\n");
      write(sock , client_message , 1);
    }
    else
    {
      //printf("crc1 failed\n");
      write(sock , client_message , 1);

      goto flush;
    }

    //printf("buffercount %d\n", primeHeader.buffercount);
    //printf("action %d\n", primeHeader.action);

    //Receive the messages
    for (int i = 0; 0 < primeHeader.buffercount; i++)
    {
      //printf(" cycle %d - %u\n", i, primeHeader.buffercount);
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
      //printf(" recv2 %d \n", bytesRead);
      if (bytesRead == 0)
      {
         goto flush;
      } 
         
      char *bufferMsg = (char *)calloc(1, messageHeader.length + 1);
      if (messageHeader.length == 0)
      {
        logtosyslog("\"message\":\"empty message\"");
        sprintf(client_message, "1");
        write(sock , client_message , 1);
      }
      else
      {
        if (bufferMsg == NULL)
        {
          logtosyslog("\"message\":\"not enough memory to create message buffer\"");
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
        //printf("  recv2 bytes read %d, expecting %lu\n", bytesRead, messageHeader.length);
    
        //Verify and acknowledge the message to the sender
        crc = crc64(0, (const unsigned char *)bufferMsg, messageHeader.length);
        //printf("  crc %" PRIx64 "\n", crc);    
        //printf("  hdr %" PRIx64 "\n", messageHeader.msgcrc);
        sprintf(client_message, (messageHeader.msgcrc == crc) ? "1" : "0");
        if (messageHeader.msgcrc == crc)
        {
            //printf("   crc3 succ\n");
            write(sock , client_message , 1);
        }
        else
        {
            //printf("   crc3 fail\n");
            write(sock , client_message , 1);
            goto flush;
        }
      }
      
      //printf("action: %d\n", primeHeader.action);
      switch (primeHeader.action)
      {
        /// Domain
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
        
        /// IP Ranges
        case bufferType_iprangeipfrom:                   
        {
          if (swapiprange_low == NULL)
          {
            swapiprange_low = (struct ip_addr **)malloc(sizeof(struct ip_addr *) * primeHeader.buffercount);
          }
          //unsigned char* p = (unsigned char*)&primeHeader;
          //struct ip_addr *x = (struct ip_addr *)&bufferMsg;
          //printf("%08x\n", x->family);
          //printf("%08x\n", x->ipv4_sin_addr);
          //printf("%08x\n", x->ipv6_sin_addr);
          
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
          swapiprange_policy_id = (int *)bufferMsg;
          swapiprange_policy_id_len = messageHeader.length / sizeof(int);
          break;
        }        
        
        //Policies
        case bufferType_policyid:
        {
          swappolicy_policy_id = (int *)bufferMsg;
          swappolicy_policy_id_len = messageHeader.length / sizeof(int);  
          break;
        }
        case bufferType_policystrategy:
        {
          swappolicy_strategy = (int *)bufferMsg;
          swappolicy_strategy_len = messageHeader.length / sizeof(int);  
          break;
        }                        
        case bufferType_policyaudit:
        {
          swappolicy_audit = (int *)bufferMsg;
          swappolicy_audit_len = messageHeader.length / sizeof(int);  
          break;
        }                        
        case bufferType_policyblock:
        {
          swappolicy_block = (int *)bufferMsg;
          swappolicy_block_len = messageHeader.length / sizeof(int);  
          break;
        } 
        
        //Custom list
        case bufferType_identitybuffer:
        {
          if (swapcustomlist_identity == NULL)   
          {
            swapcustomlist_identity = (char **)malloc(sizeof(char *) * primeHeader.buffercount);
          }  
          
          swapcustomlist_identity[swapcustomlist_identity_len++] = (char *)bufferMsg;
          break;
        }                        
        case bufferType_identitybufferwhitelist:
        {
          if (swapcustomlist_whitelist == NULL)   
          {                                                                  
            swapcustomlist_whitelist = (struct cache_domain **)malloc(sizeof(struct cache_domain *) * primeHeader.buffercount);
          }
                     
          cache_domain *whitelist = cache_domain_init_ex2((unsigned long long *)bufferMsg, messageHeader.length / sizeof(unsigned long long));
          swapcustomlist_whitelist[swapcustomlist_whitelist_len++] = (struct cache_domain *)whitelist; 
          break;
        }                        
        case bufferType_identitybufferblacklist:          
        {
          if (swapcustomlist_blacklist == NULL)   
          {
            swapcustomlist_blacklist = (struct cache_domain **)malloc(sizeof(struct cache_domain *) * primeHeader.buffercount);
          }         
          
          cache_domain *blacklist = cache_domain_init_ex2((unsigned long long *)bufferMsg, messageHeader.length / sizeof(unsigned long long));
          swapcustomlist_blacklist[swapcustomlist_blacklist_len++] = (struct cache_domain *)blacklist;  
          break;
        }                                   
        case bufferType_identitybufferpolicyid:          
        {
          if (swapcustomlist_blacklist == NULL)   
          {
            swapcustomlist_blacklist = (struct cache_domain **)malloc(sizeof(struct cache_domain *) * primeHeader.buffercount);
          }         
          
          cache_domain *blacklist = cache_domain_init_ex2((unsigned long long *)bufferMsg, messageHeader.length / sizeof(unsigned long long));
          swapcustomlist_blacklist[swapcustomlist_blacklist_len++] = (struct cache_domain *)blacklist;  
          break;
        }                                   
      }
    }
    
    if (primeHeader.action == bufferType_swapcache)
    {
		char message[255] = {};
        if ((swapdomain_crc_len != swapdomain_accuracy_len) || (swapdomain_crc_len != swapdomain_flags_len))
        {
			sprintf(message, "\"message\":\"domain cache is corrupted %llu %llu %llu\"", swapdomain_crc_len, swapdomain_accuracy_len, swapdomain_flags_len);
			logtosyslog(message);
          goto flush;          
        }
		sprintf(message, "\"message\":\"domain init %llu items\"", swapdomain_crc_len);
		logtosyslog(message);
        if ((swapiprange_identity_len != swapiprange_high_len) || (swapiprange_low_len != swapiprange_high_len) || (swapiprange_low_len != swapiprange_policy_id_len))
        {
			sprintf(message, "\"message\":\"iprange cache is corrupted\n identity=%llu\n high=%llu\n low=%llu\n policy=%llu\"",
            swapiprange_identity_len,
            swapiprange_high_len,
            swapiprange_low_len,
            swapiprange_policy_id_len);
			logtosyslog(message);
			goto flush;
        }
		sprintf(message, "\"message\":\"iprange init %llu items\"", swapiprange_identity_len);
		logtosyslog(message);
        if ((swappolicy_policy_id_len != swappolicy_strategy_len) || (swappolicy_strategy_len != swappolicy_audit_len) || (swappolicy_audit_len != swappolicy_block_len))
        {
			sprintf(message, "\"message\":\"policy cache is corrupted\n policy_id=%llu\n strategy=%llu\n audit=%llu\n block=%llu\"",
            swappolicy_policy_id_len,
            swappolicy_strategy_len,
            swappolicy_audit_len,
            swappolicy_block_len);
			logtosyslog(message);
          goto flush;          
        }        
		sprintf(message, "\"message\":\"policy init %llu items\"", swappolicy_policy_id_len);
		logtosyslog(message);
        
        if ((swapcustomlist_identity_len != swapcustomlist_whitelist_len) || (swapcustomlist_whitelist_len != swapcustomlist_blacklist_len))
        {
			sprintf(message, "\"message\":\"ignoring error, customlist cache is corrupted\n identity=%llu\n whitelist=%llu\n blacklist=%llu\"",
            swapcustomlist_identity_len,
            swapcustomlist_whitelist_len,
            swapcustomlist_blacklist_len);
			logtosyslog(message);
          //goto flush;          
        }        
		logtosyslog("\"message\":\"customlist init %llu items\"", swapcustomlist_identity_len);
		logtosyslog(message);
        
        //puts("initex domain");
        cache_domain *old_domain = cached_domain;
        cached_domain = cache_domain_init_ex(swapdomain_crc, swapdomain_accuracy, swapdomain_flags, swapdomain_crc_len);
        
        //puts("initex iprange");                   
        cache_iprange *old_iprange = cached_iprange;
        cached_iprange = cache_iprange_init_ex(swapiprange_low, swapiprange_high, swapiprange_identity, swapiprange_policy_id, swapiprange_high_len); 
        
        //puts("initex policy");
        cache_policy *old_policy = cached_policy;
        cached_policy = cache_policy_init_ex(swappolicy_policy_id, swappolicy_strategy, swappolicy_audit, swappolicy_block, swappolicy_policy_id_len);
        
        //puts("initex custom");
        cache_customlist *old_customlist = cached_customlist;
        cached_customlist = cache_customlist_init_ex(swapcustomlist_identity,  swapcustomlist_whitelist, swapcustomlist_blacklist, swapcustomlist_policyid, swapcustomlist_identity_len);

        swapdomain_crc = NULL;
        swapdomain_accuracy = NULL;
        swapdomain_flags = NULL;
        swapdomain_crc_len = 0;
        swapdomain_accuracy_len = 0;
        swapdomain_flags_len = 0;

        swapiprange_low = NULL;
        swapiprange_high = NULL; 
        swapiprange_identity = NULL; 
        swapiprange_policy_id = NULL;  
        swapiprange_low_len = 0;
        swapiprange_high_len = 0;
        swapiprange_identity_len = 0;
        swapiprange_policy_id_len = 0;
                        
        swappolicy_policy_id = NULL;
        swappolicy_strategy = NULL;
        swappolicy_audit = NULL;
        swappolicy_block  = NULL;
        swappolicy_policy_id_len = 0;
        swappolicy_strategy_len = 0;
        swappolicy_audit_len = 0;
        swappolicy_block_len = 0;           

        swapcustomlist_identity = NULL;
        swapcustomlist_whitelist = NULL;
        swapcustomlist_blacklist = NULL;
        swapcustomlist_identity_len = 0;
        swapcustomlist_whitelist_len = 0;
        swapcustomlist_blacklist_len = 0;        
                
        //puts("destroy domain");
        cache_domain_destroy(old_domain);
        //puts("destroy_iprange");                
        cache_iprange_destroy(old_iprange);
        //puts("destroy policy");
        cache_policy_destroy(old_policy);
        //puts("destroy customlist");
        cache_customlist_destroy(old_customlist);        
    }
    if (primeHeader.action == bufferType_freeswaps)
    {
        //printf("free\n");

        // Domains        
        if (swapdomain_crc != NULL)
        {
          //printf(" domain crc\n");
          free (swapdomain_crc);
          swapdomain_crc = NULL;
          swapdomain_crc_len = 0;
        }
        if (swapdomain_accuracy != NULL)
        {          
          //printf(" domain accuracy\n");
          free (swapdomain_accuracy);
          swapdomain_accuracy = NULL;
          swapdomain_accuracy_len = 0;
        }
        if (swapdomain_flags != NULL)
        {
          //printf(" domain flags\n");
          free (swapdomain_flags);
          swapdomain_flags = NULL;
          swapdomain_flags_len = 0;          
        }

        // IP Ranges
        if (swapiprange_low != NULL)
        {
          //printf(" iprange low\n");
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
          //printf(" iprange high\n");  
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
          //printf(" iprange identity\n");
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
          //printf(" iprange policy_id\n");
          free (swapiprange_policy_id);
          swapiprange_policy_id = NULL;
          swapiprange_policy_id_len = 0;
        }
        
        // Policy
        if (swappolicy_policy_id != NULL)
        {
          //printf(" policy policy_id\n");
          free (swappolicy_policy_id);
          swappolicy_policy_id = NULL;
          swappolicy_policy_id_len = 0;
        }
        if (swappolicy_strategy != NULL)
        {
          //printf(" policy strategy\n");
          free (swappolicy_strategy);
          swappolicy_strategy = NULL;
          swappolicy_strategy_len = 0;
        }
        if (swappolicy_audit != NULL)
        {
          //printf(" policy audit\n");
          free (swappolicy_audit);
          swappolicy_audit = NULL;
          swappolicy_audit_len = 0;
        }
        if (swappolicy_block != NULL)
        {
          //printf(" policy blopraock\n");
          free (swappolicy_policy_id);
          swappolicy_block = NULL;
          swappolicy_block_len = 0;
        }
        
        // Customlist
        if (swapcustomlist_identity != NULL)
        {
          //printf(" customlist identity\n");
          free (swapcustomlist_identity);
          swapcustomlist_identity = NULL;
          swapcustomlist_identity_len = 0;
        }
        if (swapcustomlist_whitelist != NULL)
        {
          //printf(" customlist whitelist\n");
          free (swapcustomlist_whitelist);
          swapcustomlist_whitelist = NULL;
          swapcustomlist_whitelist_len = 0;
        }
		if (swapcustomlist_blacklist != NULL)
		{
			//printf(" customlist blacklist\n");
			free(swapcustomlist_blacklist);
			swapcustomlist_blacklist = NULL;
			swapcustomlist_blacklist_len = 0;
		}
		if (swapcustomlist_policyid != NULL)
		{
			//printf(" customlist blacklist\n");
			free(swapcustomlist_policyid);
			swapcustomlist_policyid = NULL;
			swapcustomlist_policyid_len = 0;
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
		logtosyslog("\"message\":\"Could not create socket\"");
    }
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    for (int port = 8880; port < 8896; port++)
    {
      server.sin_port = htons( port );                   
	  char message[255] = {};
      //Bind
      if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
      {
		  sprintf(message, "\"message\":\"bind failed on port %d\"", port);
		  logtosyslog(message);
          if (port == 8895)
          {
            return (void*)-1;
          }
          
          continue;
      }
	  sprintf(message,"\"message\":\"bind succeeded on port %d\"", port);
	  logtosyslog(message);
      break;
    }
     
    //Listen
    listen(socket_desc , 3);
     
    //Accept and incoming connection
	logtosyslog("\"message\":\"waiting for incoming connections\"");
    c = sizeof(struct sockaddr_in);
    while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        //puts("connection accepted");
         
        pthread_t sniffer_thread;
        new_sock = malloc(1);
        *new_sock = new_socket;
         
        if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_sock) < 0)
        {
			logtosyslog("\"message\":\"could not create thread\"");
            return (void*)-1;
        }
         
        pthread_join( sniffer_thread , NULL);
        //puts("handler assigned");
    }
     
    if (new_socket < 0)
    {
		logtosyslog("\"message\":\"accept failed\"");
        return (void*)-1;
    }
    
    return 0;
}
 


#endif