#pragma once
#ifndef IP_RANGE_H
#define IP_RANGE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> //inet_addr

struct ip_addr 
{
   uint8_t family; // socket family type
   unsigned int ipv4_sin_addr;
   unsigned __int128 ipv6_sin_addr;
};

int is_ip_in_range(const struct ip_addr *ip, const struct ip_addr *from, const struct ip_addr *to)
{
	int result = 0;
  if (ip->family != from->family || ip->family != to->family)
    return result;
    
	switch (ip->family) {
	case AF_INET: {
		unsigned int addr_ip = ip->ipv4_sin_addr;
		unsigned int addr_fr = from->ipv4_sin_addr;
		unsigned int addr_to = to->ipv4_sin_addr;
    
    printf("%x => %x <= %x", addr_fr, addr_ip, addr_to);
    
		result = (addr_ip >= addr_fr) && (addr_ip <= addr_to);
    if (result)
      printf(" matched\n");
    else
      printf(" not matched\n");
		break;
	}
	case AF_INET6: {
		 unsigned __int128 addr6_ip = ip->ipv6_sin_addr;
		 unsigned __int128 addr6_fr = ip->ipv6_sin_addr;
		 unsigned __int128 addr6_to = ip->ipv6_sin_addr;
        
		result = memcmp(&addr6_ip, &addr6_fr, 16) >= 0 && memcmp(&addr6_ip, &addr6_to, 16) <= 0;
  		break;
	}
	default:
  { 
      printf("kekek");
  		break;
  }
	}
  
	return result;
}

#endif