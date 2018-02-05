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

unsigned int reverse_nibbles(unsigned int x)
{
  unsigned int out = 0, i;
  for(i = 0; i < 4; ++i)
  {
    const unsigned int byte = (x >> 8 * i) & 0xff;
    out |= byte << (24 - 8 * i);
  }
  return out;
}

int is_ip_in_range(const struct ip_addr *ip, const struct ip_addr *from, const struct ip_addr *to)
{
	int result = 0;
  if (ip->family != from->family || ip->family != to->family)
    return result;
    
	switch (ip->family) {
	case AF_INET: {

    printf("ip nibble %x => ", ip->ipv4_sin_addr);
    struct ip_addr ip_nibbled = {};
    ip_nibbled.ipv4_sin_addr = reverse_nibbles(ip->ipv4_sin_addr);        
    printf("%x\n", ip_nibbled.ipv4_sin_addr);  
  
		unsigned int addr_ip = ip_nibbled.ipv4_sin_addr;
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