#pragma once
#ifndef IP_RANGE_H
#define IP_RANGE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> //inet_addr

int is_ip_in_range(const struct sockaddr *ip,  const struct sockaddr *from, const struct sockaddr *to)
{
	int result = 0;
  if (ip->sa_family != from->sa_family || ip->sa_family != to->sa_family)
    return result;
    
	switch (ip->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr_ip = (struct sockaddr_in *)ip;
		struct sockaddr_in *addr_fr = (struct sockaddr_in *)from;
		struct sockaddr_in *addr_to = (struct sockaddr_in *)to;
  
		result = (addr_ip->sin_addr.s_addr >= addr_fr->sin_addr.s_addr) && (addr_ip->sin_addr.s_addr <= addr_to->sin_addr.s_addr);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *addr6_ip = (struct sockaddr_in6 *)ip;
		struct sockaddr_in6 *addr6_fr = (struct sockaddr_in6 *)from;
		struct sockaddr_in6 *addr6_to = (struct sockaddr_in6 *)to;
        
		result = memcmp(addr6_ip->sin6_addr.s6_addr, addr6_fr->sin6_addr.s6_addr, 16) >= 0 && memcmp(addr6_ip->sin6_addr.s6_addr, addr6_to->sin6_addr.s6_addr, 16) <= 0;
  		break;
	}
	default: 
  		break;
	}
  
	return result;
}

#endif