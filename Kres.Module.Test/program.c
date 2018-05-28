#include "program.h"

#include "cache_loader.h"
#include "socket_srv.h"

int sockets()
{
	struct ip_addr ip4addr;
	ip4addr.family = AF_INET;
	//inet_pton(AF_INET, "127.0.0.1", &ip4addr.ipv4_sin_addr);
	//ip4saddr = (struct ip_addr *)&ip4addr;

	struct ip_addr ip4from;
	ip4from.family = AF_INET;
	//inet_pton(AF_INET, "127.0.0.0", &ip4from.ipv4_sin_addr);
	//ip4sfrom = (struct ip_addr *)&ip4from;

	struct ip_addr ip4to;
	ip4to.family = AF_INET;
	//inet_pton(AF_INET, "127.0.0.255", &ip4to.ipv4_sin_addr);
	//ip4sto = (struct ip_addr *)&ip4to;

	struct ip_addr ip6addr;
	ip6addr.family = AF_INET6;
	inet_pton(AF_INET6, "2001:0db8:85a3:1234:5678:8a2e:0370:7335", &ip6addr.ipv6_sin_addr);
	//ip6saddr = (struct ip_addr *)&ip6addr;

	struct ip_addr ip6from;
	ip6from.family = AF_INET6;
	inet_pton(AF_INET6, "2001:0db8:85a3:1234:5678:8a2e:0370:7334", &ip6from.ipv6_sin_addr);
	//ip6sfrom = (struct ip_addr *)&ip6from;

	struct ip_addr ip6to;
	ip6to.family = AF_INET6;
	inet_pton(AF_INET6, "2001:0db8:85a3:1234:5678:8a2e:0370:7336", &ip6to.ipv6_sin_addr);
	//ip6sto = (struct ip_addr *)&ip6to;  

	is_ip_in_range(&ip4addr, &ip4from, &ip4to);
	is_ip_in_range(&ip6addr, &ip6from, &ip6to);
}

int cache_ranges()
{                         /*
  cache_iprange* cache = cache_iprange_init(2);

	struct sockaddr* ip6sfrom;
	struct sockaddr_in6 ip6from;
	ip6from.sin6_family = AF_INET6;
	ip6from.sin6_port = htons(0);
	inet_pton(AF_INET6, "2001:0db8:85a3:1234:5678:8a2e:0370:7334", &ip6from.sin6_addr);
	ip6sfrom = (struct sockaddr *)&ip6from;

	struct sockaddr* ip6sto;
	struct sockaddr_in6 ip6to;
	ip6to.sin6_family = AF_INET6;
	ip6to.sin6_port = htons(0);
	inet_pton(AF_INET6, "2001:0db8:85a3:1234:5678:8a2e:0370:7336", &ip6to.sin6_addr);
	ip6sto = (struct sockaddr *)&ip6to;

	struct sockaddr* ip4sfrom;
	struct sockaddr_in ip4from;
	ip4from.sin_family = AF_INET;
	ip4from.sin_port = htons(0);
	inet_pton(AF_INET, "10.0.0.1", &ip4from.sin_addr);
	ip4sfrom = (struct sockaddr *)&ip4from;

	struct sockaddr* ip4sto;
	struct sockaddr_in ip4to;
	ip4to.sin_family = AF_INET;
	ip4to.sin_port = htons(0);
	inet_pton(AF_INET, "10.0.1.100", &ip4to.sin_addr);
	ip4sto = (struct sockaddr *)&ip4to;

  cache_iprange_add(cache, ip6sfrom, ip6sto, "itity", 2);
  cache_iprange_add(cache, ip6sfrom, ip6sto, "itity", 3);
  cache_iprange_add(cache, ip4sfrom, ip4sto, "ident", 1);
  cache_iprange_add(cache, ip6sfrom, ip6sto, "itity", 5);


	struct sockaddr* ip4saddr;
	struct sockaddr_in ip4addr;
	ip4addr.sin_family = AF_INET;
	ip4addr.sin_port = htons(3490);
	inet_pton(AF_INET, "10.0.0.50", &ip4addr.sin_addr);
	ip4saddr = (struct sockaddr *)&ip4addr;

  iprange item = {};
  if (cache_iprange_contains(cache, ip4saddr, &item) == 1)
  {
	puts(item.identity);
  }

  cache_iprange_destroy(cache);    */
}

int cache_policies()
{
	cache_ranges();

	cache_policy* cache = cache_policy_init(4);
	cache_policy_add(cache, 1, 1, 50, 70);
	cache_policy_add(cache, 2, 2, 52, 72);
	cache_policy_add(cache, 3, 4, 53, 73);
	cache_policy_add(cache, 4, 3, 54, 74);
	policy item = {};
	if (cache_policy_contains(cache, 3, &item) == 1)
	{
		printf("%d", item.audit);
	}

	cache_policy_destroy(cache);
}

int customlists()
{
	char *value1 = "google.com";
	unsigned long long crc1 = crc64(0, (const unsigned char*)value1, strlen(value1));
	char *value2 = "facebook.com";
	unsigned long long crc2 = crc64(0, (const unsigned char*)value2, strlen(value2));

	char *value3 = "yahoo.com";
	unsigned long long crc3 = crc64(0, (const unsigned char*)value3, strlen(value3));
	char *value4 = "baidu.com";
	unsigned long long crc4 = crc64(0, (const unsigned char*)value4, strlen(value4));

	cache_domain *whitelist = cache_domain_init(2);
	cache_domain_add(whitelist, crc1, 0, 0);
	cache_domain_add(whitelist, crc2, 0, 0);
	cache_domain_sort(whitelist);

	cache_domain *blacklist = cache_domain_init(2);
	cache_domain_add(blacklist, crc3, 0, 0);
	cache_domain_add(blacklist, crc4, 0, 0);
	cache_domain_sort(blacklist);
	/*
	cache_customlist *customlist = cache_customlist_init(1);
	cache_customlist_add(customlist, "ident", whitelist, blacklist);

	if (cache_customlist_whitelist_contains(customlist, "ident", crc1) == 1) { puts("OK\n"); } else { puts("1\n"); }
	if (cache_customlist_whitelist_contains(customlist, "ident", crc2) == 1) { puts("OK\n"); } else { puts("2\n"); }
	if (cache_customlist_whitelist_contains(customlist, "ident", crc3) != 1) { puts("OK\n"); } else { puts("3\n"); }
	if (cache_customlist_blacklist_contains(customlist, "ident", crc3) == 1) { puts("OK\n"); } else { puts("4\n"); }
	if (cache_customlist_blacklist_contains(customlist, "ident", crc4) == 1) { puts("OK\n"); } else { puts("5\n"); }
	if (cache_customlist_blacklist_contains(customlist, "ident", crc1) != 1) { puts("OK\n"); } else { puts("6\n"); }
	if (cache_customlist_blacklist_contains(customlist, "iden",  crc3) != 1) { puts("OK\n"); } else { puts("7\n"); }

	cache_customlist_destroy(customlist);
	*/
}

int cache_contains_address()
{
	struct ip_addr from = {};
	char byte[4];
	inet_pton(AF_INET, "127.0.0.1", &byte);
	from.family = AF_INET;

	memcpy(&from.ipv4_sin_addr, &byte, 4);

	iprange item;
	if (cache_iprange_contains(cached_iprange, (const struct ip_addr *)&from, &item))
	{
		puts("a");
	}
	else
		puts("b");
}

int cache_list_domains(cache_domain *domainsToList, int padding)
{
	if (domainsToList == NULL)
	{
		printf("%sdomains is NULL\n", (padding == 1) ? "  " : "");
		return 0;
	}
	printf("%scapacity: [%x]\n", (padding == 1) ? "  " : "", domainsToList->capacity);
	for (int i = 0; i < domainsToList->capacity; i++)
	{
		//if (domainsToList->base[i] != 8554644589776997716)
		//	continue;

		if (domainsToList->accuracy == NULL)
		{
			printf("%s[%08d]\tcrc=>%016llx\n", (padding == 1) ? "  " : "", i, domainsToList->base[i]);
			continue;
		}

		unsigned char *flags = (unsigned char *)&domainsToList->flags[i];
		printf("%s[%08d]\tcrc=>%016llx\taccu=>%04d\tflags=>%02X %02X %02X %02X %02X %02X %02X %02X\n", (padding == 1) ? "  " : "", i, domainsToList->base[i], domainsToList->accuracy[i],
			(unsigned char)flags[0],
			(unsigned char)flags[1],
			(unsigned char)flags[2],
			(unsigned char)flags[3],
			(unsigned char)flags[4],
			(unsigned char)flags[5],
			(unsigned char)flags[6],
			(unsigned char)flags[7]);
	}
}

int cache_list_custom()
{
	if (cached_customlist == NULL)
	{
		printf("capacity: parent is NULL\n");
		return;
	}
	printf("capacity: [%x]\n", cached_customlist->capacity);
	for (int i = 0; i < cached_customlist->capacity; i++)
	{
		printf("identity=>%s\n", cached_customlist->identity[i]);
		printf(" whitelist:\n");
		cache_list_domains(cached_customlist->whitelist[i], 1);
		printf(" blacklist:\n");
		cache_list_domains(cached_customlist->blacklist[i], 1);
	}
}

int cache_list_policy()
{
	printf("capacity: [%x]\n", cached_policy->capacity);
	for (int i = 0; i < cached_policy->capacity; i++)
	{
		printf("pol=>%08d\tstrat=>%08d\taudit=>%08d\tblock=>%08d\n", cached_policy->policy[i], cached_policy->strategy[i], cached_policy->audit[i], cached_policy->block[i]);
	}
}

int cache_list_ranges()
{
	if (cached_iprange == NULL)
	{
		printf("ranges are emtpy\n");
		return;
	}
	printf("capacity: [%x]\n", cached_iprange->capacity);
	for (int i = 0; i < cached_iprange->capacity; i++)
	{
		if (cached_iprange->low[i]->family == 0x02)
		{
			printf("t=>%02x\tiplo=>%08x\tiphi=>%08x\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family, cached_iprange->low[i]->ipv4_sin_addr, cached_iprange->high[i]->ipv4_sin_addr, cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
		else
		{
			printf("t=>%02x\tiplo=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tiphi=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family,
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[0], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[1], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[2], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[3],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[4], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[5], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[6], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[7],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[8], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[9], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[10], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[11],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[12], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[13], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[14], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[15],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[0], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[1], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[2], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[3],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[4], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[5], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[6], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[7],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[8], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[9], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[10], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[11],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[12], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[13], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[14], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[15],
				cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
	}
}

int test_list_ranges()
{
	struct ip_addr ip4addr_low;
	iprange item = {};

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.29", &ip4addr_low.ipv4_sin_addr);
	if (cache_iprange_contains(cached_iprange_slovakia, (const struct ip_addr *)&ip4addr_low, &item) == 1)
	{
		puts("success");
	}
	else
	{
		puts("fail");
	}
	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.30", &ip4addr_low.ipv4_sin_addr);
	if (cache_iprange_contains(cached_iprange_slovakia, (const struct ip_addr *)&ip4addr_low, &item) == 1)
	{
		puts("success");
	}
	else
	{
		puts("fail");
	}
	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.31", &ip4addr_low.ipv4_sin_addr);
	if (cache_iprange_contains(cached_iprange_slovakia, (const struct ip_addr *)&ip4addr_low, &item) == 1)
	{
		puts("success");
	}
	else
	{
		puts("fail");
	}

}

int domain_exists()
{
	printf("enter domain name to query:");
	char query[80] = {};
	scanf("%79s", query);
	unsigned long long crc = crc64(0, (const unsigned char*)query, strlen(query));
	domain item;
	int result;
	if ((result = cache_domain_contains(cached_domain, crc, &item)) == 1)
	{
		printf("cache contains domain %s", query);
	}
	else
	{
		printf("cache does not contain domain %s", query);
	}
}

int listener()
{
	pthread_t thr_id;
	int ret = 0;
	if ((ret = pthread_create(&thr_id, NULL, &socket_server, NULL)) != 0)
	{
		puts("failed to create server thread");
		return ret;
	}

	puts("server created, type help for help");

	char command[80];
	while (1)
	{
		scanf("%79s", command);
		if (strcmp("help", command) == 0)
		{
			printf("useful commands:\n");
			printf("exit\n");
			printf("iprangetest");
			printf("domains\n");
			printf("domain\n");
			printf("custom\n");
			printf("policy\n");
			printf("ranges\n\n");
			printf("testrange\n\n");
		}

		if (strcmp("exit", command) == 0)
		{
			printf("exited\n");
			return 0;
		}
		if (strcmp("iprangetest", command) == 0)
		{
			cache_contains_address();
		}
		if (strcmp("domain", command) == 0)
		{
			domain_exists();
		}
		if (strcmp("domains", command) == 0)
		{
			cache_list_domains(cached_domain, 0);
		}
		if (strcmp("custom", command) == 0)
		{
			cache_list_custom();
		}
		if (strcmp("policy", command) == 0)
		{
			cache_list_policy();
		}
		if (strcmp("ranges", command) == 0)
		{
			cache_list_ranges();
		}
		if (strcmp("testrange", command) == 0)
		{
			test_list_ranges();
		}


		command[0] = 0;
	}
}

int explode()
{
	char domain[] = "very.up.upper.google.com";
	char *ptr = (char *)&domain;
	ptr += strlen(domain);
	int found = 0;
	while (ptr-- != (char *)&domain)
	{
		if (ptr[0] == '.')
		{
			if (++found > 1)
			{
				printf("%s\n", ptr + 1);
			}
		}
		else if (ptr == (char *)&domain)
		{
			printf("%s\n", ptr);
		}

		//pch = strtok (NULL, ".");
	}
}

int main(int argc, char *argv[])
{
	//loader_init();
	struct ip_addr ip4addr_low;
	struct ip_addr ip4addr_high;

	cached_iprange_slovakia = cache_iprange_init(5);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "100.120.0.1", &ip4addr_low.ipv4_sin_addr);
	ip4addr_low.ipv4_sin_addr = __builtin_bswap32(ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "100.127.255.255", &ip4addr_high.ipv4_sin_addr);
	ip4addr_high.ipv4_sin_addr = __builtin_bswap32(ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "100.112.0.0", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "100.119.255.255", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "151.236.224.0", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "151.236.231.255", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.21", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.21", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.30", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.30", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	listener();
}