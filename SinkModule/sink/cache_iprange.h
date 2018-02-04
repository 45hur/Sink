#pragma once
#ifndef CACHE_IPRANGE_H
#define CACHE_IPRANGE_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      

#include "iprange.h"

#ifndef WIN32
#include <unistd.h>


#else
#define _Atomic volatile
#include <Windows.h>
void usleep(__int64 usec)
{
	HANDLE timer;
	LARGE_INTEGER ft;

	ft.QuadPart = -(10 * usec); // Convert to 100 nanosecond interval, negative value indicates relative time

	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
	WaitForSingleObject(timer, INFINITE);
	CloseHandle(timer);
}

#endif

typedef struct
{
	int capacity;
	int index;
	_Atomic int searchers;
	struct ip_addr **low;
  struct ip_addr **high;
	char **identity;
  int *policy_id;
} cache_iprange;

typedef struct
{
	char *identity;
  int policy_id;
} iprange;

cache_iprange* cache_iprange_init(int count)
{
	cache_iprange *item = (cache_iprange *)calloc(1, sizeof(cache_iprange));
  if (item == NULL)
  {
    return NULL;
  }  
  
	item->capacity = count;
	item->index = 0;
	item->searchers = 0;
	item->low = (struct ip_addr **)malloc(item->capacity * sizeof(struct ip_addr *));
  item->high = (struct ip_addr **)malloc(item->capacity * sizeof(struct ip_addr *));
  item->identity = (char **)malloc(item->capacity * sizeof(char *));
  item->policy_id = (int *)malloc(item->capacity * sizeof(int));
  if (item->low == NULL || item->high == NULL || item->identity == NULL || item->policy_id == NULL)
  {
    return NULL;
  }  
  
	return item;
}

void cache_iprange_destroy(cache_iprange *cache)
{
  while (cache->searchers > 0)
  {
    usleep(50000);
  }

  int position = cache->index;
	while (--position >= 0)
	{
    if (cache->low[position] != NULL)
  	{
  		free(cache->low[position]);
  	}
    if (cache->high[position] != NULL)
  	{
  		free(cache->high[position]);
  	}
    if (cache->identity[position] != NULL)
  	{
  		free(cache->identity[position]);
  	}
  }
  
  if (cache->low != NULL)
  {
    free(cache->low);
  }  
  if (cache->high != NULL)
  {
    free(cache->high);
  }
  if (cache->identity != NULL)
  {
    free(cache->identity);
  }  
  if (cache->policy_id != NULL)
  {
    free(cache->policy_id);
  }
  if (cache != NULL)
  {
    free(cache);
  } 
}


int cache_iprange_add(cache_iprange* cache, struct ip_addr *low, struct ip_addr *high, char *identity, int policy_id)
{
	if (cache->index > cache->capacity)
		return -1;

  struct ip_addr* xlow = (struct ip_addr*)malloc(sizeof(struct ip_addr));
  struct ip_addr* xhigh = (struct ip_addr*)malloc(sizeof(struct ip_addr));
  char* xidentity = (char *)calloc(strlen(identity 1), sizeof(char));
  if (xlow == NULL || xhigh == NULL || xidentity == NULL)
  {
    return -1;    
  }

  memcpy(xlow, low, sizeof(struct ip_addr));
  memcpy(xhigh, high, sizeof(struct ip_addr));
  memcpy(xidentity, identity, strlen(identity));
	cache->low[cache->index] = xlow;
	cache->high[cache->index] = xhigh;
	cache->identity[cache->index] = xidentity;
	cache->policy_id[cache->index] = policy_id;
	cache->index++;

	return 0;
}

int cache_iprange_contains(cache_iprange* cache, const struct ip_addr * ip, iprange *item)
{
	cache->searchers++;
  int result = 0;
	int position = cache->index;
          
	while (--position >= 0)
	{
    if ((result = is_ip_in_range(
      ip,
      (const struct ip_addr *)cache->low[position],
      (const struct ip_addr *)cache->high[position]
      )) == 1)
      {
        item->identity = cache->identity[position]; 
        item->policy_id = cache->policy_id[position];       
        break;
      }
	} 
	
	cache->searchers--;
	return result;
}

#endif