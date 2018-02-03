#pragma once
#ifndef CACHE_DOMAINS_H
#define CACHE_DOMAINS_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      

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
	unsigned long long *base;
	short *accuracy;
	unsigned long long *flags;
} cache_domain;

typedef struct 
{
  unsigned long long  crc;
	short accuracy;
	unsigned long long flags;
} domain;

enum 
{
  flags_none = 0,
  flags_accuracy = 1,
  flags_blacklist = 2, 
  flags_whitelist = 4, 
  flags_drop = 8 
} flags;

unsigned char cache_domain_get_flags(unsigned long long flags, int n)
{
  return (flags >> (8 * n)) & 0xff; 
} 

static int cache_domain_compare(const void * a, const void * b)
{
	const unsigned long long ai = *(const unsigned long long*)a;
	const unsigned long long bi = *(const unsigned long long*)b;

	if (ai < bi)
	{
		return -1;
	}
	else if (ai > bi)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

cache_domain* cache_domain_init(int count)
{
	cache_domain *item = (cache_domain *)calloc(1, sizeof(cache_domain));
  if (item == NULL)
  {
    return NULL;
  }
  
	item->capacity = count;
	item->index = 0;
	item->searchers = 0;

  item->base = (unsigned long long *)malloc(item->capacity * sizeof(unsigned long long));
  item->accuracy = (short *)calloc(1, item->capacity * sizeof(short));
	item->flags = (unsigned long long *)malloc(item->capacity * sizeof(unsigned long long));
  
  if (item->base == NULL || item->accuracy == NULL || item->flags == NULL)
  {
    return NULL;
  }
                
	return item;    
}

cache_domain* cache_domain_init_ex(char *domains, char *accuracy, char *flags, int count)
{
	cache_domain *item = (cache_domain *)calloc(1, sizeof(cache_domain));
  if (item == NULL)
  {
    return NULL;
  }
    
	item->capacity = count;
	item->index = count;
	item->searchers = 0;
	item->base = (unsigned long long *)domains;
	item->accuracy = (short *)accuracy;
	item->flags = (unsigned long long *)flags;
  if (item->base == NULL || item->accuracy == NULL || item->flags == NULL)
  {
    return NULL;
  }
  
	return item;
}

void cache_domain_destroy(cache_domain *cache)
{
  while(cache->searchers > 0)
  {
    usleep(50000);
  }

	if (cache->base)
	{
		free(cache->base);
    cache->base = NULL;
	}
	if (cache->accuracy)
	{
		free(cache->accuracy);
    cache->accuracy = NULL;
  }
	if (cache->flags)
	{
		free(cache->flags);
    cache->flags = NULL;
  }

	free(cache);  
  cache = NULL;
}

int cache_domain_add(cache_domain* cache, unsigned long long value, short accuracy, unsigned long long flags)
{
	if (cache->index > cache->capacity)
		return -1;

	cache->base[cache->index] = value;
  cache->accuracy[cache->index] = accuracy;
  cache->flags[cache->index] = flags;
	cache->index++;

	return 0;
}

int cache_domain_update(cache_domain* cache, unsigned long long value, short accuracy, unsigned long long flags)
{
	if (cache->index > cache->capacity)
		return -1;

  int position = cache->index;

	while (--position >= 0)
	{
    if (cache->base[position] == value)
    {
      cache->accuracy[position] = accuracy;
      cache->flags[position] = flags;
      break;
    } 
  }	

	return 0;
}

/// does not sort the other fields of the list
/// TODO: fix qsort to work with a whole struct
void cache_domain_sort(cache_domain* cache)
{
	qsort(cache->base, (size_t)cache->index, sizeof(unsigned long long), cache_domain_compare);
}
       /*
int sink_list_dump(list* item, const char * filename)
{
	FILE* file = fopen(filename, "wb");
	if (file == NULL)
		return -1;

	int written = fwrite(item->base, sizeof(unsigned long long), item->index, file);
	if (written != item->index)
		return -2;

	if (fflush(file) != 0)
		return -3;

	return fclose(file);
}   */

int cache_domain_contains(cache_domain* cache, unsigned long long value, domain *citem)
{
	cache->searchers++;
	int lowerbound = 0;
	int upperbound = cache->index;
	int position;

	position = (lowerbound + upperbound) / 2;

	while ((cache->base[position] != value) && (lowerbound <= upperbound))
	{
		if (cache->base[position] > value)
		{
			upperbound = position - 1;
		}
		else
		{
			lowerbound = position + 1;
		}
		position = (lowerbound + upperbound) / 2;
	}
	
	if (lowerbound <= upperbound)
	{
		citem->accuracy = (cache->accuracy[position]);
		citem->flags = (cache->flags[position]);
	}

	cache->searchers--;
	return (lowerbound <= upperbound);
}

#endif