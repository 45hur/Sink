#pragma once

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
} list;

typedef struct 
{
	short accuracy;
	unsigned long long flags;
} cache1item;

enum flags 
{
	flags_accuracy = 1,
	flags_blacklist = 2,
	flags_whitelist = 4,
	flags_drop = 8
};

enum strategy 
{
	strategy_accuracy = 1,
	strategy_blacklist = 2,
	strategy_whitelist = 4,
	strategy_drop = 8
};

static int sink_list_compare(const void * a, const void * b)
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

list* sink_list_init(int count)
{
	list *result = (list *)calloc(1, sizeof(list));
	result->capacity = count;
	result->index = 0;
	result->searchers = 0;
	result->base = (unsigned long long *)malloc(result->capacity * sizeof(unsigned long long));
	result->accuracy = (short *)calloc(1, result->capacity * sizeof(short));
	result->flags = (unsigned long long *)malloc(result->capacity * sizeof(unsigned long long));
	return result;
}

list* sink_list_init_ex(char *domains, char *accuracy, char *flags, int count)
{
	list *result = (list *)calloc(1, sizeof(list));
	result->capacity = count;
	result->index = count;
	result->searchers = 0;
	result->base = (unsigned long long *)domains;
	result->accuracy = (short *)accuracy;
	result->flags = (unsigned long long *)flags;
	return result;
}

void sink_list_destroy(list *item)
{
    while(item->searchers > 0)
    {
        usleep(50000);
    }

	if (item->base != NULL)
	{
		free(item->base);
		free(item->accuracy);
		free(item->flags);
		free(item);
	}
}

int sink_list_add(list* item, unsigned long long value, short accuracy, unsigned long long flags)
{
	if (item->index > item->capacity)
		return -1;

	/// Silly colision check
	//for (int i = 0; i < index; i++)
	//{
	//	if (base[i] == value)
	//		return -1;
	//}

	item->base[item->index] = value;
	item->accuracy[item->index] = accuracy;
	item->flags[item->index] = flags;
	item->index++;

	return 0;
}

/// does not sort the other fields of the list
void sink_list_sort(list* item)
{
	qsort(item->base, (size_t)item->index, sizeof(unsigned long long), sink_list_compare);
}

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
}

bool sink_list_contains(list* item, unsigned long long value, cache1item &citem)
{
	item->searchers++;
	int lowerbound = 0;
	int upperbound = item->index;
	int position;

	position = (lowerbound + upperbound) / 2;

	while ((item->base[position] != value) && (lowerbound <= upperbound))
	{
		if (item->base[position] > value)
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
		citem.accuracy = (item->accuracy[position]);
		citem.flags = (item->flags[position]);
	}

	item->searchers--;
	return (lowerbound <= upperbound);
}