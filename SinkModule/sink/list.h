#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      

typedef struct
{
	int capacity;
	int index;
	unsigned long long *base;
} list;

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
	list *result = calloc(1, sizeof(list));
	result->capacity = count;
	result->index = 0;
	result->base = (unsigned long long *)malloc(result->capacity * sizeof(unsigned long long));
	return result;
}

list* sink_list_init_ex(char *buffer, int count)
{
	result->capacity = count;
	result->index = 0;
	result->base = (unsigned long long *)buffer;
}

void sink_list_destroy(list *item)
{
	if (item->base != NULL)
	{
		free(item->base);
		free(item);
	}
}

int sink_list_add(list* item, unsigned long long value)
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
	item->index++;

	return 0;
}

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

bool sink_list_contains(list* item, unsigned long long value)
{
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

	return (lowerbound <= upperbound);
}