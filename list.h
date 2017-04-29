#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      

class list
{
protected:
	int capacity;
	int index;
	unsigned long long * base;

	static int compare(const void * a, const void * b)
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

public:
	list(int capacity) :
		capacity(capacity),
		index(0)
	{
		base = (unsigned long long *)malloc(capacity * sizeof(unsigned long long));
	}
	~list()
	{
		if (base != NULL)
		{
			free(base);
			base = NULL;
		}
	}

	int add(unsigned long long value)
	{
		if (index > capacity)
			return -1;

		/// Silly colision check
		//for (int i = 0; i < index; i++)
		//{
		//	if (base[i] == value)
		//		return -1;
		//}

		base[index] = value;
		index++;

		return 0;
	}

	void sort() const
	{
		qsort(base, (size_t)index, sizeof(unsigned long long), compare);
	}

	int dump(const char * filename)
	{
		FILE* file = fopen(filename, "wb");
		if (file == NULL)
			return -1;

		int written = fwrite(base, sizeof(unsigned long long), index, file);
		if (written != index)
			return -2;

		if (fflush(file) != 0)
			return -3;

		return fclose(file);
	}

	bool contains(unsigned long long value)
	{
		int lowerbound = 0;
		int upperbound = index;
		int position;

		position = (lowerbound + upperbound) / 2;

		while ((base[position] != value) && (lowerbound <= upperbound))
		{
			if (base[position] > value)
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
};