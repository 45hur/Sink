#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "crc64.h"

class hashcontainer
{
public:
	hashcontainer()
	{
		load();
	}

	~hashcontainer()
	{
		if (hashtable)
		{
			delete hashtable;
		} 
	}

	bool contains(char * value)
	{
		if (!hashtable)
			return false;

		unsigned long long crc = crc64(0, (const unsigned char*)value, strlen(value));
		return sink_list_contains(hashtable, crc);
	}

protected:
	list *hashtable = NULL;

	const unsigned char* getfield(char* line, int num)
	{
		const unsigned char* tok;
		for (tok = (unsigned char *)strtok(line, ",");
			tok && *tok;
			tok = (unsigned char *)strtok(NULL, ",\n"))
		{
			if (!--num)
				return tok;
		}
		return NULL;
	}

	int load()
	{
		if (hashtable)
		{
			return -1;
		}

		FILE* dump = fopen("hashtable.dump", "rb");
		if (dump)
		{
			/// Open already sorted and serialized array
			fseek(dump, 0, SEEK_END);
			int size = ftell(dump);
			fseek(dump, 0, SEEK_SET);
			hashtable = sink_list_init(size / 8);
			char buffer[8];
			
			while (fread(buffer, 8, 1, dump) != 0)
			{
				if (sink_list_add(hashtable, *(unsigned long long *)buffer) != 0)
					break;
			}
			fclose(dump);
		}
		else
		{
			/// Load CSV and parse it
			FILE* stream = fopen("top-5.csv", "r");
			char line[1024];

			/// Get total number of domains
			int linecount = 0;
			while (fgets(line, 1024, stream))
			{
				linecount++;
			}

			/// Prepare hash table
			hashtable = sink_list_init(linecount);
			fseek(stream, 0, SEEK_SET);
			while (fgets(line, 1024, stream))
			{
				const unsigned char* value = getfield(line, 2);
				unsigned long long crc = crc64(0, value, strlen((const char *)value));
				sink_list_add(hashtable, crc);
			}
			sink_list_sort(hashtable);

			/// Dump table for future use
			sink_list_dump(hashtable, "hashtable.dump");
		}

		return 0;
	}
};
