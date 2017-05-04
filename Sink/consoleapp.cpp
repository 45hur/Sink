// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "hashcontainer.h"
#include <sys/timeb.h>
#include <time.h>


int main()
{
	hashcontainer hc;
	
	struct timeb start, end;
	int diff;
	int i = 0;
	ftime(&start);

	for (int i = 0; i < 1000000; i++)
	{
		hc.contains("napitwptech.com");
	}
		

	ftime(&end);
	diff = (int)(1000.0 * (end.time - start.time)
		+ (end.millitm - start.millitm));

	printf("\nOperation took %u milliseconds\n", diff);

    return 0;
}

