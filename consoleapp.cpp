// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "hashcontainer.h"

int main()
{
	hashcontainer hc;
	
	if (hc.contains("google.com"))
		return -1;

    return 0;
}

