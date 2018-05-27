#include<stdio.h>
#include<string.h>    //strlen
#include<stdlib.h>    //strlen
#include<syslog.h>
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write

#include<pthread.h> //for threading , link with lpthread
 
static FILE *log_whalebone = 0;
static FILE *log_debug = 0;
static FILE *log_audit = 0;

static __inline void logtofile(char *text)
{
	char message[255] = {};
	char timebuf[30] = {};
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	puts(text);

	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);

	if (log_whalebone == 0)
	{
		log_whalebone = fopen("/var/log/whalebone/whalebone.log", "at");
		if (!log_whalebone)
			log_whalebone = fopen("/var/log/whalebone/whalebone.log", "wt");
		if (!log_whalebone)
		{
			return;
		}
	}

	fputs(message, log_whalebone);
	fflush(log_whalebone);

	memset(text, 0, strlen(text));
}

static __inline void logtosyslog(char *text)
{
	char message[255] = {};
	char timebuf[30] = {};
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	puts(text);

	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);

	openlog("whalebone", LOG_CONS | LOG_PID, LOG_USER);
	syslog(LOG_INFO, "%s", message);
	closelog();

	if (log_debug == 0)
	{
		log_debug = fopen("/var/log/whalebone/debug.log", "at");
		if (!log_debug)
			log_debug = fopen("/var/log/whalebone/debug.log", "wt");
		if (!log_debug)
		{
			return;
		}
	}

	fputs(message, log_debug);
	fflush(log_debug);

	memset(text, 0, strlen(text));
}