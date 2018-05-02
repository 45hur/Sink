#ifndef SINK_SINK_H
#define SINK_SINK_H

#include "lib/module.h"
#include <pthread.h>
#include <stdio.h>
#include <syslog.h>
#include <lib/rplan.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/wait.h>


#include <libknot/packet/pkt.h>
#include <libknot/rrtype/aaaa.h>
#include <ucw/mempool.h>
#include "daemon/engine.h"
#include <knot/query/layer.h>



struct shared {
	pthread_mutex_t mutex;
	int sharedResource;
};
struct shared *p;

static __inline void logtofile(char *text)
{
	pthread_mutex_lock(&(p->mutex));

	FILE *log_whalebone = 0;
	char message[255] = {};
	char timebuf[30] = {};
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);

	if (log_whalebone == 0)
	{
		log_whalebone = fopen("/var/log/whalebone/whalebone.log", "at");
		if (!log_whalebone)
			log_whalebone = fopen("/var/log/whalebone/whalebone.log", "wt");
		if (!log_whalebone)
		{
			pthread_mutex_unlock(&(p->mutex));

			return;
		}
	}
	
	fputs(message, log_whalebone);
	fflush(log_whalebone);
	fclose(log_whalebone);

	//memset(text, 0, strlen(text));

	pthread_mutex_unlock(&(p->mutex));
}

static __inline void logtosyslog(char *text)
{
	return;

	pthread_mutex_lock(&(p->mutex));
	
	FILE *log_debug = 0;
	char message[255] = {};
	char timebuf[30] = {};
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

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
			pthread_mutex_unlock(&(p->mutex));

			return;
		}
	}

	fputs(message, log_debug);
	fflush(log_debug);
	fclose(log_debug);

	//memset(text, 0, strlen(text));

	pthread_mutex_unlock(&(p->mutex));
}

#include "cache_loader.h"
#include "socket_srv.h"

static __inline void logtoaudit(char *text)
{
	pthread_mutex_lock(&(p->mutex));

	FILE *log_audit = 0;
	char message[255] = {};
	char timebuf[30] = {};
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);

	if (log_audit == 0)
	{
		log_audit = fopen("/var/log/whalebone/audit.log", "at");
		if (!log_audit)
			log_audit = fopen("/var/log/whalebone/audit.log", "wt");
		if (!log_audit)
		{
			pthread_mutex_unlock(&(p->mutex));

			return;
		}
	}

	fputs(message, log_audit);
	fflush(log_audit);
	fclose(log_audit);

	//memset(text, 0, strlen(text));

	pthread_mutex_unlock(&(p->mutex));
}
#endif //SINK_SINK_H