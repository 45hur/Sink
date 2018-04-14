#ifndef SINK_SINK_H
#define SINK_SINK_H

#include "lib/module.h"
#include <pthread.h>
#include <syslog.h>
#include <lib/rplan.h>

#include <libknot/packet/pkt.h>
#include <libknot/rrtype/aaaa.h>
#include <ucw/mempool.h>
#include "daemon/engine.h"
#include <knot/query/layer.h>

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

#include "cache_loader.h"
#include "socket_srv.h"

static __inline void logtoaudit(char *text)
{
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
			return;
		}
	}

	fputs(message, log_audit);
	fflush(log_audit);

	memset(text, 0, strlen(text));
}
#endif //SINK_SINK_H