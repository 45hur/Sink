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

#include "cache_loader.h"
#include "socket_srv.h"


static FILE *log_audit = 0;
static FILE *log_whalebone = 0;

static __inline void logtosyslog(char *text)
{
	char message[255] = {};
	char timebuf[26] = {};
	int millisec;
	struct tm* tm_info;
	struct timeval tv;
	millisec = lrint(tv.tv_usec / 1000.0); // Round to nearest millisec
	if (millisec >= 1000) { // Allow for rounding up to nearest second
		millisec -= 1000;
		tv.tv_sec++;
	}

	tm_info = localtime(&tv.tv_sec);

	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", tm_info);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);

    openlog("whalebone", LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", message);
    closelog();

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

static __inline void logtoaudit(char *text)
{
    openlog("whalebone-audit", LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", text);
    closelog();

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
    
    fputs(text, log_audit);
    fflush(log_whalebone);

    memset(text, 0, strlen(text));
}
 
#endif //SINK_SINK_H