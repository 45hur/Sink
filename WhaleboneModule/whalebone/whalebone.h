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
    //openlog("whalebone", LOG_CONS | LOG_PID, LOG_USER);
    //syslog(LOG_INFO, "%s", text);
    //closelog();
    
    if (log_whalebone == 0) 
    {
        log_whalebone = fopen("whalebone.log", "at");
        if (!log_whalebone) 
          log_whalebone = fopen("logfile.log", "wt");
        if (!log_whalebone) 
        {
            return;   
        }
    }
    
    fprintf(log_whalebone, text);

    memset(text, 0, strlen(text));
}

static __inline void logtoaudit(char *text)
{
    //openlog("whalebone-audit", LOG_CONS | LOG_PID, LOG_USER);
    //syslog(LOG_INFO, "%s", text);
    //closelog();
    
    if (log_audit == 0) 
    {
        log_audit = fopen("audit.log", "at");
        if (!log_audit) 
          log_audit = fopen("audit.log", "wt");
        if (!log_audit) 
        {
            return;   
        }
    }
    
    fprintf(log_audit, text);

    memset(text, 0, strlen(text));
}
 
#endif //SINK_SINK_H