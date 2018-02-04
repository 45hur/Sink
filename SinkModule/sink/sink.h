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

static __inline void logtosyslog(char *text)
{
    openlog("sink", LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", text);
    closelog();
    memset(text, 0, strlen(text));
}

static __inline void logtoaudit(char *text)
{
    openlog("sink-audit", LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", text);
    closelog();
    memset(text, 0, strlen(text));
}
 
#endif //SINK_SINK_H