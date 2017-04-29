#ifndef SINK_SINK_H
#define SINK_SINK_H

#include <libknot/packet/pkt.h>
#include <libknot/rrtype/aaaa.h>
#include <ucw/mempool.h>
#include "daemon/engine.h"
#include <knot/query/layer.h>

#include "hashcontainer.h"

static __inline void logtosyslog(char *text)
{
    openlog("sink", LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s\n", text);
    closelog();
    memset(text, 0, strlen(text));
}

#endif //SINK_SINK_H