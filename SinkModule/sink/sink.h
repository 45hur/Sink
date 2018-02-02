#ifndef SINK_SINK_H
#define SINK_SINK_H

#include <libknot/packet/pkt.h>
#include <libknot/rrtype/aaaa.h>
#include <ucw/mempool.h>
#include "daemon/engine.h"
#include <knot/query/layer.h>

#include <stdio.h>
#include <string.h>    //strlen
#include <stdlib.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <pthread.h> //for threading , link with lpthread


#include "hashcontainer.h"

static __inline void logtosyslog(char *text)
{
    openlog("sink", LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", text);
    closelog();
    memset(text, 0, strlen(text));
}
 
void *connection_handler(void *);

struct Header 
{
    uint64_t action:64;
    uint64_t msgsize:64;
    uint64_t msgcrc:64;
    uint64_t headercrc:64;
};

#endif //SINK_SINK_H