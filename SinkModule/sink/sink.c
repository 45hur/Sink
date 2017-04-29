/* Convenience macro to declare module API. */
#define C_MOD_SINK "\x08""mod-sink"


#include "lib/module.h"
//#include "lib/rplan.h"
//
#include <pthread.h>
#include <syslog.h>
#include <lib/rplan.h>

#include "sink.h"

static void* observe(void *arg)
{
        /* ... do some observing ... */
        openlog("sink",  LOG_CONS | LOG_PID, LOG_USER);
        syslog(LOG_INFO, "Loaded");
        closelog();

        return NULL;
}

static int load(struct kr_module *module, const char *path)
{
        return kr_ok();
}

static int collect(kr_layer_t *ctx)
{
/*
        struct kr_request *param = ctx->data;
        struct kr_rplan *rplan = &param->rplan;
        if (!param->qsource.addr) {
                openlog("sink",  LOG_CONS | LOG_PID, LOG_USER);
                syslog(LOG_INFO, "sank");
                closelog();


                return ctx->state;
        }
        const struct sockaddr *sa = param->qsource.addr;
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;

        const char *client_address = inet_ntoa(sin->sin_addr);
        */
    struct kr_request *request = (struct kr_request *)ctx->req;
    struct kr_rplan *rplan = &request->rplan;

    char message[KNOT_DNAME_MAXLEN] = {};
    sprintf(message, "State %u",request->state);
    logtosyslog(message);


    char qname_str[KNOT_DNAME_MAXLEN];
    if (rplan->resolved.len > 0)
    {
        bool sinkit = false;
        uint16_t rclass;
        struct kr_query *last = array_tail(rplan->resolved);
        const knot_pktsection_t *ns = knot_pkt_section(request->answer, KNOT_ANSWER);

        if (ns == NULL)
        {
            logtosyslog("ns = NULL");
            return ctx->state;
        }

        sprintf(message, "ns->count = %u", ns->count);
        logtosyslog(message);
        for (unsigned i = 0; i < ns->count; ++i)
        {
            const knot_rrset_t *rr = knot_pkt_rr(ns, i);

            if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA)
            {
                knot_dname_to_str(message, rr->owner, KNOT_DNAME_MAXLEN);
                logtosyslog(message);
            }
        }
    }

    return ctx->state;
}

KR_EXPORT
const kr_layer_api_t *sink_layer(struct kr_module *module) {
        static kr_layer_api_t _layer = {
                .finish = &collect,
        };
        /* Store module reference */
        _layer.data = module;
        return &_layer;
}

KR_EXPORT
int sink_init(struct kr_module *module)
{
        /* Create a thread and start it in the background. */
        pthread_t thr_id;
        int ret = pthread_create(&thr_id, NULL, &observe, NULL);
        if (ret != 0) {
                return kr_error(errno);
        }

        /* Keep it in the thread */
        module->data = (void *)thr_id;
        return kr_ok();
}

KR_EXPORT
int sink_deinit(struct kr_module *module)
{
        /* ... signalize cancellation ... */
        void *res = NULL;
        pthread_t thr_id = (pthread_t) module->data;
        int ret = pthread_join(thr_id, res);
        if (ret != 0) {
                return kr_error(errno);
        }

        return kr_ok();
}

KR_MODULE_EXPORT(sink)