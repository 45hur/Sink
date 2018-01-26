/* Convenience macro to declare module API. */
#define C_MOD_SINK "\x08""mod-sink"

#include "lib/module.h"
#include <pthread.h>
#include <syslog.h>
#include <lib/rplan.h>

#include "sink.h"

static void* observe(void *arg)
{
    /* ... do some observing ... */
    openlog("sink",  LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "Loading");
    closelog();

    hashcontainer_init();

    openlog("sink",  LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "Loaded");
    closelog();

    return NULL;
}

static int load(struct kr_module *module, const char *path)
{
        return kr_ok();
}

static int parse_addr_str(struct sockaddr_storage *sa, const char *addr) {
    int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
    memset(sa, 0, sizeof(struct sockaddr_storage));
    sa->ss_family = family;
    char *addr_bytes = (char *)kr_inaddr((struct sockaddr *)sa);
    if (inet_pton(family, addr, addr_bytes) < 1) {
        return kr_error(EILSEQ);
    }
    return 0;
}

static int collect(kr_layer_t *ctx)
{
    struct kr_request *request = (struct kr_request *)ctx->req;
    struct kr_rplan *rplan = &request->rplan;

    char message[KNOT_DNAME_MAXLEN] = {};

    char qname_str[KNOT_DNAME_MAXLEN];
    if (rplan->resolved.len > 0)
    {
        bool sinkit = false;
        uint16_t rclass = 0;
        struct kr_query *last = array_tail(rplan->resolved);
        const knot_pktsection_t *ns = knot_pkt_section(request->answer, KNOT_ANSWER);

        if (ns == NULL)
        {
            logtosyslog("ns = NULL");
            return ctx->state;
        }

        for (unsigned i = 0; i < ns->count; ++i)
        {
            const knot_rrset_t *rr = knot_pkt_rr(ns, i);

            if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA)
            {
                char domain[KNOT_DNAME_MAXLEN];
                knot_dname_to_str(domain, rr->owner, KNOT_DNAME_MAXLEN);

                int domainLen = strlen(domain);
                if(domain[domainLen - 1] == '.')
                {
                    domain[domainLen - 1] = '\0';
                }

                if (hashcontainer_contains(domain))
                {
                    sprintf(message, "redirecting ? '%s'", domain);
                    logtosyslog(message);

                    uint16_t msgid = knot_wire_get_id(request->answer->wire);
                    kr_pkt_recycle(request->answer);

                    knot_pkt_put_question(request->answer, last->sname, last->sclass, last->stype);
                    knot_pkt_begin(request->answer, KNOT_ANSWER); //AUTHORITY?

                    struct sockaddr_storage sinkhole;
                    const char *sinkit_sinkhole = "94.237.30.217";
                    if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0) {
                        return kr_error(EINVAL);
                    }

                    sprintf(message, "apply redirect to %s", sinkit_sinkhole);
                    logtosyslog(message);

                    size_t addr_len = kr_inaddr_len((struct sockaddr *)&sinkhole);
                    const uint8_t *raw_addr = (const uint8_t *)kr_inaddr((struct sockaddr *)&sinkhole);
                    static knot_rdata_t rdata_arr[RDATA_ARR_MAX];

                    knot_wire_set_id(request->answer->wire, msgid);
 
                    kr_pkt_put(request->answer, last->sname, 120, KNOT_CLASS_IN, KNOT_RRTYPE_A, raw_addr, addr_len);

                    return KNOT_STATE_DONE;
                }
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