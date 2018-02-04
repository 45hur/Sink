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

  unsigned long long ret = 0;
  if ((ret = loader_init()) != 0)
  {
  	openlog("sink",  LOG_CONS | LOG_PID, LOG_USER);
  	syslog(LOG_INFO, "CSV load failed");
  	closelog();
  	return (void *)-1;
  }

  pthread_t thr_id;
  if ((ret = pthread_create(&thr_id, NULL, &socket_server, NULL)) != 0) 
  {
  	openlog("sink",  LOG_CONS | LOG_PID, LOG_USER);
  	syslog(LOG_INFO, "Create thread failed");
  	closelog();
    return (void *)ret;  
  }

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

static int collect_rtt(kr_layer_t *ctx, knot_pkt_t *pkt)
{
    struct kr_request *req = ctx->req;
    struct kr_query *qry = req->current_query;
    if (qry->flags.CACHED || !req->qsource.addr) {
        return ctx->state;
    }
    
    const struct sockaddr *res = req->qsource.addr;
    char *s = NULL;
    switch(res->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)res;
            s = malloc(INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res;
            s = malloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
            break;
        }
        default:
        {
            logtosyslog("not valid addr");
            return ctx->state;
            break;
        }
    }
    char message[KNOT_DNAME_MAXLEN] = {};
    sprintf(message, "IP address: %s", s);
    logtosyslog(message); 
    free(s);

    return ctx->state;
}


static int collect(kr_layer_t *ctx)
{
    char message[KNOT_DNAME_MAXLEN] = {};
    struct kr_request *request = (struct kr_request *)ctx->req;
    struct kr_rplan *rplan = &request->rplan;

	if (!request->qsource.addr) {
		sprintf(message, "request has no source address");
		logtosyslog(message);

		return ctx->state;
	}

	const struct sockaddr *res = request->qsource.addr;
	char *s = NULL;
  struct ip_addr origin = {};
	switch (res->sa_family) {
  	case AF_INET: 
    {
  		struct sockaddr_in *addr_in = (struct sockaddr_in *)res;
  		s = malloc(INET_ADDRSTRLEN);
  		inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
      origin.family = AF_INET;
      memcpy(&origin.ipv4_sin_addr, &(addr_in->sin_addr), 4);    
  		break;
  	}
  	case AF_INET6: 
    {
  		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res;
  		s = malloc(INET6_ADDRSTRLEN);
  		inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
      origin.family = AF_INET6;
      memcpy(&origin.ipv6_sin_addr, &(addr_in->sin6_addr), 16); 
  		break;
  	}
  	default:
  	{
  		sprintf(message, "qsource is invalid");
  		logtosyslog(message);
  		return ctx->state;
  		break;
  	}
	}
	sprintf(message, "[%s] request", s);
	logtosyslog(message);
	free(s);

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
                char querieddomain[KNOT_DNAME_MAXLEN];
                knot_dname_to_str(querieddomain, rr->owner, KNOT_DNAME_MAXLEN);

                int domainLen = strlen(querieddomain);
                if(querieddomain[domainLen - 1] == '.')
                {
                    querieddomain[domainLen - 1] = '\0';
                }

                unsigned long long crc = crc64(0, (const unsigned char*)querieddomain, strlen(querieddomain));
	              domain domain_item = {};
                if (cache_domain_contains(cached_domain, crc, &domain_item))
                {
                    sprintf(message, "detected '%s'", querieddomain);
                    logtosyslog(message);
                    
                    iprange iprange_item = {};
                    if (cache_iprange_contains(cached_iprange, &origin, &iprange_item))
                    {
                      sprintf(message, "detected '%s' matches ip range with ident '%s' policy '%d'", querieddomain, iprange_item.identity, iprange_item.policy_id);
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
    }

    return ctx->state;
}

KR_EXPORT
const kr_layer_api_t *sink_layer(struct kr_module *module) {
        static kr_layer_api_t _layer = {
				//.consume = &collect_rtt,
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