/* Convenience macro to declare module API. */
#define C_MOD_WHALEBONE "\x09""whalebone"

#include "lib/module.h"
#include <pthread.h>
#include <syslog.h>
#include <lib/rplan.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "whalebone.h"

static void* observe(void *arg)
{
	/* ... do some observing ... */
	logtosyslog("\"message\":\"loading\"");


	unsigned long long ret = 0;
	//if ((ret = loader_init()) != 0)
	//{
	//	logtosyslog("\"message\":\"csv load failed\"");
	//	return (void *)-1;
	//}

	if ((cached_iprange_slovakia = cache_iprange_init(5)) == NULL)
	{
		puts("not enough memory to create ip range cache");
		return (void *)-1;
	}

	struct ip_addr ip4addr_low;
	struct ip_addr ip4addr_high;

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "100.120.0.1", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "100.127.255.255", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "100.112.0.0", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "100.119.255.255", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "151.236.224.0", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "151.236.231.255", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.21", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.21", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.30", &ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.30", &ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	pthread_t thr_id;
	if ((ret = pthread_create(&thr_id, NULL, &socket_server, NULL)) != 0)
	{
		logtosyslog("\"message\":\"create thread failed\"");
		return (void *)ret;
	}

	logtosyslog("\"message\":\"load succeeded\"");

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

static int consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (qry->flags.CACHED || !req->qsource.addr)
	{
		sprintf(message, "\"message\":\"consume has no valid address\"");
		logtosyslog(message);

		return ctx->state;
	}

	const struct sockaddr *res = req->qsource.addr;
	char *s = NULL;
	switch (res->sa_family) {
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
		logtosyslog("\"message\":\"not valid addr\"");
		return ctx->state;
		break;
	}
	}
	sprintf(message, "\"message\":\"consume address: %s\"", s);
	logtosyslog(message);
	free(s);

	return ctx->state;
}

static int redirect(struct kr_request * request, struct kr_query *last, bool ipv4, struct ip_addr * origin)
{
	uint16_t msgid = knot_wire_get_id(request->answer->wire);
	kr_pkt_recycle(request->answer);

	knot_pkt_put_question(request->answer, last->sname, last->sclass, last->stype);
	knot_pkt_begin(request->answer, KNOT_ANSWER); //AUTHORITY?

	char message[KNOT_DNAME_MAXLEN] = {};
	struct sockaddr_storage sinkhole;
	if (ipv4)
	{
		const char *sinkit_sinkhole = getenv("SINKIP");
		if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
		{
			sinkit_sinkhole = "0.0.0.0";
		}
		if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
		{
			return kr_error(EINVAL);
		}

		iprange iprange_item = {};
		if (cache_iprange_contains(cached_iprange_slovakia, origin, &iprange_item) == 1)
		{
			sprintf(message, "\"message\":\"origin matches slovakia\"");
			logtosyslog(message);
			sinkit_sinkhole = "194.228.41.77";
		}
		else
		{
			sprintf(message, "\"message\":\"origin does not match slovakia\"");
			logtosyslog(message);
		}
	}
	else
	{
		const char *sinkit_sinkhole = getenv("SINKIPV6");
		if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
		{
			sinkit_sinkhole = "0000:0000:0000:0000:0000:0000:0000:0001";
		}
		if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
		{
			return kr_error(EINVAL);
		}
	}

	size_t addr_len = kr_inaddr_len((struct sockaddr *)&sinkhole);
	const uint8_t *raw_addr = (const uint8_t *)kr_inaddr((struct sockaddr *)&sinkhole);
	static knot_rdata_t rdata_arr[RDATA_ARR_MAX];

	knot_wire_set_id(request->answer->wire, msgid);

	if (ipv4)
	{
		kr_pkt_put(request->answer, last->sname, 1, KNOT_CLASS_IN, KNOT_RRTYPE_A, raw_addr, addr_len);
	}
	else
	{
		kr_pkt_put(request->answer, last->sname, 1, KNOT_CLASS_IN, KNOT_RRTYPE_AAAA, raw_addr, addr_len);
	}


	return KNOT_STATE_DONE;
}

static int search(kr_layer_t *ctx, const char * querieddomain, struct ip_addr * origin, struct kr_request * request, struct kr_query * last, char * req_addr, bool ipv4)
{
	//printf("%s.%03d\n", timebuf, millisec);
	char message[KNOT_DNAME_MAXLEN] = {};
	unsigned long long crc = crc64(0, (const unsigned char*)querieddomain, strlen(querieddomain));
	domain domain_item = {};
	if (cache_domain_contains(cached_domain, crc, &domain_item) == 1)
	{
		sprintf(message, "\"message\":\"detected '%s'\"", querieddomain);
		logtosyslog(message);

		iprange iprange_item = {};
		if (cache_iprange_contains(cached_iprange, origin, &iprange_item) == 1)
		{
			sprintf(message, "\"message\":\"detected '%s' matches ip range with ident '%s' policy '%d'\"", querieddomain, iprange_item.identity, iprange_item.policy_id);
			logtosyslog(message);
		}
		else
		{
			sprintf(message, "\"message\":\"detected '%s' does not matches any ip range\"", querieddomain);
			logtosyslog(message);
			iprange_item.identity = "";
			iprange_item.policy_id = 0;
		}

		if (strlen(iprange_item.identity) > 0)
		{
			if (cache_customlist_blacklist_contains(cached_customlist, iprange_item.identity, crc) == 1)
			{
				sprintf(message, "\"message\":\"identity '%s' got '%s' blacklisted.\"", iprange_item.identity, querieddomain);
				logtosyslog(message);
				return redirect(request, last, ipv4, origin);
			}
			if (cache_customlist_whitelist_contains(cached_customlist, iprange_item.identity, crc) == 1)
			{
				sprintf(message, "\"message\":\"identity '%s' got '%s' whitelisted.\"", iprange_item.identity, querieddomain);
				logtosyslog(message);
				return KNOT_STATE_DONE;
			}
		}
		sprintf(message, "\"message\":\"no identity match, checking policy..\"");
		logtosyslog(message);

		policy policy_item = {};
		if (cache_policy_contains(cached_policy, iprange_item.policy_id, &policy_item) == 1)
		{
			int domain_flags = cache_domain_get_flags(domain_item.flags, iprange_item.policy_id);
			if (domain_flags == 0)
			{
				sprintf(message, "\"message\":\"policy has strategy flags_none\"");
				logtosyslog(message);
			}
			if (domain_flags & flags_accuracy)
			{
				if (domain_item.accuracy >= policy_item.block)
				{
					sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"action\":\"block\",\"reason\":\"accuracy\"", iprange_item.policy_id, req_addr, querieddomain);
					logtofile(message);
					logtoaudit(message);

					return redirect(request, last, ipv4, origin);
				}
				else
				{
					if (domain_item.accuracy > policy_item.audit)
					{
						sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"action\":\"audit\",\"reason\":\"accuracy\"", iprange_item.policy_id, req_addr, querieddomain);
						logtofile(message);
						logtoaudit(message);
					}
					else
					{
						sprintf(message, "\"message\":\"policy has no action\"");
						logtosyslog(message);
					}
				}
			}
			if (domain_flags & flags_blacklist)
			{
				sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"action\":\"block\",\"reason\":\"blacklist\"", iprange_item.policy_id, req_addr, querieddomain);
				logtofile(message);
				return redirect(request, last, ipv4, origin);
			}
			if (domain_flags & flags_whitelist)
			{
				sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"action\":\"allow\",\"reason\":\"whitelist\"", iprange_item.policy_id, req_addr, querieddomain);
				logtosyslog(message);
			}
			if (domain_flags & flags_drop)
			{
				sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"action\":\"allow\",\"reason\":\"drop\"", iprange_item.policy_id, req_addr, querieddomain);
				logtosyslog(message);
			}
		}
		else
		{
			sprintf(message, "\"message\":\"cached_policy does not match\"");
			logtosyslog(message);
		}
	}

	return KNOT_STATE_DONE;
}

static int explode(kr_layer_t *ctx, char * domain, struct ip_addr * origin, struct kr_request * request, struct kr_query * last, char * req_addr, bool ipv4)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	char *ptr = domain;
	ptr += strlen(domain);
	int result = ctx->state;
	int found = 0;
	while (ptr-- != (char *)domain)
	{
		if (ptr[0] == '.')
		{
			if (++found > 1)
			{
				sprintf(message, "\"message\":\"search %s\"", ptr + 1);
				logtosyslog(message);
				if ((result = search(ctx, ptr + 1, origin, request, last, req_addr, ipv4)) == KNOT_STATE_DONE)
				{
					return result;
				}
			}
		}
		else
		{
			if (ptr == (char *)domain)
			{
				sprintf(message, "\"message\":\"search %s\"", ptr);
				logtosyslog(message);
				if ((result = search(ctx, ptr, origin, request, last, req_addr, ipv4)) == KNOT_STATE_DONE)
				{
					return result;
				}
			}
		}
	}

	return ctx->state;
}

static int can_satisfy(struct kr_query *qry)
{
	return 0;
}

static int produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	/* Query can be satisfied locally. */
	if (can_satisfy(qry) == 1)
	{

		sprintf(message, "\"message\":\"produce can satisfy\"");
		logtosyslog(message);

		/* This flag makes the resolver move the query
		* to the "resolved" list. */
		qry->flags.RESOLVED = true;
		return KR_STATE_DONE;
	}

	sprintf(message, "\"message\":\"produce can't satisfy\"");
	logtosyslog(message);

	/* Pass-through. */
	return ctx->state;
}

static int finish(kr_layer_t *ctx)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	struct kr_request *request = (struct kr_request *)ctx->req;
	struct kr_rplan *rplan = &request->rplan;

	sprintf(message, "\"message\":\"finish\"");
	logtosyslog(message);

	if (!request->qsource.addr) {
		sprintf(message, "\"message\":\"request has no source address\"");
		logtosyslog(message);

		return ctx->state;
	}

	const struct sockaddr *res = request->qsource.addr;
	char *req_addr = NULL;
	struct ip_addr origin = {};
	bool ipv4 = true;
	switch (res->sa_family) {
	case AF_INET:
	{
		struct sockaddr_in *addr_in = (struct sockaddr_in *)res;
		req_addr = malloc(INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(addr_in->sin_addr), req_addr, INET_ADDRSTRLEN);
		origin.family = AF_INET;
		memcpy(&origin.ipv4_sin_addr, &(addr_in->sin_addr), 4);
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res;
		req_addr = malloc(INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(addr_in6->sin6_addr), req_addr, INET6_ADDRSTRLEN);
		origin.family = AF_INET6;
		memcpy(&origin.ipv6_sin_addr, &(addr_in6->sin6_addr), 16);
		ipv4 = false;
		break;
	}
	default:
	{
		sprintf(message, "\"message\":\"qsource is invalid\"");
		logtosyslog(message);
		return ctx->state;
		break;
	}
	}

	sprintf(message, "\"message\":\"request from %s\"", req_addr);
	logtosyslog(message);

	char qname_str[KNOT_DNAME_MAXLEN];
	if (rplan->resolved.len > 0)
	{
		bool sinkit = false;
		uint16_t rclass = 0;
		struct kr_query *last = array_tail(rplan->resolved);
		const knot_pktsection_t *ns = knot_pkt_section(request->answer, KNOT_ANSWER);

		if (ns == NULL)
		{
			logtosyslog("\"message\":\"ns = NULL\"");
			goto cleanup;
		}

		if (ns->count == 0)
		{
			sprintf(message, "\"message\":\"query has no asnwer\"");
			logtosyslog(message);

			const knot_pktsection_t *au = knot_pkt_section(request->answer, KNOT_AUTHORITY);
			for (unsigned i = 0; i < au->count; ++i)
			{
				const knot_rrset_t *rr = knot_pkt_rr(au, i);

				if (rr->type == KNOT_RRTYPE_SOA)
				{
					char querieddomain[KNOT_DNAME_MAXLEN];
					knot_dname_to_str(querieddomain, rr->owner, KNOT_DNAME_MAXLEN);

					int domainLen = strlen(querieddomain);
					if (querieddomain[domainLen - 1] == '.')
					{
						querieddomain[domainLen - 1] = '\0';
					}

					sprintf(message, "\"message\":\"authority for %s\"", querieddomain);
					logtosyslog(message);

					//ctx->state = explode(ctx, (char *)&querieddomain, &origin, request, last, req_addr);
					//break;
				}
				else
				{
					sprintf(message, "\"message\":\"authority rr type is not SOA [%d]\"", (int)rr->type);
					logtosyslog(message);
				}
			}
		}

		for (unsigned i = 0; i < ns->count; ++i)
		{
			const knot_rrset_t *rr = knot_pkt_rr(ns, i);

			if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA)
			{
				char querieddomain[KNOT_DNAME_MAXLEN];
				knot_dname_to_str(querieddomain, rr->owner, KNOT_DNAME_MAXLEN);

				int domainLen = strlen(querieddomain);
				if (querieddomain[domainLen - 1] == '.')
				{
					querieddomain[domainLen - 1] = '\0';
				}

				sprintf(message, "\"message\":\"query for %s type %d\"", querieddomain, rr->type);
				logtosyslog(message);


				ctx->state = explode(ctx, (char *)&querieddomain, &origin, request, last, req_addr, rr->type == KNOT_RRTYPE_A);
				break;
			}
			else
			{
				sprintf(message, "\"message\":\"rr type is not A or AAAA [%d]\"", (int)rr->type);
				logtosyslog(message);
			}
		}
	}
	else
	{
		sprintf(message, "\"message\":\"query has no resolve plan\"");
		logtosyslog(message);
	}

cleanup:
	free(req_addr);

	return ctx->state;
}

KR_EXPORT
const kr_layer_api_t *whalebone_layer(struct kr_module *module) {
	static kr_layer_api_t _layer = {
			.consume = &consume,
			.produce = &produce,
			.finish = &finish,
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int whalebone_init(struct kr_module *module)
{
	int fd = shm_open("/mutex.whalebone.kres.module", O_CREAT | O_TRUNC | O_RDWR, 0600);
	ftruncate(fd, sizeof(struct shared));

	p = (struct shared*)mmap(0, sizeof(struct shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	p->sharedResource = 0;

	// Make sure it can be shared across processes
	pthread_mutexattr_t shared;
	pthread_mutexattr_init(&shared);
	pthread_mutexattr_setpshared(&shared, PTHREAD_PROCESS_SHARED);

	pthread_mutex_init(&(p->mutex), &shared);

	/* Create a thread and start it in the background. */
	pthread_t thr_id;
	int ret = pthread_create(&thr_id, NULL, &observe, NULL);
	if (ret != 0) {
		return kr_error(errno);
	}

	char msginit[KNOT_DNAME_MAXLEN] = {};
	sprintf(msginit, "\"message\":\"module init\"");
	logtosyslog(msginit);

	/* Keep it in the thread */
	module->data = (void *)thr_id;
	return kr_ok();
}

KR_EXPORT
int whalebone_deinit(struct kr_module *module)
{
	munmap(p, sizeof(struct shared*));
	shm_unlink("/mutex.whalebone.kres.module");

	/* ... signalize cancellation ... */
	void *res = NULL;
	pthread_t thr_id = (pthread_t)module->data;
	int ret = pthread_join(thr_id, res);
	if (ret != 0) {
		return kr_error(errno);
	}

	return kr_ok();
}

KR_MODULE_EXPORT(whalebone)