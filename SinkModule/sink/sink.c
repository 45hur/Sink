/* Convenience macro to declare module API. */
#define C_MOD_SINK "\x08""mod-sink"

#include "lib/module.h"
#include <pthread.h>
#include <syslog.h>
#include <lib/rplan.h>

#include "sink.h"

int server()
{
    int socket_desc , new_socket , c , *new_sock;
    struct sockaddr_in server , client;
    char *message;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );
     
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("bind failed");
        return 1;
    }
    puts("bind succeeded");
     
    //Listen
    listen(socket_desc , 3);
     
    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        puts("Connection accepted");
         
        pthread_t sniffer_thread;
        new_sock = malloc(1);
        *new_sock = new_socket;
         
        if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }
         
        //Now join the thread , so that we dont terminate before the thread
        //pthread_join( sniffer_thread , NULL);
        puts("Handler assigned");
    }
     
    if (new_socket<0)
    {
        perror("accept failed");
        return 1;
    }
     
    return 0;
}
 
/*
 * This will handle connection for each client
 * */
void *connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char client_message[4096];
    struct Header header;
    int bytesRead = 0;

    char *bufferPtr = (char *)&header;     
    //Receive a header from client
    while((read_size = recv(sock, client_message, 4096, 0)) > 0)
    {
	bytesRead += read_size;
        memcpy(bufferPtr, client_message, read_size);
	bufferPtr += read_size;
        if (read_size == -1 || read_size == 0 || bytesRead >= 32)
            break; 
    }

    //Send the header response back to client
    uint64_t crc = crc64(0, (const unsigned char *)&header, 24);
    sprintf(client_message, (header.headercrc == crc) ? "1" : "0");
    write(sock , client_message , 1);

    //Receive the message
    char *bufferMsg = (char *)malloc(header.msgsize);
    char *bufferMsgPtr = bufferMsg;
    while( (read_size = recv(sock , client_message , 4096 , 0)) > 0 )
    {
	bytesRead += read_size;
        memcpy(bufferMsgPtr, client_message, read_size);
	bufferMsgPtr += read_size; 

        if (read_size == -1 || read_size == 0 || bytesRead >= header.msgsize)
            break; 
    }

    //Verify and acknowledge the message to the sender
    uint64_t msgcrc = crc64(0, (const unsigned char *)bufferMsg, header.msgsize);
    sprintf(client_message, (header.msgcrc == msgcrc) ? "1" : "0");
    write(sock , client_message , 1);

    //Free the socket pointer
    free(socket_desc);

    if (header.msgcrc == msgcrc)
    {
        //Update the hash table
        if (header.action == 0)
        {
	    hashcontainer_reinit(bufferMsg, (int)header.msgsize / 8);
        }
    }

    return 0;
}

static void* observe(void *arg)
{
    /* ... do some observing ... */
    openlog("sink",  LOG_CONS | LOG_PID, LOG_USER);
    syslog(LOG_INFO, "Loading");
    closelog();

    hashcontainer_init();
    server();

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