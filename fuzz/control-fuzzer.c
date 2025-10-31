/*
 * Fuzzer for tmux control mode
 * Targets: control.c and control protocol parsing
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 4096

struct event_base *libevent;
static struct client *c;

int LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
    const struct options_table_entry *oe;

    global_environ = environ_create();
    global_options = options_create(NULL);
    global_s_options = options_create(NULL);
    global_w_options = options_create(NULL);
    
    for (oe = options_table; oe->name != NULL; oe++) {
        if (oe->scope & OPTIONS_TABLE_SERVER)
            options_default(global_options, oe);
        if (oe->scope & OPTIONS_TABLE_SESSION)
            options_default(global_s_options, oe);
        if (oe->scope & OPTIONS_TABLE_WINDOW)
            options_default(global_w_options, oe);
    }
    
    libevent = osdep_event_init();
    socket_path = xstrdup("dummy");
    
    // Create control mode client
    c = xcalloc(1, sizeof *c);
    c->flags = CLIENT_CONTROL;
    c->peer = NULL;
    
    return 0;
}

int LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
    struct evbuffer *evb;
    
    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;
    
    // Create buffer with fuzzing data
    evb = evbuffer_new();
    if (evb == NULL)
        return 0;
    
    evbuffer_add(evb, data, size);
    
    // Process control mode input
    control_write(c, "%.*s", (int)size, data);
    
    // Drain any output
    while (cmdq_next(c) != 0)
        ;
    
    evbuffer_free(evb);
    
    return 0;
}
