
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 2048

struct event_base *libevent;
static struct client *c;
static struct session *s;
static struct cmdq_item *item;

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
    
    c = xcalloc(1, sizeof *c);
    c->flags = 0;
    
    s = session_create(NULL, "fuzz", NULL, global_environ, global_s_options, NULL);
    
    return 0;
}

int LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
    struct cmd_parse_result *pr;
    struct cmd_list *cmdlist;
    char *input;
    
    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;
    

    input = malloc(size + 1);
    if (input == NULL)
        return 0;
    memcpy(input, data, size);
    input[size] = '\0';
    

    pr = cmd_parse_from_string(input, NULL);
    free(input);
    
    if (pr->status != CMD_PARSE_SUCCESS) {

        if (pr->error != NULL)
            free(pr->error);
        return 0;
    }
    

    cmdlist = pr->cmdlist;
    if (cmdlist != NULL) {
        item = cmdq_get_command(cmdlist, NULL);
        if (item != NULL) {
            cmdq_append(c, item);

            while (cmdq_next(c) != 0)
                ;
        }
        cmd_list_free(cmdlist);
    }
    
    return 0;
}
