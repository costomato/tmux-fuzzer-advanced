/*
 * Persistent mode fuzzer for tmux input parser
 * This is MUCH faster than the original
 */

#include <stddef.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 512
#define PANE_WIDTH 80
#define PANE_HEIGHT 25

struct event_base *libevent;
static struct window *global_w = NULL;
static struct window_pane *global_wp = NULL;
static struct bufferevent *global_vpty[2];

// Initialize once
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
    options_set_number(global_w_options, "monitor-bell", 0);
    options_set_number(global_w_options, "allow-rename", 1);
    options_set_number(global_options, "set-clipboard", 2);
    socket_path = xstrdup("dummy");

    // Create window once
    global_w = window_create(PANE_WIDTH, PANE_HEIGHT, 0, 0);
    global_wp = window_add_pane(global_w, NULL, 0, 0);
    bufferevent_pair_new(libevent, BEV_OPT_CLOSE_ON_FREE, global_vpty);
    global_wp->ictx = input_init(global_wp, global_vpty[0], NULL);
    window_add_ref(global_w, __func__);

    global_wp->fd = open("/dev/null", O_WRONLY);
    if (global_wp->fd == -1)
        errx(1, "open(\"/dev/null\") failed");
    global_wp->event = bufferevent_new(global_wp->fd, NULL, NULL, NULL, NULL);

    return 0;
}

// This runs in a loop - MUCH faster!
int LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
    int error;

    if (size > FUZZER_MAXLEN)
        return 0;

    // Reset input context state
    input_reset(global_wp, 0);
    
    // Parse the input
    input_parse_buffer(global_wp, (u_char *)data, size);
    
    // Process any queued commands
    while (cmdq_next(NULL) != 0)
        ;
    
    // Run event loop
    error = event_base_loop(libevent, EVLOOP_NONBLOCK);
    if (error == -1)
        errx(1, "event_base_loop failed");

    return 0;
}
