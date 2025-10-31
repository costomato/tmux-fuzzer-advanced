#include <stddef.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "tmux.h"

#define FUZZER_MAXLEN 512
#define PANE_WIDTH 80
#define PANE_HEIGHT 25

struct event_base *libevent;

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
    const struct options_table_entry *oe;
    struct window *w;
    struct window_pane *wp;
    struct bufferevent *vpty[2];
    int error;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif


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

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        if (len > FUZZER_MAXLEN || len == 0)
            continue;


        w = window_create(PANE_WIDTH, PANE_HEIGHT, 0, 0);
        wp = window_add_pane(w, NULL, 0, 0);
        bufferevent_pair_new(libevent, BEV_OPT_CLOSE_ON_FREE, vpty);
        wp->ictx = input_init(wp, vpty[0], NULL);
        window_add_ref(w, __func__);

        wp->fd = open("/dev/null", O_WRONLY);
        if (wp->fd == -1)
            continue;
        wp->event = bufferevent_new(wp->fd, NULL, NULL, NULL, NULL);


        input_parse_buffer(wp, buf, len);
        

        while (cmdq_next(NULL) != 0)
            ;
        

        error = event_base_loop(libevent, EVLOOP_NONBLOCK);


        assert(w->references == 1);
        window_remove_ref(w, __func__);
        bufferevent_free(vpty[0]);
        bufferevent_free(vpty[1]);
    }

    return 0;
}
