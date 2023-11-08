#ifndef _LOCAL_H
#define _LOCAL_H
#ifdef __cplusplus
extern "C" {
#endif
#include <libcork/ds.h>
#include <libev/ev.h>

#include "samapacket.h"
#ifdef __MINGW32__
#include "winsock.h"
#endif
#if 0
#include "src/ssr_utils.h"
#include "src/netutils.h"
#include "src/utils.h"
#include "src/socks5.h"
#include "src/acl.h"
#include "src/plugin.h"
#include <libcork/ds.h>
#include <libev/ev.h>
#include "src/crypto.h"
#include "src/jconf.h"
#include "src/common.h"
#include "src/winsock.h"
//#include "src/stream.h"
#endif
#include "src/crypto.h"
#include "src/jconf.h"

#include "src/common.h"
#ifdef __cplusplus
}
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

typedef struct listen_ctx {
    ev_io io;
    char *iface;
    int timeout;
    int fd;
    int mptcp;
    int auditor_num;
    struct sockaddr **auditor_addr;
    int worker_num;
    struct sockaddr **worker_addr;
} listen_ctx_t;

typedef struct server_ctx {
    ev_io io;
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct server {
    int fd;
    int stage;

    cipher_ctx_t *e_ctx_r;
    cipher_ctx_t *e_ctx_s;
    cipher_ctx_t *d_ctx_s;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listener;
    struct remote *remote;

    buffer_t *buf;
    buffer_t *abuf;
    buffer_t *routerdata;

    ev_timer delayed_connect_watcher;

    struct cork_dllist_item entries;
} server_t;

typedef struct remote_ctx {
    ev_io io;
    ev_timer watcher;

    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
    int direct;
    int addr_len;
    uint32_t counter;
#ifdef TCP_FASTOPEN_WINSOCK
    OVERLAPPED olap;
    int connect_ex_done;
#endif

    int _has_sent;
    buffer_t *buf;

    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
    struct sockaddr_storage addr;
} remote_t;

#endif // _LOCAL_H
