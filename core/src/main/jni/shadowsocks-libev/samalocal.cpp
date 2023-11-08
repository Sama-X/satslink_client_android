/*
 * local.c - Setup a socks5 proxy through remote shadowsocks server
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#endif
#ifdef LIB_ONLY
#include "shadowsocks.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif
extern "C" {
//#include <libcork/core.h>

#include "src/netutils.h"
#include "src/utils.h"
#include "src/socks5.h"
#include "src/acl.h"
#include "src/plugin.h"
//#include "src/local.h"
#include "src/winsock.h"
}

#include <string>
#include "common/GlobalOperate.h"
#include "common/encode.h"
#include "common/NodeInfo.h"
#include "ServiceLocal.h"

#ifndef LIB_ONLY
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if defined(MAC_OS_X_VERSION_10_10) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10
#include <launch.h>
#define HAVE_LAUNCHD
#endif
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

int verbose    = 0;
int reuse_port = 0;

#ifdef __ANDROID__
int vpn        = 1;
//int android_vpn = 1;
uint64_t tx    = 0;
uint64_t rx    = 0;
ev_tstamp last = 0;

char *stat_path   = NULL;
#endif

static crypto_t *crypto;

static int acl       = 0;
static int mode      = TCP_ONLY;
static int ipv6first = 0;
int fast_open        = 0;
static int no_delay  = 0;
static int udp_fd    = 0;
static int ret_val   = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_async ev_stop_watch;
static struct ev_async ev_quit_watch;
static struct ev_async ev_update_node_watch;
#ifndef __MINGW32__
static struct ev_signal sigchld_watcher;
static struct ev_signal sigusr1_watcher;
#else
#ifndef LIB_ONLY
static struct plugin_watcher_t {
    ev_io io;
    SOCKET fd;
    uint16_t port;
    int valid;
} plugin_watcher;
#endif
#endif

#ifdef HAVE_SETRLIMIT
#ifndef LIB_ONLY
static int nofile = 0;
#endif
#endif

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void signal_cb(EV_P_ ev_signal *w, int revents);
#if defined(__MINGW32__) && !defined(LIB_ONLY)
static void plugin_watcher_cb(EV_P_ ev_io *w, int revents);
#endif

static int create_and_bind(const char *addr, const char *port);
#ifdef HAVE_LAUNCHD
static int launch_or_create(const char *addr, const char *port);
#endif
static remote_t *create_remote(listen_ctx_t *listener, struct sockaddr *addr, int direct);
static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);

class SS_NodeInfo
{
public:
    SS_NodeInfo() {}
    ~SS_NodeInfo() {}
public:
    void setBase(const sama::business::CNodeInfo& info) {
        release();
        baseInfo.assign(info);
        if(6 == info.m_nIdentity) {
            crypto = crypto_init(info.strEcdh.c_str(), 0, "chacha20-ietf-poly1305");
        }
        else if(7 == info.m_nIdentity) {
            crypto = crypto_init(info.strEcdh.c_str(), 0, "aes-128-cfb");
        }
    }
    void release() {
        if(0 != crypto){
            ss_free(crypto);
            crypto = 0;
        }
    }
public:
    sama::business::CNodeInfo baseInfo;
    crypto_t *crypto = 0;
};

SS_NodeInfo g_AuditorNodeInfo;
SS_NodeInfo g_WorkerNodeInfo;
char g_chMyPubKey[33];
bool g_bDirectServer = false;
struct ev_loop *g_loop = nullptr;
listen_ctx_t listen_ctx;
#pragma pack(1)
struct RouterHeaderSamaIpv4
{
    char ipinfo;    //1 for ipv4 2 for ipv6
    unsigned int ip;
    unsigned short port;
    char serPubKeyHash[32];
};
#pragma pack()

#pragma pack(1)
struct RouterHeaderSamaIpv6
{
    char ipinfo;    //1 for ipv4 2 for ipv6
    char ip[16];
    unsigned short port;
    char serPubKeyHash[32];
};
#pragma pack()


static void MakeSeverInfo2Router(remote_t *remote, server_t *server, buffer_t* buf)
{
    if(remote->_has_sent == 1)
    {
        return;
    }
    remote->_has_sent = 1;
    const char* pubKey = g_chMyPubKey;
    int tmpLen = (int)remote->buf->len;
    if(!g_bDirectServer)
    {
        SAMA_Packet_Auditor(1, pubKey, server->routerdata->data, server->routerdata->len, remote->buf->data, &tmpLen);
    }
    else
    {
        SAMA_Packet_Worker(1, pubKey, remote->buf->data, &tmpLen);
    }
    remote->buf->len = (size_t)tmpLen;
}

static struct cork_dllist connections;

#ifndef __MINGW32__
int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#endif

int
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    result            = NULL;

    s = getaddrinfo(addr, port, &hints, &result);

    if (s != 0) {
        LOGI("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        if (reuse_port) {
            int err = set_reuseport(listen_sock);
            if (err == 0) {
                LOGI("tcp port reuse enabled");
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
        listen_sock = -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

#ifdef HAVE_LAUNCHD
int
launch_or_create(const char *addr, const char *port)
{
    int *fds;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &fds, &cnt);
    if (error == 0) {
        if (cnt == 1) {
            return fds[0];
        } else {
            FATAL("please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /* ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *          in the caller's launchd.plist(5).
         */
        if (port == NULL) {
            usage();
            exit(EXIT_FAILURE);
        }
        return create_and_bind(addr, port);
    } else {
        FATAL("launch_activate_socket() error");
    }
    return -1;
}

#endif
#define cork_container_of_ex(field, struct_type, field_name) ((struct_type *) (- offsetof(struct_type, field_name) +  (char*)(field)))
static void
free_connections(struct ev_loop *loop)
{
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(&connections, curr, next) {
        server_t *server = cork_container_of_ex(curr, server_t, entries);
        remote_t *remote = server->remote;
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
    }
}

static void
delayed_connect_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_t *server = cork_container_of_ex(watcher, server_t,
                                         delayed_connect_watcher);

    server_recv_cb(EV_A_ & server->recv_ctx->io, revents);
}

static int
server_handshake_reply(EV_P_ ev_io *w, int udp_assc, struct socks5_response *response)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    if (server->stage != STAGE_HANDSHAKE)
        return 0;

    struct sockaddr_in sock_addr;
    if (udp_assc) {
        socklen_t addr_len = sizeof(sock_addr);
        if (getsockname(server->fd, (struct sockaddr *)&sock_addr, &addr_len) < 0) {
            LOGE("getsockname: %s", strerror(errno));
            response->rep = SOCKS5_REP_CONN_REFUSED;
            send(server->fd, (char *)response, sizeof(struct socks5_response), 0);
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return -1;
        }
    } else
        memset(&sock_addr, 0, sizeof(sock_addr));

    buffer_t resp_to_send;
    buffer_t *resp_buf = &resp_to_send;
    balloc(resp_buf, SOCKET_BUF_SIZE);

    memcpy(resp_buf->data, response, sizeof(struct socks5_response));
    memcpy(resp_buf->data + sizeof(struct socks5_response),
           &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
    memcpy(resp_buf->data + sizeof(struct socks5_response) +
           sizeof(sock_addr.sin_addr),
           &sock_addr.sin_port, sizeof(sock_addr.sin_port));

    int reply_size = sizeof(struct socks5_response) +
                     sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);

    int s = send(server->fd, resp_buf->data, reply_size, 0);

    bfree(resp_buf);

    if (s < reply_size) {
        LOGE("failed to send fake reply");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return -1;
    }
    if (udp_assc) {
        // Wait until client closes the connection
        return -1;
    }
    return 0;
}

static int
server_handshake(EV_P_ ev_io *w, buffer_t *buf)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    struct socks5_request *request = (struct socks5_request *)buf->data;
    size_t request_len             = sizeof(struct socks5_request);

    if (buf->len < request_len) {
        return -1;
    }

    struct socks5_response response;
    response.ver  = SVERSION;
    response.rep  = SOCKS5_REP_SUCCEEDED;
    response.rsv  = 0;
    response.atyp = SOCKS5_ATYP_IPV4;

    if (request->cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
        if (verbose) {
            LOGI("udp assc request accepted");
        }
        return server_handshake_reply(EV_A_ w, 1, &response);
    } else if (request->cmd != SOCKS5_CMD_CONNECT) {
        LOGE("unsupported command: %d", request->cmd);
        response.rep = SOCKS5_REP_CMD_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, 4, 0);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return -1;
    }

    char host[MAX_HOSTNAME_LEN + 1], ip[INET6_ADDRSTRLEN], port[16];
    memset(port, 0, 16);

    buffer_t *abuf = server->abuf;
    abuf->idx = 0;
    abuf->len = 0;

    abuf->data[abuf->len++] = request->atyp;
    int atyp = request->atyp;

    // get remote addr and port
    if (atyp == SOCKS5_ATYP_IPV4) {
        size_t in_addr_len = sizeof(struct in_addr);
        if (buf->len < request_len + in_addr_len + 2) {
            return -1;
        }
        memcpy(abuf->data + abuf->len, buf->data + request_len, in_addr_len + 2);
        abuf->len += in_addr_len + 2;

        if (acl || verbose) {
            uint16_t p = load16_be(buf->data + request_len + in_addr_len);
            if (!inet_ntop(AF_INET, (const void *)(buf->data + request_len),
                           ip, INET_ADDRSTRLEN)) {
                LOGI("inet_ntop(AF_INET): %s", strerror(errno));
                ip[0] = '\0';
            }
            sprintf(port, "%d", p);
        }
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        uint8_t name_len = *(uint8_t *)(buf->data + request_len);
        if (buf->len < request_len + 1 + name_len + 2) {
            return -1;
        }
        abuf->data[abuf->len++] = name_len;
        memcpy(abuf->data + abuf->len, buf->data + request_len + 1, name_len + 2);
        abuf->len += name_len + 2;

        if (acl || verbose) {
            uint16_t p = load16_be(buf->data + request_len + 1 + name_len);
            memcpy(host, buf->data + request_len + 1, name_len);
            host[name_len] = '\0';
            sprintf(port, "%d", p);
        }
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (buf->len < request_len + in6_addr_len + 2) {
            return -1;
        }
        memcpy(abuf->data + abuf->len, buf->data + request_len, in6_addr_len + 2);
        abuf->len += in6_addr_len + 2;

        if (acl || verbose) {
            uint16_t p = load16_be(buf->data + request_len + in6_addr_len);
            if (!inet_ntop(AF_INET6, (const void *)(buf->data + request_len),
                           ip, INET6_ADDRSTRLEN)) {
                LOGI("inet_ntop(AF_INET6): %s", strerror(errno));
                ip[0] = '\0';
            }
            sprintf(port, "%d", p);
        }
    } else {
        LOGE("unsupported addrtype: %d", request->atyp);
        response.rep = SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, 4, 0);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return -1;
    }

    if (server_handshake_reply(EV_A_ w, 0, &response) < 0)
        return -1;
    server->stage = STAGE_STREAM;

    buf->len -= (3 + abuf->len);
    if (buf->len > 0) {
        memmove(buf->data, buf->data + 3 + abuf->len, buf->len);
    }

    if (verbose) {
        if (atyp == SOCKS5_ATYP_DOMAIN)
            LOGI("connect to %s:%s", host, port);
        else if (atyp == SOCKS5_ATYP_IPV4)
            LOGI("connect to %s:%s", ip, port);
        else if (atyp == SOCKS5_ATYP_IPV6)
            LOGI("connect to [%s]:%s", ip, port);
    }

    if (acl
#ifdef __ANDROID__
        && !(vpn && strcmp(port, "53") == 0)
#endif
        ) {
        int bypass   = 0;
        int resolved = 0;
        struct sockaddr_storage storage;
        memset(&storage, 0, sizeof(struct sockaddr_storage));
        int err;

        int host_match = 0;
        if (atyp == SOCKS5_ATYP_DOMAIN)
            host_match = acl_match_host(host);

        if (host_match > 0)
            bypass = 1;                             // bypass hostnames in black list
        else if (host_match < 0)
            bypass = 0;                             // proxy hostnames in white list
        else {
            if (atyp == SOCKS5_ATYP_DOMAIN
#ifdef __ANDROID__
                && !vpn
#endif
                ) {           // resolve domain so we can bypass domain with geoip
                if (get_sockaddr(host, port, &storage, 0, ipv6first))
                    goto not_bypass;
                resolved = 1;
                switch (((struct sockaddr *)&storage)->sa_family) {
                case AF_INET:
                {
                    struct sockaddr_in *addr_in = (struct sockaddr_in *)&storage;
                    if (!inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN))
                        goto not_bypass;
                    break;
                }
                case AF_INET6:
                {
                    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&storage;
                    if (!inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN))
                        goto not_bypass;
                    break;
                }
                default:
                    goto not_bypass;
                }
            }

            int ip_match = (resolved || atyp == SOCKS5_ATYP_IPV4
                            || atyp == SOCKS5_ATYP_IPV6) ? acl_match_host(ip) : 0;

            switch (get_acl_mode()) {
            case BLACK_LIST:
                if (ip_match > 0)
                    bypass = 1;                                               // bypass IPs in black list
                break;
            case WHITE_LIST:
                bypass = 1;
                if (ip_match < 0)
                    bypass = 0;                                               // proxy IPs in white list
                break;
            }
        }

        if (bypass) {
            if (verbose) {
                if (atyp == SOCKS5_ATYP_DOMAIN)
                    LOGI("bypass %s:%s", host, port);
                else if (atyp == 1)
                    LOGI("bypass %s:%s", ip, port);
                else if (atyp == 4)
                    LOGI("bypass [%s]:%s", ip, port);
            }
            if (atyp == SOCKS5_ATYP_DOMAIN && !resolved)
#ifdef __ANDROID__
                if (vpn)
                    goto not_bypass;
                else
#endif
                err = get_sockaddr(host, port, &storage, 0, ipv6first);
            else
                err = get_sockaddr(ip, port, &storage, 0, ipv6first);
            if (err != -1) {
                remote = create_remote(server->listener, (struct sockaddr *)&storage, 1);
            }
        }
    }

not_bypass:
    // Not bypass
    if (remote == NULL) {
        remote = create_remote(server->listener, NULL, 0);
    }

    if (remote == NULL) {
        LOGE("invalid remote addr");
        close_and_free_server(EV_A_ server);
        return -1;
    }

    if (!remote->direct) {
        int err = g_WorkerNodeInfo.crypto->encrypt(abuf, server->e_ctx_s, SOCKET_BUF_SIZE);
        if (err) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return -1;
        }
    }

    if (buf->len > 0) {
        memcpy(remote->buf->data, buf->data, buf->len);
        remote->buf->len = buf->len;
    }

    server->remote = remote;
    remote->server = server;

    if (buf->len > 0) {
        return 0;
    } else {
        ev_timer_start(EV_A_ & server->delayed_connect_watcher);
    }

    return -1;
}

static void
server_stream(EV_P_ ev_io *w, buffer_t *buf)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    if (remote == NULL) {
        LOGE("invalid remote");
        close_and_free_server(EV_A_ server);
        return;
    }

    // insert shadowsocks header
    if (!remote->direct) {
#ifdef __ANDROID__
        tx += remote->buf->len;
#endif
        int err = g_WorkerNodeInfo.crypto->encrypt(remote->buf, server->e_ctx_s, SOCKET_BUF_SIZE);

        if (err) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        if (server->abuf) {
            bprepend(remote->buf, server->abuf, SOCKET_BUF_SIZE);
            bfree(server->abuf);
            ss_free(server->abuf);
            server->abuf = NULL;
        }
    }

    MakeSeverInfo2Router(remote, server, remote->buf);
    if (!remote->send_ctx->connected) {
#ifdef __ANDROID__
        if (vpn) {
            int not_protect = 0;
            if (remote->addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&remote->addr;
                if (s->sin_addr.s_addr == inet_addr("127.0.0.1"))
                    not_protect = 1;
            }
            LOGE("not_protect:%d\n", not_protect);
            if (!not_protect) {
                if (protect_socket(remote->fd) == -1) {
                    LOGE("not_protect error:%d\n", not_protect);
                    ERROR("protect_socket");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }
        }
#endif

        remote->buf->idx = 0;

        if (!fast_open || remote->direct) {
            // connecting, wait until connected
            int r = connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);

            if (r == -1 && errno != CONNECT_IN_PROGRESS) {
                ERROR("connect");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            // wait on remote connected event
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
            ev_timer_start(EV_A_ & remote->send_ctx->watcher);
        } else {
#if defined(MSG_FASTOPEN) && !defined(TCP_FASTOPEN_CONNECT)
            int s = -1;
            s = sendto(remote->fd, remote->buf->data, remote->buf->len, MSG_FASTOPEN,
                       (struct sockaddr *)&(remote->addr), remote->addr_len);
#elif defined(TCP_FASTOPEN_WINSOCK)
            DWORD s   = -1;
            DWORD err = 0;
            do {
                int optval = 1;
                // Set fast open option
                if (setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN,
                               &optval, sizeof(optval)) != 0) {
                    ERROR("setsockopt");
                    break;
                }
                // Load ConnectEx function
                LPFN_CONNECTEX ConnectEx = winsock_getconnectex();
                if (ConnectEx == NULL) {
                    LOGE("Cannot load ConnectEx() function");
                    err = WSAENOPROTOOPT;
                    break;
                }
                // ConnectEx requires a bound socket
                if (winsock_dummybind(remote->fd,
                                      (struct sockaddr *)&(remote->addr)) != 0) {
                    ERROR("bind");
                    break;
                }
                // Call ConnectEx to send data
                memset(&remote->olap, 0, sizeof(remote->olap));
                remote->connect_ex_done = 0;
                if (ConnectEx(remote->fd, (const struct sockaddr *)&(remote->addr),
                              remote->addr_len, remote->buf->data, remote->buf->len,
                              &s, &remote->olap)) {
                    remote->connect_ex_done = 1;
                    break;
                }
                // XXX: ConnectEx pending, check later in remote_send
                if (WSAGetLastError() == ERROR_IO_PENDING) {
                    err = CONNECT_IN_PROGRESS;
                    break;
                }
                ERROR("ConnectEx");
            } while (0);
            // Set error number
            if (err) {
                SetLastError(err);
            }
#else
            int s = -1;
#if defined(CONNECT_DATA_IDEMPOTENT)
            ((struct sockaddr_in *)&(remote->addr))->sin_len = sizeof(struct sockaddr_in);
            sa_endpoints_t endpoints;
            memset((char *)&endpoints, 0, sizeof(endpoints));
            endpoints.sae_dstaddr    = (struct sockaddr *)&(remote->addr);
            endpoints.sae_dstaddrlen = remote->addr_len;

            s = connectx(remote->fd, &endpoints, SAE_ASSOCID_ANY,
                         CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                         NULL, 0, NULL, NULL);
#elif defined(TCP_FASTOPEN_CONNECT)
            int optval = 1;
            if (setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                           (void *)&optval, sizeof(optval)) < 0)
                FATAL("failed to set TCP_FASTOPEN_CONNECT");
            s = connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);
#else
            FATAL("fast open is not enabled in this build");
#endif
            if (s == 0)
                s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
#endif
            if (s == -1) {
                if (errno == CONNECT_IN_PROGRESS) {
                    // in progress, wait until connected
                    remote->buf->idx = 0;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    return;
                } else {
                    if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                        errno == ENOPROTOOPT) {
                        LOGE("fast open is not supported on this platform");
                        // just turn it off
                        fast_open = 0;
                    } else {
                        ERROR("fast_open_connect");
                    }
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            } else {
                remote->buf->len -= s;
                remote->buf->idx  = s;

                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
                ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                return;
            }
        }
    } else {
        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf->idx = 0;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
                return;
            } else {
                ERROR("server_recv_cb_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        } else if (s < (int)(remote->buf->len)) {
            remote->buf->len -= s;
            remote->buf->idx  = s;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
            return;
        } else {
            remote->buf->idx = 0;
            remote->buf->len = 0;
        }
    }
}

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    buffer_t *buf;
    ssize_t r;

    ev_timer_stop(EV_A_ & server->delayed_connect_watcher);

    if (remote == NULL) {
        buf = server->buf;
    } else {
        buf = remote->buf;
    }

    if (revents != EV_TIMER) {
        r = recv(server->fd, buf->data + buf->len, SOCKET_BUF_SIZE - buf->len, 0);

        if (r == 0) {
            // connection closed
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        } else if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data
                // continue to wait for recv
                return;
            } else {
                if (verbose)
                    ERROR("server_recv_cb_recv");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
        buf->len += r;
    }

    while (1) {
        // local socks5 server
        if (server->stage == STAGE_STREAM) {
            server_stream(EV_A_ w, buf);

            // all processed
            return;
        } else if (server->stage == STAGE_INIT) {
            if (verbose) {
                struct sockaddr_in peer_addr;
                socklen_t peer_addr_len = sizeof peer_addr;
                if (getpeername(server->fd, (struct sockaddr *)&peer_addr, &peer_addr_len) == 0) {
                    LOGI("connection from %s:%hu", inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
                }
            }
            if (buf->len < 1)
                return;
            if (buf->data[0] != SVERSION) {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
            if (buf->len < sizeof(struct method_select_request)) {
                return;
            }
            struct method_select_request *method = (struct method_select_request *)buf->data;
            int method_len                       = method->nmethods + sizeof(struct method_select_request);
            if (buf->len < method_len) {
                return;
            }

            struct method_select_response response;
            response.ver    = SVERSION;
            response.method = METHOD_UNACCEPTABLE;
            for (int i = 0; i < method->nmethods; i++)
                if (method->methods[i] == METHOD_NOAUTH) {
                    response.method = METHOD_NOAUTH;
                    break;
                }
            char *send_buf = (char *)&response;
            send(server->fd, send_buf, sizeof(response), 0);
            if (response.method == METHOD_UNACCEPTABLE) {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            server->stage = STAGE_HANDSHAKE;

            if (method_len < (int)(buf->len)) {
                memmove(buf->data, buf->data + method_len, buf->len - method_len);
                buf->len -= method_len;
                continue;
            }

            buf->len = 0;
            return;
        } else if (server->stage == STAGE_HANDSHAKE) {
            int ret = server_handshake(EV_A_ w, buf);
            if (ret)
                return;
        }
    }
}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_cb_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t)(server->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
            return;
        }
    }
}

#ifdef __ANDROID__
extern "C" void
stat_update_cb()
{
    ev_tstamp now = ev_time();
    if (now - last > 0.5) {
        send_traffic_stat(tx, rx);
        last = now;
    }
}

#endif

static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx
        = cork_container_of_ex(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote_recv_cb_recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;

    if (!remote->direct) {
#ifdef __ANDROID__
        rx += server->buf->len;
        stat_update_cb();
#endif
        int err = g_WorkerNodeInfo.crypto->decrypt(server->buf, server->d_ctx_s, SOCKET_BUF_SIZE);
        if (err == CRYPTO_ERROR) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        } else if (err == CRYPTO_NEED_MORE) {
            return; // Wait for more
        }
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_cb_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < (int)(server->buf->len)) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes;
                DWORD flags;
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                                           &numBytes, FALSE, &flags)) {
                    remote->buf->len       -= numBytes;
                    remote->buf->idx        = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                           SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r         = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
            ev_io_start(EV_A_ & remote->recv_ctx->io);

            // no need to send any data
            if (remote->buf->len == 0) {
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                return;
            }
        } else {
            // not connected
            ERROR("getpeername");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        MakeSeverInfo2Router(remote, server, remote->buf);
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t)(remote->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_t *remote;
    remote = (remote_t *)ss_malloc(sizeof(remote_t));

    memset(remote, 0, sizeof(remote_t));

    remote->buf      = (buffer_t *)ss_malloc(sizeof(buffer_t));
    remote->recv_ctx = (remote_ctx *)ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = (remote_ctx *)ss_malloc(sizeof(remote_ctx_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

static server_t *
new_server(int fd)
{
    server_t *server;
    server = (server_t*)ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx = (server_ctx*)ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = (server_ctx*)ss_malloc(sizeof(server_ctx_t));
    server->buf      = (buffer_t*)ss_malloc(sizeof(buffer_t));
    server->abuf     = (buffer_t*)ss_malloc(sizeof(buffer_t));
    server->routerdata     = (buffer_t*)ss_malloc(sizeof(buffer_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    balloc(server->abuf, SOCKET_BUF_SIZE);
    balloc(server->routerdata, SOCKET_BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    server->stage               = STAGE_INIT;
    server->recv_ctx->connected = 0;
    server->send_ctx->connected = 0;
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->send_ctx->server    = server;

    server->e_ctx_r = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
    server->e_ctx_s = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx_s = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
    g_AuditorNodeInfo.crypto->ctx_init(g_AuditorNodeInfo.crypto->cipher, server->e_ctx_r, 1);
    g_WorkerNodeInfo.crypto->ctx_init(g_WorkerNodeInfo.crypto->cipher, server->e_ctx_s, 1);
    g_WorkerNodeInfo.crypto->ctx_init(g_WorkerNodeInfo.crypto->cipher, server->d_ctx_s, 0);

    if(!g_bDirectServer)
    {
        if(g_WorkerNodeInfo.baseInfo.bIpV4)
        {
            RouterHeaderSamaIpv4 rhs4;
            rhs4.ipinfo = 1;
            rhs4.ip = g_WorkerNodeInfo.baseInfo.nIpv4;
            rhs4.port = g_WorkerNodeInfo.baseInfo.getRandomWorkPort2();
            memcpy(rhs4.serPubKeyHash, g_WorkerNodeInfo.baseInfo.strPubKeySha256, 32);
            server->routerdata->len = sizeof(rhs4);
            memcpy(server->routerdata->data, &rhs4, server->routerdata->len);
        }
        else
        {
            RouterHeaderSamaIpv6 rhs6;
            rhs6.ipinfo = 2;
            memcpy(rhs6.ip, g_WorkerNodeInfo.baseInfo.chIpv6, 16);
            rhs6.port = g_WorkerNodeInfo.baseInfo.getRandomWorkPort2();
            memcpy(rhs6.serPubKeyHash, g_WorkerNodeInfo.baseInfo.strPubKeySha256, 32);
            server->routerdata->len = sizeof(rhs6);
            memcpy(server->routerdata->data, &rhs6, server->routerdata->len);
        }
        g_AuditorNodeInfo.crypto->encrypt(server->routerdata, server->e_ctx_r, SOCKET_BUF_SIZE);
    }

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

    ev_timer_init(&server->delayed_connect_watcher, delayed_connect_cb, 0.05, 0);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void
free_server(server_t *server)
{
    cork_dllist_remove(&server->entries);

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx_r != NULL) {
        g_AuditorNodeInfo.crypto->ctx_release(server->e_ctx_r);
        ss_free(server->e_ctx_r);
    }
    if (server->e_ctx_s != NULL) {
        g_WorkerNodeInfo.crypto->ctx_release(server->e_ctx_s);
        ss_free(server->e_ctx_s);
    }
    if (server->d_ctx_s != NULL) {
        g_WorkerNodeInfo.crypto->ctx_release(server->d_ctx_s);
        ss_free(server->d_ctx_s);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    if (server->abuf != NULL) {
        bfree(server->abuf);
        ss_free(server->abuf);
    }
    if (server->routerdata != NULL) {
        bfree(server->routerdata);
        ss_free(server->routerdata);
    }
    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->delayed_connect_watcher);
        close(server->fd);
        free_server(server);
    }
}
static void printSocketAddress(struct sockaddr_storage *addr) {
    char ipstr[46] = {0};
    int port = 0;
    if (addr->ss_family == AF_INET) {
        // IPv4
        struct sockaddr_in *s = (struct sockaddr_in *) addr;
        port = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
    } else { // AF_INET6
        // IPv6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *) addr;
        port = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
    }
    LOGI("IP address:%s,port: %d\n", ipstr, port);
}
static remote_t *
create_remote(listen_ctx_t *listener,
              struct sockaddr *addr,
              int direct)
{
    struct sockaddr *remote_addr;

    if(g_bDirectServer)
    {
        int index = rand() % listener->worker_num;
        if (addr == NULL) {
            remote_addr = listener->worker_addr[index];
        } else {
            remote_addr = addr;
        }
    }
    else
    {
        int index = rand() % listener->auditor_num;
        if (addr == NULL) {
            remote_addr = listener->auditor_addr[index];
        } else {
            remote_addr = addr;
        }
    }

    int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

    if (remotefd == -1) {
        ERROR("socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (listener->mptcp > 1) {
        int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable multipath TCP");
        }
    } else if (listener->mptcp == 1) {
        int i = 0;
        while ((listener->mptcp = mptcp_enabled_values[i]) > 0) {
            int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
            if (err != -1) {
                break;
            }
            i++;
        }
        if (listener->mptcp == 0) {
            ERROR("failed to enable multipath TCP");
        }
    }

    // Setup
    setnonblocking(remotefd);
#ifdef SET_INTERFACE
    if (listener->iface) {
        if (setinterface(remotefd, listener->iface) == -1)
            ERROR("setinterface");
    }
#endif

    remote_t *remote = new_remote(remotefd, direct ? MAX_CONNECT_TIMEOUT : listener->timeout);
    remote->addr_len = get_sockaddr_len(remote_addr);
    memcpy(&(remote->addr), remote_addr, remote->addr_len);
    remote->direct = direct;

    if (verbose) {
        struct sockaddr_in *sockaddr = (struct sockaddr_in *)&remote->addr;
        LOGI("remote: %s:%hu", inet_ntoa(sockaddr->sin_addr), ntohs(sockaddr->sin_port));
    }

    return remote;
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
#ifndef __MINGW32__
        case SIGCHLD:
            if (!is_plugin_running()) {
                LOGE("plugin service exit unexpectedly");
                ret_val = -1;
            } else
                return;
        case SIGUSR1:
#endif
        case SIGINT:
        case SIGTERM:
            ev_async_stop(EV_DEFAULT, &ev_stop_watch);
            ev_async_stop(EV_DEFAULT, &ev_quit_watch);
            ev_async_stop(EV_DEFAULT, &ev_update_node_watch);
            ev_signal_stop(EV_DEFAULT, &sigint_watcher);
            ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
            ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
            ev_signal_stop(EV_DEFAULT, &sigusr1_watcher);
#else
#ifndef LIB_ONLY
            ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
#endif
#endif
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

#if defined(__MINGW32__) && !defined(LIB_ONLY)
static void
plugin_watcher_cb(EV_P_ ev_io *w, int revents)
{
    char buf[1];
    SOCKET fd = accept(plugin_watcher.fd, NULL, NULL);
    if (fd == INVALID_SOCKET) {
        return;
    }
    recv(fd, buf, 1, 0);
    closesocket(fd);
    LOGE("plugin service exit unexpectedly");
    ret_val = -1;
    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
    ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
    ev_unloop(EV_A_ EVUNLOOP_ALL);
}

#endif

void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    server_t *server = new_server(serverfd);
    server->listener = listener;

    ev_io_start(EV_A_ & server->recv_ctx->io);
}

void FreeListenCtx()
{
    for (int i = 0; i < listen_ctx.auditor_num; i++)
        ss_free(listen_ctx.auditor_addr[i]);
    ss_free(listen_ctx.auditor_addr);
    for (int i = 0; i < listen_ctx.worker_num; i++)
        ss_free(listen_ctx.worker_addr[i]);
    ss_free(listen_ctx.worker_addr);
    listen_ctx.auditor_num = 0;
    listen_ctx.worker_num = 0;
}

static void async_stop_cb(struct ev_loop *loop, ev_async *watcher, int revents)
{
    free_connections(loop);
    FreeListenCtx();
}

static void async_quit_cb(struct ev_loop *loop, ev_async *watcher, int revents)
{
    ev_break(loop, EVBREAK_ALL);
    printf("async_quit_cb\n");
}

static void async_update_node_info(struct ev_loop *loop, ev_async *watcher, int revents)
{
}

int SetNodeInfo2(const sama::business::CNodeInfo& auditor, const sama::business::CNodeInfo& worker, bool bDirectServer, const char* pubKey, const char* s_path)
{
    printf("SetNodeInfo2 \n");
    char* chSPath = new char[1024];
    memset(chSPath, 0, 1024);
    sprintf(chSPath, "%s",s_path);
    stat_path = chSPath;
    printf("%s\n", stat_path);
    g_bDirectServer = bDirectServer;
    g_AuditorNodeInfo.setBase(auditor);
    g_WorkerNodeInfo.setBase(worker);
    {
        int faliedTime = 0;
        listen_ctx.auditor_num  = 3;
        listen_ctx.auditor_addr = (struct sockaddr **)ss_malloc(sizeof(struct sockaddr *) * listen_ctx.auditor_num);
        memset(listen_ctx.auditor_addr, 0, sizeof(struct sockaddr *));
        for(int i = 0; i < listen_ctx.auditor_num; ++i)
        {
            const char* ip = g_AuditorNodeInfo.baseInfo.m_strNetIP.c_str();
            uint16_t port = g_AuditorNodeInfo.baseInfo.workPort[i];
            printf("SetNodeInfo2 ip:%s, port:%d\n", ip, port);
            struct sockaddr_storage *storage = (struct sockaddr_storage *)ss_malloc(sizeof(struct sockaddr_storage));
            memset(storage, 0, sizeof(struct sockaddr_storage));
            if (get_sockaddr((char*)ip, (char*)std::to_string(port).c_str(), storage, 1, 0) == -1){
                FATAL("failed to resolve the provided hostname");
                ss_free(storage);
                faliedTime++;
            }
            listen_ctx.auditor_addr[i] = (struct sockaddr *)storage;
        }
        listen_ctx.auditor_num -= faliedTime;
    }
    {
        int faliedTime = 0;
        listen_ctx.worker_num  = 3;
        listen_ctx.worker_addr = (struct sockaddr **)ss_malloc(sizeof(struct sockaddr *) * listen_ctx.worker_num);
        memset(listen_ctx.worker_addr, 0, sizeof(struct sockaddr *));
        for (int i = 0; i < listen_ctx.worker_num; i++)
        {
            const char* ip = g_WorkerNodeInfo.baseInfo.m_strNetIP.c_str();
            uint16_t port = g_WorkerNodeInfo.baseInfo.workPort[i];
            printf("SetNodeInfo2 ip:%s, port:%d\n", ip, port);
            struct sockaddr_storage *storage = (struct sockaddr_storage *)ss_malloc(sizeof(struct sockaddr_storage));
            memset(storage, 0, sizeof(struct sockaddr_storage));
            if (get_sockaddr((char*)ip, (char*)std::to_string(port).c_str(), storage, 1, 0) == -1){
                FATAL("failed to resolve the provided hostname");
                ss_free(storage);
                faliedTime++;
            }
            listen_ctx.worker_addr[i] = (struct sockaddr *)storage;
        }
        listen_ctx.worker_num -= faliedTime;
    }
    listen_ctx.timeout = 60;
    memcpy(g_chMyPubKey, pubKey, 33);
    return 1;
}

int StartTcpClient(const std::string& listenIp, const uint16_t listenPort)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    g_loop = EV_DEFAULT;

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_async_init(&ev_stop_watch, async_stop_cb);
    ev_async_start(g_loop, &ev_stop_watch);
    ev_async_init(&ev_quit_watch, async_quit_cb);
    ev_async_start(g_loop, &ev_quit_watch);
    ev_async_init(&ev_update_node_watch, async_update_node_info);
    ev_async_start(g_loop, &ev_update_node_watch);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
	ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);

    int listenfd = create_and_bind(listenIp.c_str(), std::to_string(listenPort).c_str());
    if (listenfd == -1) {
        FATAL("bind() error");
        return -1;
    }
    if (listen(listenfd, SOMAXCONN) == -1) {
        FATAL("listen() error");
        return -1;
    }
    setnonblocking(listenfd);

    listen_ctx.fd = listenfd;

    ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
    ev_io_start(g_loop, &listen_ctx.io);

    if (geteuid() == 0) {
        LOGI("running from root user");
    }

    cork_dllist_init(&connections);
    ev_run(g_loop, 0);
    ev_io_stop(g_loop, &listen_ctx.io);
    free_connections(g_loop);
    FreeListenCtx();
    close(listenfd);
    g_AuditorNodeInfo.release();
    g_WorkerNodeInfo.release();
    g_bDirectServer = false;
    printf("ev_run end\n");
    return 0;
}

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        std::cout << "param num error:" << argc << std::endl;
        return 0;
    }
    std::cout << argv[0] << std::endl;
    std::cout << argv[1] << std::endl;
    std::cout << argv[2] << std::endl;
    bool bDirectServer = true;
    std::string publicKey;
    int port;
    sama::business::CNodeInfo auditor, worker;
    sama::business::GlobalOperate go;
    if(!go.DeralizeSSInfo2(argv[1], auditor, worker, bDirectServer, publicKey, port))
    {
        std::cout << "DeralizeSSInfo error\n";
        return 0;
    }
    std::string publicKey2 = Encode::HexDecode(publicKey);
    SetNodeInfo2(auditor, worker, bDirectServer, publicKey2.c_str(), argv[2]);
    std::cout << "start tcp client port:" << port << std::endl;
    StartTcpClient("127.0.0.1", (uint16_t)port);
    std::cout << "end tcp client port:" << port << std::endl;
    return 0;
}
/*
https://blog.csdn.net/bawang_cn/article/details/115691696
https://blog.csdn.net/generallizhong/article/details/121046862
https://blog.csdn.net/python_yjys/article/details/127145470
https://it.cha138.com/ios/show-30974.html
 */
