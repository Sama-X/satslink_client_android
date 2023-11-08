#include <iostream>
#include <string>
#include <vector>
#include <fstream>
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
#include <sys/un.h>
#endif

#include "ServiceClient.h"

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

static struct cork_dllist connections;

static int setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#if defined(__CYGWIN__)
int fast_open = 0;
#else
int fast_open = 0;
#endif
int verbose    = 0;
int reuse_port = 0;
#ifdef __ANDROID__
int vpn        = 1;
uint64_t tx    = 0;
uint64_t rx    = 0;
ev_tstamp last = 0;

char *stat_path   = NULL;
#endif

extern "C" void
stat_update_cb()
{
    ev_tstamp now = ev_time();
    if (now - last > 0.5) {
        send_traffic_stat(tx, rx);
        last = now;
    }
}

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;
static struct ev_signal sigusr1_watcher;
static struct ev_async ev_stop_watch;
static struct ev_async ev_quit_watch;
static struct ev_async ev_update_node_watch;


static void ServerRecvCallback(EV_P_ ev_io *w, int revents);
static void ServerSendCallback(EV_P_ ev_io *w, int revents);
static void RemoteRecvCallback(EV_P_ ev_io *w, int revents);
static void RemoteSendCallback(EV_P_ ev_io *w, int revents);
static void AcceptCallback(EV_P_ ev_io *w, int revents);
static void SignalCallback(EV_P_ ev_signal *w, int revents);

static remote_t *CreateRemote(listen_ctx_t *listener, struct sockaddr *addr, int direct);
static void FreeRemote(remote_t *remote);
static void CloseAndFreeRemote(EV_P_ remote_t *remote);
static void FreeServer(server_t *server);
static void CloseAndFreeServer(EV_P_ server_t *server);

static remote_t *NewRemote(int fd, int timeout);
static server_t *NewServer(int fd);
static int ServerHandshake(EV_P_ ev_io *w, buffer_t *buf);
static void ServerStream(EV_P_ ev_io *w, buffer_t *buf);
static void RemoteTimeoutCallback(EV_P_ ev_timer *watcher, int revents);

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
#define cork_container_of_ex(field, struct_type, field_name) ((struct_type *) (- offsetof(struct_type, field_name) +  (char*)(field)))
static void DelayedConnectCallback(EV_P_ ev_timer *watcher, int revents)
{
    server_t *server = cork_container_of_ex(watcher, server_t, delayed_connect_watcher);
    ServerRecvCallback(EV_A_ & server->recv_ctx->io, revents);
}

static int ServerHandshakeReply(EV_P_ ev_io *w, int udp_assc, struct socks5_response *response)
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
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return -1;
        }
    } else
        memset(&sock_addr, 0, sizeof(sock_addr));

    buffer_t resp_to_send;
    buffer_t *resp_buf = &resp_to_send;
    balloc(resp_buf, SOCKET_BUF_SIZE);

    memcpy(resp_buf->data, response, sizeof(struct socks5_response));
    memcpy(resp_buf->data + sizeof(struct socks5_response), &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
    memcpy(resp_buf->data + sizeof(struct socks5_response) + sizeof(sock_addr.sin_addr), &sock_addr.sin_port, sizeof(sock_addr.sin_port));

    int reply_size = sizeof(struct socks5_response) + sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);

    int s = send(server->fd, resp_buf->data, reply_size, 0);

    bfree(resp_buf);

    if (s < reply_size) {
        LOGE("failed to send fake reply");
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return -1;
    }
    if (udp_assc) {
        // Wait until client closes the connection
        return -1;
    }
    return 0;
}

static int ServerHandshake(EV_P_ ev_io *w, buffer_t *buf)
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
        return ServerHandshakeReply(EV_A_ w, 1, &response);
    } else if (request->cmd != SOCKS5_CMD_CONNECT) {
        LOGE("unsupported command: %d", request->cmd);
        response.rep = SOCKS5_REP_CMD_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, 4, 0);
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return -1;
    }

    char host[MAX_HOSTNAME_LEN + 1], ip[INET6_ADDRSTRLEN], port[16];

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
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        uint8_t name_len = *(uint8_t *)(buf->data + request_len);
        if (buf->len < request_len + 1 + name_len + 2) {
            return -1;
        }
        abuf->data[abuf->len++] = name_len;
        memcpy(abuf->data + abuf->len, buf->data + request_len + 1, name_len + 2);
        abuf->len += name_len + 2;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (buf->len < request_len + in6_addr_len + 2) {
            return -1;
        }
        memcpy(abuf->data + abuf->len, buf->data + request_len, in6_addr_len + 2);
        abuf->len += in6_addr_len + 2;
    } else {
        LOGE("unsupported addrtype: %d", request->atyp);
        response.rep = SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, 4, 0);
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return -1;
    }

    if (ServerHandshakeReply(EV_A_ w, 0, &response) < 0)
        return -1;
    server->stage = STAGE_STREAM;

    buf->len -= (3 + abuf->len);
    if (buf->len > 0) {
        memmove(buf->data, buf->data + 3 + abuf->len, buf->len);
    }

    // Not bypass
    if (remote == NULL) {
        remote = CreateRemote(server->listener, NULL, 0);
    }

    if (remote == NULL) {
        LOGE("invalid remote addr");
        CloseAndFreeServer(EV_A_ server);
        return -1;
    }

    if (!remote->direct) {
        int err = g_WorkerNodeInfo.crypto->encrypt(abuf, server->e_ctx_s, SOCKET_BUF_SIZE);
        if (err) {
            LOGE("invalid password or cipher");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
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

#ifdef __ANDROID__
#include "ancillary.h"
#endif

static void Connect_Server(EV_P_ ev_io *w, buffer_t *buf)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
#ifdef __ANDROID__
    if (vpn) {
        int not_protect = 0;
        if (remote->addr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&remote->addr;
            if (s->sin_addr.s_addr == inet_addr("127.0.0.1"))
                not_protect = 1;
        }
        LOGE("samal not_protect:%d\n", not_protect);
        if (!not_protect) {
            if (protect_socket(remote->fd) == -1) {
                LOGE("samal not_protect error:%d\n", not_protect);
                ERROR("protect_socket");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                printf("protect_socket123456\n");
                return;
            }
        }
    }
#endif

    remote->buf->idx = 0;
    LOGE("start connect fast_open:%d, direct:%d\n", fast_open, remote->direct);
    if (!fast_open || remote->direct) {
        // connecting, wait until connected
        int r = connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);
        LOGE("start connect:%d\n", r);
        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect 1");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }

        // wait on remote connected event
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
    } else {
#if defined(MSG_FASTOPEN) && !defined(TCP_FASTOPEN_CONNECT)
        int s = -1;
        s = sendto(remote->fd, remote->buf->data, remote->buf->len, MSG_FASTOPEN, (struct sockaddr *)&(remote->addr), remote->addr_len);
#elif defined(TCP_FASTOPEN_WINSOCK)
        DWORD s   = -1;
        DWORD err = 0;
        do {
            int optval = 1;
            // Set fast open option
            if (setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN, &optval, sizeof(optval)) != 0) {
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
            if (winsock_dummybind(remote->fd, (struct sockaddr *)&(remote->addr)) != 0) {
                ERROR("bind");
                break;
            }
            // Call ConnectEx to send data
            memset(&remote->olap, 0, sizeof(remote->olap));
            remote->connect_ex_done = 0;
            if (ConnectEx(remote->fd, (const struct sockaddr *)&(remote->addr), remote->addr_len, remote->buf->data, remote->buf->len, &s, &remote->olap)) {
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

        s = connectx(remote->fd, &endpoints, SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT, NULL, 0, NULL, NULL);
#elif defined(TCP_FASTOPEN_CONNECT)
        //#error fuck
        int optval = 1;
        if (setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, (void *)&optval, sizeof(optval)) < 0)
            FATAL("failed to set TCP_FASTOPEN_CONNECT");
        s = connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);
#else
        FATAL("fast open is not enabled in this build 1");
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
                    ERROR("fast_open_connect 1");
                }
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
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
}

static void ServerStream(EV_P_ ev_io *w, buffer_t *buf)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    if (remote == NULL) {
        LOGE("invalid remote");
        CloseAndFreeServer(EV_A_ server);
        return;
    }

    // insert shadowsocks header
    if (!remote->direct) {
        int err = g_WorkerNodeInfo.crypto->encrypt(remote->buf, server->e_ctx_s, SOCKET_BUF_SIZE);

        if (err) {
            LOGE("invalid password or cipher");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
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
        return Connect_Server(EV_A_ w, buf);
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
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
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

static void ServerRecvCallback(EV_P_ ev_io *w, int revents)
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
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        } else if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data
                // continue to wait for recv
                return;
            } else {
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }
        }
        buf->len += r;
    }

    while (1) {
        // local socks5 server
        if (server->stage == STAGE_STREAM) {
            ServerStream(EV_A_ w, buf);

            // all processed
            return;
        } else if (server->stage == STAGE_INIT) {
            if (buf->len < 1)
                return;
            if (buf->data[0] != SVERSION) {
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }
            if (buf->len < sizeof(struct method_select_request)) {
                return;
            }
            struct method_select_request *method = (struct method_select_request *)buf->data;
            unsigned int method_len                       = method->nmethods + sizeof(struct method_select_request);
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
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }

            server->stage = STAGE_HANDSHAKE;

            if (method_len < buf->len) {
                memmove(buf->data, buf->data + method_len, buf->len - method_len);
                buf->len -= method_len;
                continue;
            }

            buf->len = 0;
            
            return;
        } else if (server->stage == STAGE_HANDSHAKE) {
            int ret = ServerHandshake(EV_A_ w, buf);
            if (ret)
                return;
        }
    }
}

static void ServerSendCallback(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0) {
        // close and free
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx, server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_cb_send");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
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

static void RemoteRecvCallback(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote_recv_cb_recv");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;

    if (!remote->direct) {
        int err = g_WorkerNodeInfo.crypto->decrypt(server->buf, server->d_ctx_s, SOCKET_BUF_SIZE);
        if (err == CRYPTO_ERROR) {
            LOGE("invalid password or cipher");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
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
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    } else if (s < (int)(server->buf->len)) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void RemoteSendCallback(EV_P_ ev_io *w, int revents)
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
                if (WSAGetOverlappedResult(remote->fd, &remote->olap, &numBytes, FALSE, &flags)) {
                    remote->buf->len       -= numBytes;
                    remote->buf->idx        = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    CloseAndFreeRemote(EV_A_ remote);
                    CloseAndFreeServer(EV_A_ server);
                    return;
                }
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
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
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else {
        // has data to send
        MakeSeverInfo2Router(remote, server, remote->buf);
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx, remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
                // close and free
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
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

static remote_t* NewRemote(int fd, int timeout)
{
    remote_t *remote;
    remote = (remote_t*)ss_malloc(sizeof(remote_t));

    memset(remote, 0, sizeof(remote_t));

    remote->buf      = (buffer_t*)ss_malloc(sizeof(buffer_t));
    remote->recv_ctx = (remote_ctx*)ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = (remote_ctx*)ss_malloc(sizeof(remote_ctx_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;
    remote->_has_sent = 0;

    ev_io_init(&remote->recv_ctx->io, RemoteRecvCallback, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, RemoteSendCallback, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, RemoteTimeoutCallback, min(10, timeout), 0);

    return remote;
}

static void FreeRemote(remote_t *remote)
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

static void CloseAndFreeRemote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        FreeRemote(remote);
    }
}

static server_t* NewServer(int fd)
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

    ev_io_init(&server->recv_ctx->io, ServerRecvCallback, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, ServerSendCallback, fd, EV_WRITE);

    ev_timer_init(&server->delayed_connect_watcher, DelayedConnectCallback, 0.05, 0);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void FreeServer(server_t *server)
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

static void CloseAndFreeServer(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->delayed_connect_watcher);
        close(server->fd);
        FreeServer(server);
    }
}

static remote_t* CreateRemote(listen_ctx_t *listener, struct sockaddr *addr, int direct)
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
    remote_t *remote = NewRemote(remotefd, direct ? 10 : listener->timeout);
    remote->addr_len = get_sockaddr_len(remote_addr);
    memcpy(&(remote->addr), remote_addr, remote->addr_len);
    remote->direct = direct;

    return remote;
}

static void RemoteTimeoutCallback(EV_P_ ev_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx = cork_container_of_ex(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;
    CloseAndFreeRemote(EV_A_ remote);
    CloseAndFreeServer(EV_A_ server);
}

static void SignalCallback(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGCHLD:
            return;
        case SIGUSR1:
        case SIGINT:
        case SIGTERM:
            ev_async_stop(EV_DEFAULT, &ev_stop_watch);
            ev_async_stop(EV_DEFAULT, &ev_quit_watch);
            ev_async_stop(EV_DEFAULT, &ev_update_node_watch);
            ev_signal_stop(EV_DEFAULT, &sigint_watcher);
            ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
            ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
            ev_signal_stop(EV_DEFAULT, &sigusr1_watcher);
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

static void AcceptCallback(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    LOGE("accept_cb:%d\n", serverfd);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    if(listener->auditor_num == 0 || listener->worker_num == 0)
    {
        close(serverfd);
        return;
    }
    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    server_t *server = NewServer(serverfd);
    server->listener = listener;

    ev_io_start(EV_A_ & server->recv_ctx->io);
}

static int CreateAndBind(const char *addr, const char *port)
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

static void
free_connections(struct ev_loop *loop)
{
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(&connections, curr, next) {
        server_t *server = cork_container_of_ex(curr, server_t, entries);
        remote_t *remote = server->remote;
        CloseAndFreeServer(loop, server);
        CloseAndFreeRemote(loop, remote);
    }
}

struct ev_loop *loop = nullptr;
listen_ctx_t listen_ctx;

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

int StartTcpClient(const std::string& listenIp, const uint16_t listenPort)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    loop = EV_DEFAULT;

    ev_signal_init(&sigint_watcher, SignalCallback, SIGINT);
    ev_signal_init(&sigterm_watcher, SignalCallback, SIGTERM);
    ev_signal_init(&sigchld_watcher, SignalCallback, SIGCHLD);
    ev_async_init(&ev_stop_watch, async_stop_cb);
    ev_async_start(loop, &ev_stop_watch);
    ev_async_init(&ev_quit_watch, async_quit_cb);
    ev_async_start(loop, &ev_quit_watch);
    ev_async_init(&ev_update_node_watch, async_update_node_info);
    ev_async_start(loop, &ev_update_node_watch);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);

    int listenfd = CreateAndBind(listenIp.c_str(), std::to_string(listenPort).c_str());
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

    ev_io_init(&listen_ctx.io, AcceptCallback, listenfd, EV_READ);
    ev_io_start(loop, &listen_ctx.io);

    if (geteuid() == 0) {
        LOGI("running from root user");
    }
    
    cork_dllist_init(&connections);
    ev_run(loop, 0);
    ev_io_stop(loop, &listen_ctx.io);
    free_connections(loop);
    FreeListenCtx();
    close(listenfd);
    g_AuditorNodeInfo.release();
    g_WorkerNodeInfo.release();
    g_bDirectServer = false;
    printf("ev_run end\n");
    return 0;
}

void StopTcpClient()
{
    ev_async_send(loop, &ev_stop_watch);
}

void QuitTcpClient()
{
    ev_async_send(loop, &ev_quit_watch);
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