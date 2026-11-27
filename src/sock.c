/* sock.c — the only file that talks to the socket API: Winsock 2 on
 * Windows, BSD sockets elsewhere. Timeouts use select (Windows) or poll;
 * writing to a closed connection never raises SIGPIPE (MSG_NOSIGNAL on
 * Linux, SO_NOSIGPIPE on macOS and the BSDs). */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#endif

#include "nmzp.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sys_socket;
#define SYS_BAD INVALID_SOCKET
#define CLOSE closesocket
static int last_error(void) { return WSAGetLastError(); }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef int sys_socket;
#define SYS_BAD (-1)
#define CLOSE close
static int last_error(void) { return errno; }
#endif

#if defined(MSG_NOSIGNAL)
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif

static sys_socket sys(nmzp_socket s) { return (sys_socket)s; }

int nmzp_net_init(void) {
#if defined(_WIN32)
    static int done;
    WSADATA wsa;
    if (done) return 0;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
    done = 1;
#endif
    return 0;
}

const char *nmzp_sock_error(char *buf, size_t n) {
#if defined(_WIN32)
    int e = WSAGetLastError();
    char msg[256] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)e, 0, msg, sizeof msg,
                   NULL);
    {
        size_t k = strlen(msg);
        while (k && (msg[k - 1] == '\n' || msg[k - 1] == '\r' || msg[k - 1] == '.')) msg[--k] = '\0';
    }
    snprintf(buf, n, "%s (error %d)", msg[0] ? msg : "socket error", e);
#else
    snprintf(buf, n, "%s", strerror(errno));
#endif
    return buf;
}

static void no_sigpipe(sys_socket s) {
#if defined(SO_NOSIGPIPE)
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#else
    (void)s;
#endif
}

static void no_delay(sys_socket s) {
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
}

/* wait until s is readable (want_write = 0) or writable: 1 ready, 0 timeout, -1 error */
static int wait_for(sys_socket s, int want_write, int timeout_ms) {
#if defined(_WIN32)
    fd_set set, err;
    struct timeval tv;
    int r;
    FD_ZERO(&set);
    FD_ZERO(&err);
    FD_SET(s, &set);
    FD_SET(s, &err);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    r = select(0, want_write ? NULL : &set, want_write ? &set : NULL, &err, timeout_ms < 0 ? NULL : &tv);
    if (r < 0) return -1;
    if (r == 0) return 0;
    if (FD_ISSET(s, &err) && !FD_ISSET(s, &set)) return -1;
    return 1;
#else
    struct pollfd p;
    int r;
    p.fd = s;
    p.events = want_write ? POLLOUT : POLLIN;
    p.revents = 0;
    do {
        r = poll(&p, 1, timeout_ms < 0 ? -1 : timeout_ms);
    } while (r < 0 && errno == EINTR);
    if (r < 0) return -1;
    if (r == 0) return 0;
    return 1;
#endif
}

static int set_blocking(sys_socket s, int blocking) {
#if defined(_WIN32)
    u_long mode = blocking ? 0 : 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(s, F_SETFL, blocking ? (fl & ~O_NONBLOCK) : (fl | O_NONBLOCK)) == 0 ? 0 : -1;
#endif
}

nmzp_socket nmzp_connect(const char *host, int port, int timeout_ms, char *err, size_t errn) {
    struct addrinfo hints, *res = NULL, *ai;
    char ports[16], why[256];
    sys_socket s = SYS_BAD;
    int rc;
    if (err && errn) err[0] = '\0';
    if (nmzp_net_init()) {
        if (err) snprintf(err, errn, "the socket library did not start");
        return NMZP_NO_SOCKET;
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(ports, sizeof ports, "%d", port);
    rc = getaddrinfo(host, ports, &hints, &res);
    if (rc != 0 || !res) {
        if (err) snprintf(err, errn, "cannot resolve %s", host);
        return NMZP_NO_SOCKET;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        int r;
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == SYS_BAD) continue;
        no_sigpipe(s);
        set_blocking(s, 0);
        r = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (r != 0) {
            int e = last_error();
#if defined(_WIN32)
            int pending = e == WSAEWOULDBLOCK;
#else
            int pending = e == EINPROGRESS;
#endif
            r = -1;
            if (pending && wait_for(s, 1, timeout_ms) == 1) {
                int soerr = 0;
#if defined(_WIN32)
                int len = sizeof soerr;
#else
                socklen_t len = sizeof soerr;
#endif
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len) == 0 && soerr == 0) r = 0;
            }
        }
        if (r == 0) {
            set_blocking(s, 1);
            no_delay(s);
            break;
        }
        CLOSE(s);
        s = SYS_BAD;
    }
    freeaddrinfo(res);
    if (s == SYS_BAD && err) snprintf(err, errn, "cannot connect to %s:%d (%s)", host, port, nmzp_sock_error(why, sizeof why));
    return s == SYS_BAD ? NMZP_NO_SOCKET : (nmzp_socket)s;
}

nmzp_socket nmzp_listen(const char *bind_addr, int port, int backlog, int *bound, char *err, size_t errn) {
    struct addrinfo hints, *res = NULL;
    char ports[16], why[256];
    sys_socket s;
    int one = 1;
    if (err && errn) err[0] = '\0';
    if (nmzp_net_init()) {
        if (err) snprintf(err, errn, "the socket library did not start");
        return NMZP_NO_SOCKET;
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
    snprintf(ports, sizeof ports, "%d", port);
    if (getaddrinfo(bind_addr && *bind_addr ? bind_addr : "127.0.0.1", ports, &hints, &res) != 0 || !res) {
        if (err) snprintf(err, errn, "'%s' is not an IP address to listen on", bind_addr ? bind_addr : "");
        return NMZP_NO_SOCKET;
    }
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == SYS_BAD) {
        if (err) snprintf(err, errn, "socket: %s", nmzp_sock_error(why, sizeof why));
        freeaddrinfo(res);
        return NMZP_NO_SOCKET;
    }
#if defined(_WIN32)
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof one);
#else
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
    if (bind(s, res->ai_addr, (int)res->ai_addrlen) != 0 || listen(s, backlog > 0 ? backlog : 64) != 0) {
        if (err) snprintf(err, errn, "cannot listen on %s:%d (%s)", bind_addr, port, nmzp_sock_error(why, sizeof why));
        CLOSE(s);
        freeaddrinfo(res);
        return NMZP_NO_SOCKET;
    }
    freeaddrinfo(res);
    if (bound) {
        struct sockaddr_storage ss;
#if defined(_WIN32)
        int len = sizeof ss;
#else
        socklen_t len = sizeof ss;
#endif
        *bound = port;
        if (getsockname(s, (struct sockaddr *)&ss, &len) == 0) {
            if (ss.ss_family == AF_INET) *bound = ntohs(((struct sockaddr_in *)&ss)->sin_port);
            if (ss.ss_family == AF_INET6) *bound = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
        }
    }
    return (nmzp_socket)s;
}

nmzp_socket nmzp_accept(nmzp_socket ls, int timeout_ms, int *timed_out, char *peer, size_t peern) {
    struct sockaddr_storage ss;
#if defined(_WIN32)
    int len = sizeof ss;
#else
    socklen_t len = sizeof ss;
#endif
    sys_socket c;
    int w;
    if (timed_out) *timed_out = 0;
    if (peer && peern) peer[0] = '\0';
    w = wait_for(sys(ls), 0, timeout_ms);
    if (w == 0) {
        if (timed_out) *timed_out = 1;
        return NMZP_NO_SOCKET;
    }
    if (w < 0) return NMZP_NO_SOCKET;
    c = accept(sys(ls), (struct sockaddr *)&ss, &len);
    if (c == SYS_BAD) {
        if (timed_out) *timed_out = 1; /* e.g. the client went away: try again */
        return NMZP_NO_SOCKET;
    }
    no_sigpipe(c);
    no_delay(c);
    if (peer && peern) {
        char host[64] = "?";
        int port = 0;
        if (ss.ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, host, sizeof host);
            port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, host, sizeof host);
            port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
        }
        snprintf(peer, peern, "%s:%d", host, port);
    }
    return (nmzp_socket)c;
}

int nmzp_send_all(nmzp_socket s, const void *p, size_t n) {
    const char *c = (const char *)p;
    while (n > 0) {
        int chunk = n > 1048576 ? 1048576 : (int)n;
        int k = (int)send(sys(s), c, chunk, SEND_FLAGS);
        if (k <= 0) {
#if !defined(_WIN32)
            if (k < 0 && errno == EINTR) continue;
#endif
            return -1;
        }
        c += k;
        n -= (size_t)k;
    }
    return 0;
}

long nmzp_recv(nmzp_socket s, void *p, size_t n, int timeout_ms) {
    int w = wait_for(sys(s), 0, timeout_ms), k;
    if (w == 0) return -2;
    if (w < 0) return -1;
    for (;;) {
        k = (int)recv(sys(s), (char *)p, n > 1048576 ? 1048576 : (int)n, 0);
#if !defined(_WIN32)
        if (k < 0 && errno == EINTR) continue;
#endif
        break;
    }
    return k < 0 ? -1 : (long)k;
}

void nmzp_close_graceful(nmzp_socket s, int ms) {
    char buf[4096];
    double end = nmzp_clock() + ms / 1000.0;
    size_t total = 0;
    if (s == NMZP_NO_SOCKET) return;
#if defined(_WIN32)
    shutdown(sys(s), SD_SEND);
#else
    shutdown(sys(s), SHUT_WR);
#endif
    while (total < (8u << 20)) {
        double left = end - nmzp_clock();
        long k;
        if (left <= 0) break;
        k = nmzp_recv(s, buf, sizeof buf, (int)(left * 1000) + 1);
        if (k <= 0) break;
        total += (size_t)k;
    }
    CLOSE(sys(s));
}

void nmzp_close(nmzp_socket s) {
    if (s == NMZP_NO_SOCKET) return;
#if defined(_WIN32)
    shutdown(sys(s), SD_BOTH);
#else
    shutdown(sys(s), SHUT_RDWR);
#endif
    CLOSE(sys(s));
}
