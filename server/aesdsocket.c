#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define PORT 9000
#define DATAFILE "/var/tmp/aesdsocketdata"
#define BACKLOG 10
#define RECV_CHUNK 1024

static volatile sig_atomic_t g_exit = 0;

static void handle_signal(int sig) { (void)sig; g_exit = 1; }

static int send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_file(int sockfd, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[RECV_CHUNK];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        if (send_all(sockfd, buf, (size_t)n) < 0) {
            close(fd);
            return -1;
        }
    }
    int rc = (n < 0) ? -1 : 0;
    close(fd);
    return rc;
}

static int append_packet(const char *path, const char *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    const char *p = data;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    close(fd);
    return 0;
}

static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);

    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    (void)open("/dev/null", O_RDONLY);
    (void)open("/dev/null", O_RDWR);
    (void)open("/dev/null", O_RDWR);
}

int main(int argc, char **argv) {
    int opt_daemon = (argc == 2 && strcmp(argv[1], "-d") == 0);

    openlog("aesdsocket", LOG_PID, LOG_USER);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        syslog(LOG_ERR, "socket: %m");
        closelog();
        return -1;
    }

    int yes = 1;
    (void)setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "bind: %m");
        close(listenfd);
        closelog();
        return -1;
    }
    if (listen(listenfd, BACKLOG) < 0) {
        syslog(LOG_ERR, "listen: %m");
        close(listenfd);
        closelog();
        return -1;
    }

    if (opt_daemon) daemonize();

    while (!g_exit) {
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        int connfd = accept(listenfd, (struct sockaddr*)&cli, &clilen);
        if (connfd < 0) {
            if (errno == EINTR && g_exit) break;
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "accept: %m");
            break;
        }

        char ip[INET_ADDRSTRLEN] = "unknown";
        (void)inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof ip);
        syslog(LOG_INFO, "Accepted connection from %s", ip);

        char *pkt = NULL;
        size_t cap = 0, len = 0;
        int have_newline = 0;
        char buf[RECV_CHUNK];

        while (!g_exit && !have_newline) {
            ssize_t n = recv(connfd, buf, sizeof buf, 0);
            if (n == 0) {
                break; // peer closed
            }
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }

            if (len + (size_t)n > cap) {
                size_t newcap = (cap ? cap * 2 : 2048);
                while (newcap < len + (size_t)n) newcap *= 2;
                char *tmp = realloc(pkt, newcap);
                if (!tmp) {
                    free(pkt);
                    pkt = NULL;
                    cap = 0;
                    len = 0;
                    // keep reading until newline to resync
                } else {
                    pkt = tmp;
                    cap = newcap;
                }
            }

            if (pkt) {
                size_t start = len;
                memcpy(pkt + len, buf, (size_t)n);
                len += (size_t)n;
                for (size_t i = start; i < len; i++) {
                    if (pkt[i] == '\n') {
                        have_newline = 1;
                        break;
                    }
                }
            } else {
                for (ssize_t i = 0; i < n; i++) {
                    if (buf[i] == '\n') {
                        have_newline = 1;
                        break;
                    }
                }
            }
        }

        if (pkt && len) {
            size_t upto = 0;
            while (upto < len && pkt[upto] != '\n') upto++;
            if (upto < len && pkt[upto] == '\n') upto++;

            if (append_packet(DATAFILE, pkt, upto) < 0) {
                syslog(LOG_ERR, "append: %m");
            } else {
                if (send_file(connfd, DATAFILE) < 0) {
                    syslog(LOG_ERR, "send_file: %m");
                }
            }
        }

        free(pkt);
        (void)shutdown(connfd, SHUT_RDWR);
        close(connfd);
        syslog(LOG_INFO, "Closed connection from %s", ip);
    }

    syslog(LOG_INFO, "Caught signal, exiting");
    close(listenfd);
    (void)unlink(DATAFILE);
    closelog();
    return 0;
}
