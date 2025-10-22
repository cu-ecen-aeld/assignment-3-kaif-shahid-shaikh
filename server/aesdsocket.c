// Credits to ChatGPT for pointing out my mutex mistake around append packet and send file also to wrap around append packet correctly
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
#include <pthread.h>
#include <sys/queue.h>
#include <time.h>

#define USE_AESD_CHAR_DEVICE 1

#if USE_AESD_CHAR_DEVICE
#define DATAFILE "/dev/aesdchar"
#else
#define DATAFILE "/var/tmp/aesdsocketdata"
#endif

#define PORT 9000
#define BACKLOG 10
#define RECV_CHUNK 1024

static int listenfd = -1;   // make the listening socket global
static volatile sig_atomic_t g_exit = 0;

pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

// thread node structure for linked list
struct thread_node {
    pthread_t tid;
    int client_fd;
    SLIST_ENTRY(thread_node) entries;
};
SLIST_HEAD(thread_head, thread_node);
static struct thread_head g_thread_list = SLIST_HEAD_INITIALIZER(g_thread_list);
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;

static void handle_signal(int sig)
{
    (void)sig;
    g_exit = 1;

    // Wake up a blocking accept() immediately so tests don't hang
    if (listenfd >= 0) {
        int _ignored = shutdown(listenfd, SHUT_RDWR);
        (void)_ignored;
    }
}

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
#if USE_AESD_CHAR_DEVICE
    int fd = open(path, O_WRONLY);              // device: no O_CREAT/O_APPEND
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
#endif
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

static void *handle_client(void *arg) {
    int client_fd = *(int*)arg;
    free(arg);

    char buf[RECV_CHUNK];
    char *pkt = NULL;
    size_t cap = 0, len = 0;
    int have_newline = 0;

    while (!g_exit && !have_newline) {
        ssize_t n = recv(client_fd, buf, sizeof buf, 0);
        if (n <= 0) break;

        if (len + (size_t)n > cap) {
            size_t newcap = (cap ? cap * 2 : 2048);
            while (newcap < len + (size_t)n) newcap *= 2;
            char *tmp = realloc(pkt, newcap);
            if (!tmp) { free(pkt); pkt=NULL; cap=0; len=0; continue; }
            pkt = tmp; cap = newcap;
        }
        memcpy(pkt + len, buf, (size_t)n);
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') have_newline = 1;
        }
        len += (size_t)n;
    }

if (pkt && len) {
    size_t start = 0;
    while (start < len) {
        size_t i = start;
        while (i < len && pkt[i] != '\n') i++;

        if (i < len && pkt[i] == '\n') {
            size_t linelen = (i + 1) - start;  // include '\n'
            pthread_mutex_lock(&file_mutex);
            append_packet(DATAFILE, pkt + start, linelen);
            pthread_mutex_unlock(&file_mutex);
            start = i + 1;  // next line
        } else {
            // partial (no trailing '\n'): keep for future recv if you support multi-line clients
            break;
        }
    }

    pthread_mutex_lock(&file_mutex);
    send_file(client_fd, DATAFILE);
    pthread_mutex_unlock(&file_mutex);
}

    free(pkt);
    return NULL;
}

#if !USE_AESD_CHAR_DEVICE
static void *timestamp_thread(void *arg) {
    (void)arg;
    while (!g_exit) {
        sleep(10);
        if (g_exit) break;
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char ts[128];
        strftime(ts, sizeof ts, "timestamp:%a, %d %b %Y %H:%M:%S %z\n", tm_info);

        pthread_mutex_lock(&file_mutex);
        append_packet(DATAFILE, ts, strlen(ts));
        pthread_mutex_unlock(&file_mutex);
    }
    return NULL;
}
#endif

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

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        syslog(LOG_ERR, "socket() failed with errno=%d (%s)", errno, strerror(errno));
        closelog();
        return EXIT_FAILURE;
    }

    int yes = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        syslog(LOG_ERR, "setsockopt() failed with errno=%d (%s)", errno, strerror(errno));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "bind() failed with errno=%d (%s)", errno, strerror(errno));
        close(listenfd);
        closelog();
        return EXIT_FAILURE;
    }
    if (listen(listenfd, BACKLOG) < 0) {
        syslog(LOG_ERR, "listen() failed with errno=%d (%s)", errno, strerror(errno));
        close(listenfd);
        closelog();
        return EXIT_FAILURE;
    }

    if (opt_daemon) daemonize();
    #if !USE_AESD_CHAR_DEVICE
    {
        int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_TRUNC, 0664);
        if (fd < 0) {
            syslog(LOG_ERR, "Failed to open %s at startup: %s", DATAFILE, strerror(errno));
        } else {
            close(fd);
        }
    }
    #endif
    
    #if !USE_AESD_CHAR_DEVICE
    pthread_t ts_tid;
    pthread_create(&ts_tid, NULL, timestamp_thread, NULL);
    #endif

    while (!g_exit) {
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        int connfd = accept(listenfd, (struct sockaddr*)&cli, &clilen);
        if (connfd < 0) {
            if (errno == EINTR && g_exit) break;
            if (errno == EINTR) continue;
            if (g_exit) break;
            syslog(LOG_ERR, "accept() failed with errno=%d (%s)", errno, strerror(errno));
            continue;
        }

        int *fd_arg = malloc(sizeof(int));
        *fd_arg = connfd;

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, fd_arg);

        struct thread_node *node = malloc(sizeof *node);
        node->tid = tid;
        node->client_fd = connfd;
        pthread_mutex_lock(&list_mutex);
        SLIST_INSERT_HEAD(&g_thread_list, node, entries);
        pthread_mutex_unlock(&list_mutex);

        {
            struct thread_node *cur = SLIST_FIRST(&g_thread_list);
            struct thread_node *next;
            while (cur) {
                next = SLIST_NEXT(cur, entries);
                if (pthread_tryjoin_np(cur->tid, NULL) == 0) {
                    pthread_mutex_lock(&list_mutex);
                    SLIST_REMOVE(&g_thread_list, cur, thread_node, entries);
                    pthread_mutex_unlock(&list_mutex);
                    close(cur->client_fd);
                    free(cur);
                }
                cur = next;
            }
        }
    }

    // join timestamp thread
    #if !USE_AESD_CHAR_DEVICE
    pthread_join(ts_tid, NULL);
    #endif

    // join all client threads
    struct thread_node *np;
    while (!SLIST_EMPTY(&g_thread_list)) {
        np = SLIST_FIRST(&g_thread_list);
        pthread_join(np->tid, NULL);
        SLIST_REMOVE_HEAD(&g_thread_list, entries);
        free(np);
    }

    syslog(LOG_INFO, "Caught signal, exiting");
    close(listenfd);
    closelog();
    return EXIT_SUCCESS;
}

