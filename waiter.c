#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROGRAM_NAME "waiter"

#define log(...) fprintf(stderr, PROGRAM_NAME": "__VA_ARGS__)
#define logp(msg) perror(PROGRAM_NAME": "msg)
#define die(...) {log("ERROR: "__VA_ARGS__); putc('\n', stderr); exit(-1);}
#define diep(msg) {logp("ERROR: "msg); exit(-1);}

// constants
#define RECV_BUFFER_CAP 2048 // NOTE: buffer size might not be good
#define SEND_BUFFER_CAP 2048 // NOTE: buffer size might not be good

// globals
int _server_fd = 0;
char INDEX_FILENAME[] = "index.html";
char ERROR_404_FILENAME[] = "404.html";
char *MIME_TYPES[][2] = {
    {"html", "text/html"},
    {"js", "text/javascript"},
    {"css", "text/css"},
};

// functions
char const *
mime_type(char const *restrict filename)
{
    char *ext = strrchr(filename, '.');
    if(ext == NULL) {return(NULL);}
    ext++;
    for(size_t i = 0;
            i < sizeof(MIME_TYPES) / sizeof(*MIME_TYPES);
            i++)
    {
        if(strcmp(ext, MIME_TYPES[i][0]) == 0)
        {
            return(MIME_TYPES[i][1]);
        }
    }
    return(NULL);
}

char const *
mime_type_default(char const *restrict filename)
{
    char const *mime = mime_type(filename);
    return(mime == NULL ? MIME_TYPES[0][1] : mime);
}

void
socket_send_all(
        int fd,
        char const *restrict buf,
        size_t buf_size)
{
    size_t bytes_sent = 0;
    do
    {
        ssize_t bsent = 0;
        if((bsent = send(fd, buf + bytes_sent, buf_size - bytes_sent, 0)) < 0)
        {
            diep("failed to send packet");
        }
        bytes_sent += bsent;
    } while(bytes_sent < buf_size);
}

void
close_server(void)
{
    log("close server");
    close(_server_fd);
}

size_t
file_get_size(char const *restrict filename)
{
    struct stat sb;
    if(stat(filename, &sb) == -1)
    {
        logp("failed to get file length");
    }
    return(sb.st_size);
}

uint8_t
file_is_reg(char *filename)
{
    struct stat sb;

    if(stat(filename, &sb) == -1)
    {
        if(errno == ENOMEM) {diep("stat");}
        else {return(0);}
    }
    return (sb.st_mode & S_IFMT) == S_IFREG;
}

int
main(void)
{
    uint16_t const server_port = 8080;
    int const server_queue_size = 10;
    struct sockaddr_in server_addr = {0};

    // get socket
    if((_server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        diep("failed to create server socket");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_port);

    int sockopt_enable = 1;
    if (setsockopt(_server_fd,
                SOL_SOCKET,
                SO_REUSEADDR,
                &sockopt_enable,
                sizeof(int)) < 0)
    {
        diep("failed to setsockopt REUSEADDR");
    }

    // port
    if(bind(_server_fd,
                (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0)
    {
        diep("failed to bind server socket to port");
    }

    if(listen(_server_fd, server_queue_size) < 0)
    {
        diep("failed to listen to server socket");
    }
    log("Server listening on port\n");

    // make sure to close the server
    atexit(close_server);

    // we only serve from the public directory
    chdir("public/");

    // accept loop
    while(1)
    {
        char recv_buf[RECV_BUFFER_CAP] = {0};
        struct sockaddr_in client_addr = {0};
        socklen_t client_addr_size = sizeof(client_addr);
        int client_fd = 0;

        // get
        if((client_fd = accept(_server_fd,
                        (struct sockaddr *)&client_addr,
                        &client_addr_size)) < 0)
        {
            logp("failed to accept a connection\n");
            continue;
        }

        ssize_t recv_buf_size = 0;
        recv_buf_size = recv(client_fd, recv_buf, RECV_BUFFER_CAP, 0); // TODO: unfinished reads
        if(recv_buf_size == 0) {goto EXIT_REQUEST;}
        if(recv_buf_size < 0) {diep("recv");}
        char *recv_buf_end = recv_buf + recv_buf_size;

        // recv parse
        char *method = recv_buf;
        char *url = NULL;
        char *params = NULL;
        char *protocol = NULL;
        char *rest = NULL;
        for(url = method; url < recv_buf_end; url++)
        {
            if(*url == ' ') {*(url++) = '\0'; break;}
        }
        params = url;
        for(protocol = url; protocol < recv_buf_end; protocol++)
        {
            if(*protocol == '?') {*(protocol++) = '\0'; params = protocol;}
            if(*protocol == ' ') {*(protocol++) = '\0'; break;}
        }
        for(rest = protocol; rest < recv_buf_end; rest++)
        {
            if(isspace(*rest)) {*(rest++) = '\0'; break;}
        }
        if(strcmp(method, "GET") != 0) {log("failed: was not GET\n"); goto EXIT_REQUEST;}
        if(strcmp(protocol, "HTTP/1.1") != 0) {log("failed: was not HTTP/1.1\n"); goto EXIT_REQUEST;}
        log("URL: %s\n", url);
        if(params != url) {log("PARAMS: %s\n", params);}

        // url verification
        char temp_filename[PATH_MAX] = {0};
        url++;
        size_t url_size = strlen(url);
        if(url_size == 0) {url = INDEX_FILENAME;}
        else if(url[url_size - 1] == '/')
        {
            memcpy(temp_filename, url, url_size);
            memcpy(temp_filename + url_size, INDEX_FILENAME, sizeof(INDEX_FILENAME)); // NOTE: has \0 at the end
            url = temp_filename;
        }
        else if(!file_is_reg(url))
        {
            memcpy(temp_filename, url, url_size);
            temp_filename[url_size] = '/';
            memcpy(temp_filename + url_size + 1, INDEX_FILENAME, sizeof(INDEX_FILENAME)); // NOTE: has \0 at the end
            url = temp_filename;
        }
        log("NEW URL: %s\n", url);

        // find file
        int fd = open(url, O_RDONLY);
        size_t file_size = 0;

        // send header
        char *header_type = "HTTP/1.1 200 OK";
        char send_buf[SEND_BUFFER_CAP] = {0};
        size_t send_buf_offset = 0;
        if(fd < 0)
        {
            url = ERROR_404_FILENAME;
            fd = open(url, O_RDONLY);
            if(fd < 0) {log("missing 404 file"); goto EXIT_REQUEST;}

            file_size = file_get_size(url);
            header_type = "HTTP/1.1 404 NOT FOUND\r\n";
        }
        file_size = file_get_size(url);
        send_buf_offset = snprintf(
                send_buf, SEND_BUFFER_CAP,
                "%s\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %ld\r\n"
                "\r\n",
                header_type,
                mime_type_default(url),
                file_size);
        if(send_buf_offset > SEND_BUFFER_CAP) {die("failed to write header");}
        socket_send_all(client_fd, send_buf, send_buf_offset);

        // handle file
        if(sendfile(client_fd, fd, NULL, file_size) < 0)
        {
            diep("failed to send file");
        }
        close(fd);

EXIT_REQUEST:
        close(client_fd);
    }

    return(0);
}
