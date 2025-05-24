#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <glob.h>
#include <linux/limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PROGRAM_NAME "waiter"

#define log(...) fprintf(stderr, PROGRAM_NAME": "__VA_ARGS__)
#define logp(msg) perror(PROGRAM_NAME": "msg)
#define die(...) {log("ERROR: "__VA_ARGS__); putc('\n', stderr); exit(-1);}
#define diep(msg) {logp("ERROR: "msg); exit(-1);}
#define static_array_size(arr) sizeof(arr) / sizeof(*(arr))

// constants
#define RECV_BUFFER_CAP 8192
#define SEND_BUFFER_CAP 8192
#define SEND_HEADER_CAP 2048
#define THREAD_COUNT 16

// certs
#define CERT_FILE "../certs/cert.pem"
#define PRIVATE_KEY_FILE "../certs/key.pem"

// structs
struct thread_data
{
    int client;
    sem_t notify;
};

// constant globals
char _http_default_404[] =
    "HTTP/1.1 404 NOT FOUND\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 18\r\n" // WARN: relies on the string length below
    "\r\n"
    "404 page not found";
char _http_default_417[] =
    "HTTP/1.1 417 Expectation Failed\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 29\r\n" // WARN: relies on the string length below
    "\r\n"
    "unable to read entire request";
char _http_default_500[] =
    "HTTP/1.1 500 Internal Error\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 27\r\n" // WARN: relies on the string length below
    "\r\n"
    "500 - internal server error";

// globals
char _curr_dir[PATH_MAX] = {0};
int _server_fd = 0;
SSL_CTX *_ctx = NULL;
char _file_index[] = "index.html";
char _file_error_404[] = "404.html";
char *_mime_types[][2] = {
    {"html", "text/html"},
    {"js", "text/javascript"},
    {"css", "text/css"},
};
char *_blacklisted_config[] = {
    ".git/",
};
glob_t _blacklisted = {0};

// functions
char const *
mime_type(
        char const *restrict filename)
{
    char *ext = strrchr(filename, '.');
    if(ext == NULL) {return(NULL);}
    ext++;
    for(size_t i = 0;
            i < static_array_size(_mime_types);
            i++)
    {
        if(strcmp(ext, _mime_types[i][0]) == 0)
        {
            return(_mime_types[i][1]);
        }
    }
    return(NULL);
}

char const *
mime_type_default(char const *restrict filename)
{
    char const *mime = mime_type(filename);
    return(mime == NULL ? _mime_types[0][1] : mime);
}

void
socket_send_all_SSL(
        SSL* ssl,
        char const *restrict buf,
        size_t buf_size)
{
    size_t bytes_sent = 0;
    do
    {
        ssize_t bsent = 0;
        if((bsent = SSL_write(ssl, buf + bytes_sent, buf_size - bytes_sent)) <= 0)
        {
            diep("failed to send packet");
        }
        bytes_sent += bsent;
    } while(bytes_sent < buf_size);
}

void
close_server(
        void)
{
    log("close server");
    close(_server_fd);
}

void
close_SSL_context(void)
{
    SSL_CTX_free(_ctx);
}

size_t
file_get_size(
        char const *restrict filename)
{
    struct stat sb;
    if(stat(filename, &sb) == -1)
    {
        logp("failed to get file length");
    }
    return(sb.st_size);
}

uint8_t
file_is_reg(
        char const *restrict filename)
{
    struct stat sb;

    if(stat(filename, &sb) == -1)
    {
        if(errno == ENOMEM) {diep("stat");}
        else {return(0);}
    }
    return (sb.st_mode & S_IFMT) == S_IFREG;
}

void
send_default_404_msg_SSL(SSL* ssl)
{
    log("missing 404 file\n");
    socket_send_all_SSL(ssl, _http_default_404, sizeof(_http_default_404));
}

void
send_request_denied_SSL(SSL* ssl)
{
    socket_send_all_SSL(ssl, _http_default_417, sizeof(_http_default_417));
}

void send_internal_error_SSL(SSL* ssl) {
    socket_send_all_SSL(ssl, _http_default_500, sizeof(_http_default_500));
}

uint8_t
user_handle_url_SSL(
        SSL* ssl,
        char *restrict url,
        size_t url_size)
{
    // lstrip '/'
    url++;
    url_size--;
    // rstrip '/'
    if(url[url_size - 1] == '/') {url[--url_size] = '\0';}

    if(strcmp(url, "config") == 0 && 0)
    {
        char *buffer =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 28\r\n" // WARN: relies on the string length below
                "\r\n"
                "<html><body>hi</body></html>";
        socket_send_all_SSL(ssl, buffer, strlen(buffer) - 1);
        return(1);
    }
    return(0);
}

// NOTE(nick): we aren't error checking calls to close(); should we be?
void *
handle_connection(
        void *data_ptr)
{
    struct thread_data *data = data_ptr;
    while(1)
    {
        sem_wait(&data->notify);

        // init SSL connection
        SSL *ssl;
        if((ssl = SSL_new(_ctx)) == NULL) {
            log("failed to create SSL connection struct");
            goto EXIT_REQUEST;
        }
        if (SSL_set_fd(ssl, data->client) != 1) {
            log("failed to link client fd to SSL connection struct");
            goto EXIT_REQUEST;
        }
        if (SSL_accept(ssl) <= 0) {
            log("SSL connection rejected due bad client / internal error");
            goto EXIT_REQUEST;
        }

        char recv_buf[RECV_BUFFER_CAP] = {0};
        ssize_t recv_buf_size = 0;
        recv_buf_size = SSL_read(ssl, recv_buf, RECV_BUFFER_CAP); // TODO: unfinished reads
        if(recv_buf_size == 0) {goto EXIT_REQUEST;}
        if(recv_buf_size == RECV_BUFFER_CAP) // NOTE: we do not support dynamic size request
        {
            do // 'finish' read
            {
                recv_buf_size = SSL_read(ssl, recv_buf, RECV_BUFFER_CAP);
                if(recv_buf_size == 0) {goto EXIT_REQUEST;}
            } while(recv_buf_size == RECV_BUFFER_CAP);
            send_request_denied_SSL(ssl);
            goto EXIT_REQUEST;
        }
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
        if(url == recv_buf_end) {send_request_denied_SSL(ssl); goto EXIT_REQUEST;}

        params = url;
        for(protocol = url; protocol < recv_buf_end; protocol++)
        {
            if(*protocol == '?') {*(protocol++) = '\0'; params = protocol;}
            if(*protocol == ' ') {*(protocol++) = '\0'; break;}
        }
        if(params == recv_buf_end) {send_request_denied_SSL(ssl); goto EXIT_REQUEST;}

        for(rest = protocol; rest < recv_buf_end; rest++)
        {
            if(isspace(*rest)) {*(rest++) = '\0'; break;}
        }
        if(rest == recv_buf_end) {send_request_denied_SSL(ssl); goto EXIT_REQUEST;}

        // verify request parameters
        if(strcmp(method, "GET") != 0) {log("failed: was not GET\n"); goto EXIT_REQUEST;}
        if(strcmp(protocol, "HTTP/1.0") != 0
                && strcmp(protocol, "HTTP/1.1") != 0)
        {
            log("failed: http protocol was not supported: %s\n", protocol);
            goto EXIT_REQUEST;
        }
        log(">>> URL: %s\n", url);
        if(params != url) {log("PARAMS: %s\n", params);}

        /* handle request */
        size_t url_size = strlen(url);
        if(user_handle_url_SSL(ssl, url, url_size))
        {
            goto EXIT_REQUEST;
        }

        // strip leading slash
        url_size--;
        url++;

        /* url verification */
        char temp_filename[PATH_MAX] = {0};
        // index handling
        if(url_size == 0) {url = _file_index;}
        else if(url[url_size - 1] == '/')
        {
            memcpy(temp_filename, url, url_size);
            memcpy(temp_filename + url_size, _file_index, sizeof(_file_index)); // NOTE: has \0 at the end
            url = temp_filename;
        }
        else if(!file_is_reg(url))
        {
            memcpy(temp_filename, url, url_size);
            temp_filename[url_size] = '/';
            memcpy(temp_filename + url_size + 1, _file_index, sizeof(_file_index)); // NOTE: has \0 at the end
            url = temp_filename;
        }
        else
        {
            // blacklisted prefixes
            uint8_t valid = 1;
            for(size_t i = 0;
                    i < _blacklisted.gl_pathc;
                    i++)
            {
                if(strstr(url, _blacklisted.gl_pathv[i]) == url)
                {
                    url = _file_error_404;
                    valid = 0;
                }
            }

            // prevent parent directory traversal
            if(valid)
            {
                realpath(url, temp_filename);
                if(memcmp(_curr_dir, temp_filename, strlen(_curr_dir)) != 0)
                {
                    url = _file_error_404;
                }
                else
                {
                    url = temp_filename;
                }
            }
        }
        url_size = strlen(url);
        log("NEW URL: %s\n", url);

        /* find file */
        int fd = open(url, O_RDONLY);
        size_t file_size = 0;

        char *header_type = "HTTP/1.1 200 OK";
        // check 404
        if(fd < 0)
        {
            if(url == _file_error_404) {send_default_404_msg_SSL(ssl); goto EXIT_REQUEST;}

            url = _file_error_404;
            fd = open(url, O_RDONLY);
            if(fd < 0) {send_default_404_msg_SSL(ssl); goto EXIT_REQUEST;}

            file_size = file_get_size(url);
            header_type = "HTTP/1.1 404 NOT FOUND";
        }

        /* send */
        // send header
        file_size = file_get_size(url);
        char send_buf[SEND_HEADER_CAP] = {0};
        size_t send_buf_size = snprintf(
                send_buf, SEND_HEADER_CAP,
                "%s\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %ld\r\n"
                "\r\n",
                header_type,
                mime_type_default(url),
                file_size);
        if(send_buf_size > SEND_HEADER_CAP) {
            log("failed to write header");
            send_internal_error_SSL(ssl);
            goto EXIT_REQUEST;
        }
        socket_send_all_SSL(ssl, send_buf, send_buf_size);

        // send file
        char *file_map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
        if(file_map == MAP_FAILED) {
            // BUG(nick): hopefully the header we sent describes a text format.
            logp("failed to mmap file");
            char msg[] = "500 - Internal Server Error\nFailed to send file";
            socket_send_all_SSL(ssl, msg, strlen(msg));
            goto EXIT_REQUEST;
        }
        close(fd);
        socket_send_all_SSL(ssl, file_map, file_size);
        if(munmap(file_map, file_size)) {
            diep("file munmap failed");
        }

EXIT_REQUEST:
        // end ssl connection
        if (ssl != NULL) {
            unsigned long err = ERR_get_error();
            if (err != SSL_ERROR_SYSCALL && err != SSL_ERROR_SSL) {
                SSL_shutdown(ssl);
            }

            SSL_free(ssl);
        }

        close(data->client);
        data->client = -1;
    }

    return(NULL);
}

int
main(
        void)
{
    uint16_t const server_port = 8080;
    int const server_queue_size = 4096;
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
    log("Server listening on port %d\n", server_port);

    // make sure to close the server
    atexit(close_server);

    // create and configure SSL context
    if ((_ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
        die("failed to create SSL context");
    }
    if (!SSL_CTX_use_certificate_chain_file(_ctx, CERT_FILE)) {
        die("failed to link certification to SSL context");
    }
    if (!SSL_CTX_use_PrivateKey_file(_ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM)) {
        die("failed to link private key to SSL context");
    }
    if (!SSL_CTX_check_private_key(_ctx)) {
        die("private key validity check failed");
    }

    atexit(close_SSL_context);

    // we only serve from the public directory
    chdir("public/");
    if(getcwd(_curr_dir, PATH_MAX) == NULL)
    {
        diep("failed to get current directory");
    }

    // setup blacklist paths
    for(size_t i = 0;
            i < static_array_size(_blacklisted_config);
            i++)
    {
        int flags = GLOB_MARK | GLOB_NOSORT;
        if(i != 0) {flags |= GLOB_APPEND;}
        glob(_blacklisted_config[i], flags, NULL, &_blacklisted);
    }

    // spawn threads
    pthread_t thread_ids[THREAD_COUNT] = {0};
    struct thread_data thread_data_arr[THREAD_COUNT] = {0};
    for(size_t i = 0; i < THREAD_COUNT; i++)
    {
        thread_data_arr[i].client = -1;
        if(sem_init(&thread_data_arr[i].notify, 0, 0) != 0)
        {
            die("failed to init notify semaphore");
        }

        if(pthread_create(
                &thread_ids[i],
                NULL,
                handle_connection,
                &thread_data_arr[i]
                ) != 0)
        {
            diep("failed to spawn thread");
        }
    }

    // accept loop
    size_t thread_to_add_to = 0;
    while(1)
    {
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

        // add to thread client
        while(thread_data_arr[thread_to_add_to].client != -1)
        {
            thread_to_add_to = (thread_to_add_to + 1) % THREAD_COUNT;
        }
        thread_data_arr[thread_to_add_to].client = client_fd;
        sem_post(&thread_data_arr[thread_to_add_to].notify);
    }

    globfree(&_blacklisted);

    return(0);
}
