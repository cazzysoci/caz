```gcc -o caz caz.c -lcurl -lpthread -O2 -Wall```

### Run with random cookies enabled (default)
```./caz -url https://example.com -duration 30 -concurrency 100```

### Run without random cookies
```./caz -url https://example.com -duration 30 -concurrency 100 -no-random-cookie```

### With proxies and random cookies
```./caz -url https://example.com -duration 60 -concurrency 200 -proxy-file proxies.txt```
