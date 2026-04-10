```gcc -o caz caz.c -lcurl -lpthread -O2 -Wall```


### Test with small values first
```./caz -url example.com -duration 10 -concurrency 10```

### Increase gradually
```./caz -url https://example.com -duration 30 -concurrency 100```

### With proxies
```./caz -url example.com -duration 60 -concurrency 200 -proxy-file proxies.txt```
