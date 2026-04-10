```gcc -o caz caz.c -lcurl -lssl -lcrypto -lpthread -O2 -Wall```


### Compile
```gcc -o caz caz.c -lcurl -lpthread -O2 -Wall```

### Test with a small configuration first
```./caz -url https://example.com -duration 10 -concurrency 10```

### If that works, increase concurrency
```./caz -url https://example.com -duration 30 -concurrency 100```

### With proxies
```./caz -url https://example.com -duration 60 -concurrency 200 -proxy-file proxies.txt```
