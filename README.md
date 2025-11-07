# Waiter : waits for users
Simple HTTP/1.1 TLS file server; its poorly threaded.

# How to Run:
```sh
make release
./waiter -p 8000 -t 4 -f 512
./waiter -p8000 -t4 -f512
./waiter --port 8000 --thread-count 4 --file-cache-size 512
```
