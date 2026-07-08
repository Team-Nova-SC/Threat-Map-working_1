import redis
import time

url = "redis://default:gQAAAAAAAZdnAAIgcDI0YjFiMjBhNmY3ZTA0MzU0YjI4NDc2OTRlOGRmNGJhNQ@flexible-urchin-104295.upstash.io:6379"
print("Connecting to Redis...")
start = time.time()
try:
    r = redis.Redis.from_url(url, socket_timeout=5)
    r.ping()
    print("Success")
except Exception as e:
    print(f"Error: {e}")
print(f"Time taken: {time.time() - start:.2f}s")
