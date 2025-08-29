# github-bulk-env-update
A simple script to Update secrets in Github repo environments in bulk


Usage:

```bash
Saraths-iMac:github-bulk-env-update sarath$ go run main.go -config config.yml 
2025/08/29 19:25:04 ==> Repo: Modus-sandbox/sarath-test
2025/08/29 19:25:04   -> Ensure environment: dev
2025/08/29 19:25:05     ✓ API_KEY
2025/08/29 19:25:06     ✓ SIMPLE_SECRET
2025/08/29 19:25:06   -> Ensure environment: prod
2025/08/29 19:25:07     ✓ DB_PASSWORD
2025/08/29 19:25:08     ✓ API_URL
2025/08/29 19:25:08 All done.
```

The config.yml example is in this repo.
