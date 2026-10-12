# keeps

Encrypted local secret store for Kraken. API keys, credentials, and small files. AES-256-GCM at rest. No daemon. No catalog. No cloud.

```bash
kraken tentacle add <this-repo>
printf '%s' '{"v":1,"action":"put","payload":{"name":"openai","value":"sk-…"}}' | sh handler.sh
printf '%s' '{"v":1,"action":"get","payload":{"name":"openai"}}' | sh handler.sh
# value is •••• unless payload.reveal=true
```

See [docs/USAGE.md](docs/USAGE.md) and [docs/SECURITY.md](docs/SECURITY.md).
Brand: same ink / teal / foam / gold as watch, marks, board. Kit: spawn · ink · keel.
