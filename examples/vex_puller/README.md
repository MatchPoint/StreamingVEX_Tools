# VEX pull subscriber example

Uses the **`streamingvex-pull`** CLI from the parent [StreamingVEX_tools](https://github.com/MatchPoint/StreamingVEX_tools) package.

```bash
cd ..
pip install -e ".[dev]"
cp examples/puller.config.example.json puller.config.json
# Edit base_url and api_key
streamingvex-pull --config puller.config.json
```

Full reference: [docs/vex-puller.md](../../docs/vex-puller.md)

Server-side guide: [Enterprise delivery](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/enterprise-delivery.md)
