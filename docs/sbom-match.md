# SBOM match CLI

Client-side SBOM-to-catalog matching. **Your SBOM never leaves your machine.**

## Commands

```bash
streamingvex-sbom-match sync-index --base-url http://127.0.0.1:8000 --out catalog-match-index.json
streamingvex-sbom-match match --sbom firmware.cdx.json --index catalog-match-index.json --out report.json
streamingvex-sbom-match subscribe --config matcher.config.json --report report.json
streamingvex-sbom-match fetch-vex --config matcher.config.json --report report.json --out-dir ./vex/
streamingvex-sbom-match outreach-draft --downstream-org "Acme" --downstream-product "Firmware X" \
  --target-supplier "VendorCo" --target-product "Widget" --target-version "2.0"
```

Server docs: [StreamingVEX sbom-matching.md](https://github.com/MatchPoint/StreamingVEX/blob/main/docs/user/sbom-matching.md).
