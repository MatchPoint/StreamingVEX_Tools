# Webhook receiver example

Runnable sample for **`catalog.vex.updated`** deliveries. Full guide: [docs/webhook-receiver.md](../../docs/webhook-receiver.md).

```bash
pip install "streamingvex-tools[webhook]"
export WEBHOOK_SECRET=your-secret
python receiver.py --port 9000
```

Register `http://127.0.0.1:9000/webhook` in StreamingVEX with the same secret.
