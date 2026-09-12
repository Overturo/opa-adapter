> **Release mirror.** This repository is a read-only snapshot of
> `github.com/overturo/opa-adapter` 1.0.1, published from Overturo's main
> development repository. Issues and pull requests are welcome here; accepted
> changes are ported upstream and appear in the next release snapshot.
> Security reports: see [SECURITY.md](./SECURITY.md).

# overturo-opa-adapter

**Documentation:** <https://overturo.com/developers/agent-authorization> · **API reference:** <https://overturo.com/developers/openapi>

Go sidecar that consumes Open Policy Agent decision logs and translates
each decision into an Overturo Oversight attestation.

Single static binary; ~15 MB Docker image (`overturo/opa-adapter:v1`).
Apache-2.0.

## Why a sidecar (not a library)

OPA's ecosystem is Go-native; sidecar binaries are how OPA itself is
deployed. The adapter speaks the OAP wire directly via Go's `net/http`
client — no Node runtime, no dependency on the TypeScript or Python
SDKs.

## Architecture

```
   OPA pod ────decision-log────▶  opa-adapter  ────POST /api/v1/oap/attestations────▶  Overturo
                (HTTP or file)         │
                                       └────heartbeat every Ns────▶  Overturo
```

## Run via Docker

```bash
docker run --rm \
  -v $(pwd)/overturo-opa-adapter.yaml:/etc/opa-adapter.yaml \
  -e OVERTURO_ATTESTER_TOKEN=tat_us_... \
  -p 8181:8181 \
  overturo/opa-adapter:v1
```

## Configure OPA to ship decisions

```yaml
# opa-config.yaml
decision_logs:
  service: overturo-adapter
  reporting:
    min_delay_seconds: 5
    max_delay_seconds: 10
services:
  overturo-adapter:
    url: http://localhost:8181
```

## Sample adapter config

See `examples/overturo-opa-adapter.yaml`.

## License

Apache-2.0
