# SPIFFE Integration Guide

`agent-identity-framework` includes a SPIFFE workload identity adapter in the
`spiffe` Go package. This guide covers how to configure SPIRE, issue SVIDs
(SPIFFE Verifiable Identity Documents), and bridge them to the framework's DID
and Verifiable Credential system.

## What SPIFFE Provides

[SPIFFE](https://spiffe.io/) is a set of open standards for workload identity
in cloud-native environments. A SPIFFE identity takes the form of a URI:

```
spiffe://trust-domain/path/to/workload
```

These identities are encoded in X.509 certificates or JWTs called **SVIDs**
(SPIFFE Verifiable Identity Documents). SPIRE is the reference SPIFFE
implementation — it issues and rotates SVIDs for workloads.

## What this Framework Adds

SPIFFE/SPIRE handles *workload* identity — identifying a running process on a
node. This framework adds *agent* identity — a stable, cryptographically-rooted
DID and Verifiable Credential layer on top of the workload identity. The two
complement each other:

| Layer    | Identifier    | Issued by           | Attests to                      |
|----------|---------------|---------------------|---------------------------------|
| SPIFFE   | SVID (URI)    | SPIRE agent         | Workload process on a host      |
| This SDK | DID + VC      | `IdentityManager`   | AI agent logical identity       |

## Prerequisites

- A running SPIRE server reachable from the node running your agent.
- A SPIRE agent installed on the node, registered with the server.
- The `agent-identity-framework` Go server running and reachable.

## SPIRE Setup

### 1. Install SPIRE

Follow the [official SPIRE quickstart](https://spiffe.io/docs/latest/spire/installing/).
A minimal SPIRE server config for development:

```hcl
# spire-server.conf
server {
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  trust_domain = "example.org"
  data_dir     = "/var/lib/spire/server"
  log_level    = "INFO"

  ca_subject {
    country       = ["US"]
    organization  = ["example.org"]
    common_name   = ""
  }
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type   = "sqlite3"
      connection_string = "/var/lib/spire/server/datastore.sqlite3"
    }
  }

  NodeAttestor "join_token" {
    plugin_data {}
  }

  KeyManager "memory" {
    plugin_data {}
  }
}
```

Start the server:

```bash
spire-server run -config spire-server.conf
```

### 2. Register the Agent Node

On the node, generate a join token and start the SPIRE agent:

```bash
# On the server host
TOKEN=$(spire-server token generate -spiffeID spiffe://example.org/node-1 | awk '{print $2}')

# On the agent node
spire-agent run -config spire-agent.conf -joinToken "$TOKEN"
```

### 3. Register Workload Entries

Register the AI agent process as a workload. Replace `<node-spiffe-id>` with
the node's SPIFFE ID and `<uid>` with the UID of the process running the agent:

```bash
spire-server entry create \
  -parentID spiffe://example.org/node-1 \
  -spiffeID spiffe://example.org/agents/my-agent \
  -selector unix:uid:<uid>
```

The SPIRE agent will automatically issue and rotate an X.509 SVID for any
process matching this selector.

## Connecting SPIRE to the Framework

The Go `spiffe` package provides an `SVIDAdapter` that:

1. Watches the SPIRE Workload API socket for SVID updates.
2. Extracts the SPIFFE URI from the SVID.
3. Maps the SPIFFE URI to a DID registered with `IdentityManager`.
4. Returns the corresponding `AgentIdentity`.

### Configuration

```go
import (
    "github.com/aumos-ai/agent-identity-framework/spiffe"
    "github.com/aumos-ai/agent-identity-framework/identity"
)

manager, _ := identity.NewIdentityManager(identity.ManagerOptions{
    Store: identity.NewInMemoryStore(),
})

adapter, err := spiffe.NewSVIDAdapter(spiffe.SVIDAdapterOptions{
    WorkloadSocketPath: "/var/run/spire/sockets/agent.sock",
    IdentityManager:    manager,
    TrustDomain:        "example.org",
})
if err != nil {
    log.Fatal(err)
}
defer adapter.Close()
```

### SPIFFE URI to DID Mapping

The `SVIDAdapter` maintains a mapping from SPIFFE URI to DID. Entries are
registered when an agent identity is created:

```go
agentIdentity, err := manager.CreateIdentity(ctx, identity.CreateOptions{
    OwnerDID:  "did:key:z6Mk...",
    DIDMethod: types.DIDMethodKey,
})

// Register the mapping
adapter.RegisterMapping(
    "spiffe://example.org/agents/my-agent",
    agentIdentity.DID,
)
```

When the SPIRE agent delivers a renewed SVID for
`spiffe://example.org/agents/my-agent`, the adapter resolves it to the
registered DID and validates the `AgentIdentity` record.

### Retrieving an Agent Identity from an SVID

```go
ctx := context.Background()
svid, err := adapter.FetchSVID(ctx, "spiffe://example.org/agents/my-agent")
if err != nil {
    log.Fatal(err)
}

agentIdentity, err := adapter.ResolveFromSVID(ctx, svid)
if err != nil {
    log.Fatal(err)
}
fmt.Println(agentIdentity.DID)
```

## SVID Rotation

SPIRE agents automatically rotate SVIDs before they expire. The `SVIDAdapter`
watches the Workload API for updates using the SVID watcher interface. No
manual rotation is needed.

Key rotation on the DID side is a separate operation — see
[key-management.md](key-management.md) for details. SVID rotation and DID
key rotation are independent lifecycles.

## TLS with SPIFFE SVIDs

X.509 SVIDs can be used directly for mutual TLS between services. The
`spiffe` package exposes the raw `*x509.Certificate` for this purpose:

```go
tlsCert, err := adapter.TLSCertificate(ctx, "spiffe://example.org/agents/my-agent")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{*tlsCert},
    // Configure your trust bundle for peer verification.
}
```

## Troubleshooting

**SPIRE agent socket not found**

Ensure the SPIRE agent is running and the `WorkloadSocketPath` matches the
socket path configured in `spire-agent.conf`. Default:
`/var/run/spire/sockets/agent.sock`.

**SVID not issued for workload**

Check that the workload selector matches the running process. On Linux,
`unix:uid` is the most reliable selector. Verify with:

```bash
spire-server entry show
```

**SPIFFE URI not in mapping**

Call `adapter.RegisterMapping()` after creating the agent identity. The
adapter does not auto-discover identities from SPIRE — the mapping must be
explicitly registered.

**SVID expired**

SPIRE rotates SVIDs automatically. If an SVID has expired, it means the SPIRE
agent is not running or cannot reach the server. Check the SPIRE agent logs.
