# kfadapter design

**Audience:** Implementers, security reviewers, and operators  
**Scope:** A provider-extensible containerized local SOCKS5 adapter, browser control plane, and stable installation-bound subscription service; the registered providers are KuaiFan and QuickFox.

## 1. Decision summary

| Area | Decision |
|---|---|
| Adapter interface | Expose one authenticated SOCKS5 listener. Each logical node is represented by a credential-bearing `socks5://` URI. |
| Subscription interface | Render a Base64-encoded, newline-delimited list of SOCKS5 URIs at one installation-bound UUIDv8 path. External consumers fetch that path on their own schedule. |
| Control plane | Serve the local UI and JSON API from the Go daemon. A local access token protects the browser session; provider login credentials remain transient, while validated provider session authority is retained in protected SQLite until explicit provider logout. |
| Data plane | Dispatch KuaiFan nodes through the observed Fanster-branded `WIFIIN` TCP and UDP-over-TCP framing, and QuickFox nodes through its observed native XOR-framed TCP proxy. |
| Deployment | Run production with the host network so OpenWrt LAN addresses and ephemeral UDP association ports are directly reachable. The portable developer Compose uses bridge publishing and therefore supports TCP only from outside its container network. |

```mermaid
flowchart LR
    Browser[Local browser] -->|HTTP UI and provider-keyed JSON API| HTTP[HTTP control server]
    Consumer[External subscription consumer] -->|GET stable subscription URL| HTTP
    Consumer -->|SOCKS5 TCP and UDP| SOCKS[SOCKS5 server]
    HTTP --> Coordinator[Provider coordinator]
    Coordinator --> State[Aggregate provider snapshots, selectors, and subscription state]
    Coordinator -->|Lifecycle driver| KuaiFanControl[KuaiFan control API]
    Coordinator -->|Lifecycle driver| QuickFoxControl[QuickFox control API]
    SOCKS --> State
    SOCKS -->|Protocol registry| Transport[Provider transport]
    Transport -->|WIFIIN or QuickFox native TCP| Node[Selected upstream node]
```

The external consumer remains outside the adapter trust boundary. It fetches the published artifact; its configuration, routing policy, and update schedule are its operator's responsibility.

## 2. Goals and boundaries

### Goals

1. Authenticate to the observed control API without weakening TLS validation or collecting device identifiers.
2. Maintain complete, immutable session and node snapshots; retain valid runtime data across temporary control-plane outages and daemon recreation.
3. Provide a local, browser-authenticated management UI and API whose unexpired opaque sessions survive daemon recreation.
4. Provide selector-authenticated SOCKS5 `CONNECT` and `UDP ASSOCIATE` for eligible nodes.
5. Publish one subscription URL whose credentials survive provider login/logout, account swaps, catalog changes, and restarts; only an access-token change rotates them.
6. Preserve confidentiality of account, session, selector, proxy-authentication, and local access-token material.
7. Fail closed for unsupported SOCKS commands, fragmented UDP, and unverified UDP address forms.

### Non-goals

- Implementing a general VPN, routing engine, or a protocol other than SOCKS5 for external consumers.
- Promising compatibility with a consumer that does not accept Base64-encoded newline-delimited SOCKS5 URIs.
- Exposing the UI, SOCKS listener, or subscription endpoint to the LAN by default.
- Persisting raw local access tokens, provider login accounts or passwords, or relay state.
- Providing an unauthenticated local access-token reset facility.
- Claiming that the legacy tunnel provides modern authenticated encryption.
- Resolving SOCKS UDP domain destinations directly or claiming IPv6 UDP support; observed WIFIIN nodes accept only IPv4 UOT destination frames.

## 3. Trust and state model

The daemon maintains three related state domains:

- **Provider catalog** is an immutable aggregate of provider-keyed snapshots containing browser-safe account views, opaque refresh state, transport authorities, nodes, and expiry hints. Provider mutations preserve the other providers. Probe-only health updates remain process-local.
- **Browser access state** contains `sha256(cookieToken)`, unchanged CSRF material, and expiry. Raw cookie tokens are never persisted. Login attempts and throttling reservations remain process-local.
- **Installation identity** derives subscription and SOCKS credentials from the installation ID and the local access-token verifier. Provider identities and display labels never participate. No separate binding keys, account-scoped selector keys, or rendered subscription body are stored.

Schema v9 contains exactly `schema_version`, `state_metadata`, `access_token_verifier`, `preferences`, `excluded_node_ids`, `active_session`, `active_session_providers`, `active_session_authorities`, `active_session_nodes`, and `browser_sessions`. `InstallationID`, refresh policy, exclusions, provider account/refresh/authority/node rows, expiry hints, and the Argon2id verifier remain durable. Live username maps are rebuilt from the catalog and identity.

The store requires a non-symlinked, current-UID-owned `0700` directory and a regular, non-symlinked, current-UID-owned `0600` database with exactly one link. Initial creation and aggregate replacement are transactional. SQLite uses `_txlock=immediate`, foreign keys, a bounded busy timeout, secure deletion, rollback-journal `DELETE` mode, and `synchronous=FULL`. Every store operation accepts a context and uses context-aware SQL. Integrity checking runs only when opening a database; `Load` never prunes or writes state. The single aggregate write path validates its input and uses prepared statements for bulk inserts. `ErrStateBusy` distinguishes SQLite busy contention from corruption. An injected clock controls browser-session lifecycle; eviction retains the latest expiry dates first (`expires_at_ns DESC`) and removes the oldest excess rows.

`AccessTokenVerifier` persists Argon2id salt, parameters, and a 32-byte derived hash. The supplied access token is trimmed, validated, used transiently for setup or login, and never written to state, logs, browser storage, or diagnostics. Provider login accounts and passwords are likewise transient. Each validated provider snapshot deliberately persists its canonical user ID, opaque refresh state, opaque tunnel authorities, redacted account summary, nodes, and `ExpiresAt` inside the protected database so daemon or container recreation does not force another provider login. `ExpiresAt` is only a staleness hint, not a deletion deadline or tunnel-admission condition. Each linked provider has its own refresh supervisor: the normal due time is the earlier of last success plus the refresh policy and `ExpiresAt` minus a 30-minute safety margin. Startup refreshes stale snapshots immediately without deleting them, and each one-minute tick rechecks the wall clock so suspension cannot skip work. Transient failures preserve the last-good snapshot and retry indefinitely with exponential backoff from one minute to a 30-minute maximum and ±20% jitter (clamped to that maximum). Explicit upstream `ErrSessionRejected` marks only that provider `needs_relogin`, retains its nodes and authority, and suspends automatic attempts until a manual refresh or login succeeds. If token rotation succeeds but the catalog fails, the coordinator durably merges only the returned `RefreshState` into the previous snapshot before returning the error.

The externally visible service state is derived from the aggregate provider
statuses; it is not an independently edited transition graph:

| State | Entry condition | Exit | Runtime side effect |
|---|---|---|---|
| `signed_out` | No provider has a usable persisted session, or access authority is not initialized | A successful login begins `authenticating` | Clear active provider authority and reject new tunnel admissions |
| `authenticating` | A login operation is admitted and provider credentials are being verified | Login publishes a complete aggregate (`ready`), or fails back to `signed_out`/the previous usable state | Do not publish partial provider snapshots |
| `syncing` | A refresh or replacement login is rebuilding the aggregate | Complete publication yields `ready`; a failed refresh yields `degraded` when another usable aggregate remains | Existing complete snapshot remains pinned while network I/O runs |
| `ready` | Every required provider status is OK and a complete aggregate has eligible nodes | Provider refresh failure (`degraded`), logout (`signed_out`) | Admit new SOCKS flows and expose node details |
| `degraded` | At least one provider refresh fails while another usable aggregate remains | All providers recover (`ready`), logout (`signed_out`) | Keep the last complete aggregate; surface per-provider failure |
| `expired` | Not entered. Snapshots are never expired by time; the value is kept for API and frontend compatibility | Login begins (`authenticating`) or logout (`signed_out`) | None while unreachable |
| `error` | No usable aggregate remains after an operation or publication error | Login begins (`authenticating`) or logout (`signed_out`) | Keep process liveness but reject control/data operations that require a session |

`internal/credentials` calculates the installation key, domain-separated UUIDs, and SOCKS usernames; `internal/provider/route.go` owns the shared route identity, canonical node key, and node ID construction:

```text
instanceKey = HMAC-SHA256(AccessTokenVerifier.derivedHash,
                        "kfadapter/instance/v3\x00" || InstallationID)
subscriptionID = UUIDv8(HMAC-SHA256(instanceKey, "kfadapter/subscription/v3")[:16])
socksPassword = UUIDv8(HMAC-SHA256(instanceKey, "kfadapter/socks-password/v3")[:16])
nodeKey = provider || "\x00" || protocol || "\x00" || canonicalHost || "\x00" || decimalPort
nodeID = provider || "_" || base64url(SHA256(nodeKey)[:12])
socksUsername = "n_" || base64url(HMAC-SHA256(instanceKey,
                    "kfadapter/socks-user/v3\x00" || nodeKey)[:12])
```

UUID construction uses the first 16 digest bytes, sets the version nibble to 8 and the RFC 9562 variant bits to `10`, and formats a lowercase canonical 36-character UUID. There is no usable installation key before token setup, so subscription and SOCKS authentication are unavailable. All nodes share the instance password; a node's username depends only on its transport route. Neither current transport consumes any further per-node routing fields: KuaiFan dials `NodeHost:NodePort` and decodes handshake material from opaque authority; QuickFox resolves `NodeHost`, dials `NodePort`, and builds its native prefaces from opaque authority and the requested destination. Model, weight, auto, group/region/line labels and catalog IDs are not transport routing inputs. Authority identity is checked separately when pinning a tunnel.

Provider network I/O retains the existing per-provider lock; publication rebases concurrent provider and probe changes under a short mutation lock. Adding/removing a provider or changing its account never changes the installation identity. Removed nodes are omitted and cannot authenticate; when the same route returns its credentials work again. The subscription response path reads an atomically published catalog, renders a request-local authority, and never accesses SQLite or the mutation lock.

`internal/state` owns domain types, aggregate validation, and the runtime manager. `internal/store` imports `state` and owns SQLite persistence, browser-session lifecycle, secure-file validation, and the `ValidateSQLiteFile` entry point used by `validate-state`; `state` does not import `store`. The migration chain and historical definitions remain in `internal/store/migrate.go`, `migration_v9.go`, and `schema_history.go` because they share current schema definitions and store validation, durability, and codec helpers rather than exposing those internals through a separate migration package.

Offline backup and restore use exactly one `state.db`. A backup is taken while the service is stopped and contains no journal files. Before committing a restore, the tooling validates file identity, SQLite integrity, the fixed schema, foreign keys, and semantic aggregate state; it rejects symlinks, hard links, special files, broad permissions, excess size, journals, unrelated entries, corrupt state, and unknown or unsupported schemas. The prior protected state directory is retained until the replacement is known good so recovery can roll back safely.

The rendered subscription body, derived selector credentials, provider session authority, and browser session tokens are secrets. They must not appear in logs, metrics, diagnostics, browser history, browser storage, or routine API responses. The authenticated node-details endpoint derives one current local SOCKS profile on demand; the browser clears it when the details popover closes and the service never returns provider tunnel secrets.

### Schema v9 release note

Upgrading from v8 changes the subscription URL and SOCKS credentials once. Copy the new `/sub/<36-char-uuid>` URL into each external consumer after upgrading. Subsequent provider account changes no longer rotate credentials. The v8-to-v9 migration keeps both providers' accounts, refresh state, authorities and nodes because every `nodeKey` input is already persisted; neither provider requires re-login or a forced catalog refresh. It recomputes route-based node IDs, merges duplicate routes, remaps known excluded IDs and drops exclusions with no matching node. Existing raw browser-session tokens are hashed so their cookies remain valid. It removes `subscription_authority`, `active_session_selectors`, `last_good`, `last_good_nodes`, and the stored node selector column. The committed `internal/store/testdata/v8.db` fixture was created by the v8 store at HEAD `a25303b` in a temporary worktree before store changes and exercises this preservation contract. Historical v4–v7 migrations retain their existing renewable-authority cutovers before reaching v9.

### 3.1 Provider boundary

`internal/provider` defines provider-neutral lifecycle, snapshot, node, authority, registry, and transport contracts. A driver owns one provider's login and refresh protocol and returns a complete `provider.Snapshot`; refresh state and authority bytes remain opaque outside the originating driver and matching transport. The coordinator in `internal/accounts` serializes mutations, merges the changed provider snapshot with the other current providers, builds one collision-free selector map, and publishes the aggregate transactionally; the same package schedules independent provider refreshes. Provider IDs select lifecycle drivers; protocol IDs independently select SOCKS transports.

`internal/accounts`, `internal/state`, `internal/store`, `internal/credentials`, `internal/subscription`, `internal/app`, `internal/web`, and `internal/socks` validate and route generic provider data only. They neither decode provider refresh state nor interpret authority bytes. A node references an authority in its own provider snapshot with the same protocol, and route-derived node IDs are globally unique. Schema v9 persists the normalized catalog but never derived usernames or rendered bodies.

Provider node IDs use the common `nodeKey` and SHA-256 construction above, prefixed by the provider ID. Hosts are canonical IP addresses or lowercase IDNA DNS names without a trailing dot. Protocols separate distinct transports at the same endpoint. Repeated routes collapse even when group, region, pool, or line labels differ; iOS remains preferred over Windows when KuaiFan profiles expose the same route.

The provider-neutral account contract is `{Tier, SubscriptionActive, SubscriptionEndsAt}`. `Tier` is a nonempty provider-defined display label. An active subscription requires an exact nonzero expiration; an inactive/free account has no expiration. Drivers normalize expired or incomplete paid metadata to their free tier unless the provider response claims currently paid access without the exact expiration required to authorize it, which is rejected. The status API and browser render the tier verbatim, show the expiration only while active, and never infer provider semantics from the label.

`Node.Eligible` is the provider driver's definitive subscription-and-transport admission result. Drivers may discard ineligible catalog rows before returning a snapshot; the coordinator also rejects them from the runtime aggregate. Runtime node APIs, node details, selector maps, and rendered subscriptions therefore contain only eligible nodes. The browser filters the flag again defensively and never presents an ineligible row returned by a stale or mismatched backend.

### 3.2 KuaiFan transaction boundary

All KuaiFan-specific control, fingerprint, encryption, refresh coordination, and tunnel-wire code lives under `internal/provider/kuaifan`. `internal/provider/kuaifan/profile` contains the standalone iOS and Windows wire-profile definitions and deterministic/randomized request builders. The application layer supplies only transient account credentials and a protected random installation ID; it does not choose a client profile, construct device fields, encrypt provider requests, parse provider responses, or decode WIFIIN authority.

The KuaiFan driver runs two immutable control clients: the captured iOS 4.18.4 profile and the recovered Windows 4.3.30 profile. Both reuse hardened HTTPS transport, bounded control codecs, line normalization, and catalog merge; their fingerprints, request schemas, refresh rules, authority parsing, and provider extensions remain separate. Both branches must return the same provider user ID. The account tier is `VIP` only when both profiles report VIP and the earlier of their exact expirations is still in the future; otherwise it is `Standard`, inactive, and has no displayed expiration. A transient failure in either branch leaves the prior complete provider snapshot current; no provisional session, authority, partial catalog, or mixed-generation node set is published. When exactly one profile's session is rejected, the driver publishes a complete snapshot from the surviving profile and keeps the rejected profile's state for a later retry; when both are rejected, refresh returns `provider.ErrSessionRejected`.

Session rejection is recognized only from observed responses. Authenticated KuaiFan endpoints (`user/refresh.do`, `invpn/getAuthority.do`, `invpn/getLines.do`) answer an unaccepted token with business status `-5`, observed live in 2026-10 for both profiles; every other non-success status stays transient. Logging in again from another device does not invalidate an existing token, and refresh returns the same token rather than rotating it.

Catalog merge gives iOS priority for routes present in both profiles and appends Windows-only routes. Historical evidence reported a 169-line labeled union (167 iOS lines plus two Windows-only lines); v9 route identities additionally collapse shared endpoints across display groups. Each source profile validates its own line protocol and marks only verified WIFIIN rows eligible. Each retained node references its source profile's opaque authority, and only `kuaifan-wifiin` decodes that authority. Localized tags compare case-insensitively with `_` and `-` equivalent. See [the protocol evidence report](kuaifan-ios-4.18.4-analysis.md) for request profiles, field-level evidence, historical inventory counts, and Fanster analysis limits.

### 3.3 QuickFox transaction boundary

All QuickFox-specific HTTPS, encrypted-envelope, catalog, membership, authority, and native-relay code lives under `internal/provider/quickfox`. Its stable IDs are provider `quickfox`, protocol `quickfox-native`, and authority `native`. The provider-neutral layers treat all QuickFox refresh and authority bytes as opaque.

```mermaid
sequenceDiagram
    participant UI as Browser/API
    participant D as QuickFox Driver
    participant C as QuickFox Control API
    participant S as Generic Snapshot Store
    participant T as QuickFox Transport
    UI->>D: Login(account, password, installation ID)
    D->>C: POST /user/login
    D->>C: GET /user/info
    D->>C: POST /line/socksServerPoolList
    D->>S: Complete validated Snapshot
    Note over S: Opaque token/device refresh state, opaque native authority, safe nodes
    UI->>D: Refresh(previous Snapshot)
    D->>C: GET /user/info + catalog POST
    D->>S: Atomic replacement Snapshot
    T->>S: Decode only matching quickfox-native authority
```

The login and profile responses use the captured QuickFox AES-CBC envelope and bounded schemas. The original QuickFox 3.59.6 renderer is authoritative for entitlement: its `isVip()` returns SVIP when `userInfo.svip.svipTime > 0`, otherwise ordinary VIP when the quoted signed `userInfo.vipTime > 0`, and free access otherwise. Its native configuration maps free, VIP, and SVIP to values 0, 1, and 2. The adapter preserves those states as the provider-defined `Standard`, `VIP`, and `SVIP` tiers; `payVipFlag`, `userPayVipFlag`, exclusive flags, and `vipInfo[].grade` are not entitlement predicates.

An active VIP or SVIP countdown additionally requires a future exact `vipInfo[].endTime` for the matching period grade: grade 1 for VIP and grade 2 for SVIP. SVIP takes precedence if both countdowns are positive. The matching expiration becomes the browser-visible subscription expiration. Signed nonpositive VIP/SVIP countdowns represent inactive or expired access and are valid; the adapter normalizes them to `Standard` with no displayed expiration. A positive countdown without its matching future exact expiration is rejected as inconsistent provider state.

The catalog's embedded `userInfo` is accepted only as an identity cross-check because it can omit current profile data. The original renderer removes `feeType` 1, 2, and 3 from the free list and distinguishes the SVIP line class as `feeType = 3`. The adapter therefore admits visible, enabled `feeType = 0` lines for every tier, `feeType` 1 and 2 lines for VIP and SVIP, and `feeType = 3` lines only for SVIP. Unknown fee types and malformed catalog rows are rejected rather than guessed.

The persisted QuickFox `RefreshState` contains only the provider token, canonical user ID, and random installation device code needed to fetch a new complete snapshot. The opaque native authority contains the token, user ID, and app ID required by the matching transport. The driver sets a 24-hour staleness hint for scheduled refresh, not an authority-rejection deadline; browser subscription expiry is shown only for an active VIP or SVIP account. An authenticated request whose token is no longer accepted returns envelope code `401` with message `token失效，请重新登录` and no `success` field; the client maps it to `provider.ErrSessionRejected` (observed live in 2026-10). Other envelope codes stay transient. A second-device login does not invalidate an existing token, and the token is not bound to the device code it was issued with.

For a SOCKS `CONNECT`, the QuickFox transport resolves the requested destination to IPv4, opens separate control and data TCP connections to the selected relay, sends the recovered control and destination prefaces, waits for the fixed control acknowledgement, revalidates the immutable session pin, and then relays the stream through the recovered XOR framing. It deliberately returns an error for datagrams: no QuickFox UDP protocol has been verified.

### 3.4 Adding another provider

Provider integration is a clean two-part boundary; do not add provider conditionals to state, subscription, web, or SOCKS packages.

1. Define one stable lowercase `provider.ID` and one `provider.Protocol` per distinct wire protocol. IDs allow lowercase ASCII, digits, hyphen, and underscore, start with a letter, and are at most 32 bytes.
2. Implement `provider.Driver`: `ID`, `Login`, and `Refresh`. Each successful operation must return a complete, immutable, structurally valid `provider.Snapshot`. A failed refresh returns a zero snapshot unless a token rotated, in which case it returns a partial snapshot with `Provider` and the nonempty rotated `RefreshState`; the coordinator retains the previous catalog and authorities. Convert login rejection to `provider.ErrLoginRejected` and explicit invalidation of a stored session to `provider.ErrSessionRejected`; all other refresh failures are transient. Keep the submitted password transient.
3. Populate the snapshot with a canonical provider user ID, redacted display value, nonempty provider-defined tier, normalized active-subscription flag and exact active expiry, a bounded opaque `RefreshState`, at least one bounded opaque `Authority`, and secret-free eligible nodes. Every node ID must be globally unique, every node must reference an authority in the same snapshot, and the node and authority protocols must match. Resolve subscription and transport support inside the driver, retain only `Node.Eligible` rows, and never silently fall back to direct dialing.
4. Implement `provider.Transport` for each protocol. `RelayStream` and `RelayDatagrams` receive only a selected relay endpoint, destination, opaque authority, bounded dial function, and final `Admit`/`Ready` gates. Decode authority only here. Call `Admit` after the provider handshake and immediately before `Ready`; return an explicit error for an unverified stream or datagram mode.
5. Construct the client, driver, and transport in `cmd/kfadapter/main.go`, then add them to `provider.NewRegistry`. Duplicate IDs/protocols fail startup. The coordinator automatically exposes registered provider IDs, serializes per-provider login/refresh/logout, merges snapshots, regenerates selectors, persists the aggregate, and emits state events.
6. Add the provider's friendly browser label to `web/src/App.tsx` if desired. The UI already discovers provider IDs, supports one account per provider, and uses generic provider-keyed login, refresh, logout, status, node, and subscription flows; an unknown ID falls back to its literal value.

No provider-specific database table or migration is required for a new driver. SQLite stores the generic provider, authority, node, and selector rows. A schema change is justified only if the provider-neutral `provider.Snapshot` contract itself changes. The driver owns opaque byte encoding and versioning; `Snapshot.Valid`, coordinator aggregation, persistent semantic validation, and transport protocol matching are the mandatory gates.

The minimum verification is: control-client fixture tests for login/profile/catalog parsing and bounds; driver tests for complete snapshots, partial rotated-token results, explicit session rejection, refresh, account-tier eligibility, staleness hints, and malformed provider data; transport tests against a captured or independently verified relay for handshake, destination, fragmentation, cancellation, and unsupported modes; persistence round-trip; and an end-to-end SOCKS connection through the registered protocol. A plain TCP node probe proves only relay-port reachability and is not transport verification.

## 4. Listener and deployment contract

### 4.1 Configuration

The public configuration has one shared listener address, an optional shared hostname, and separate management, proxy, and provider sections:

```yaml
listenAddr: 0.0.0.0
# hostname: adapter.example.com
management:
  port: 10809
  sessionTTL: 30m
proxy:
  port: 10808
  dialTimeout: 10s
  handshakeTimeout: 15s
provider:
  requestTimeout: 15s
  refreshInterval: 2h
```

`listenAddr` is one canonical numeric IPv4 or IPv6 address used by both listeners; `management.port` and `proxy.port` must differ. `hostname` is an optional bare DNS name used by management admission and client-facing advertisements, not by socket binding. A missing configuration file generates `listenAddr: 127.0.0.1` with ports `10809` and `10808`; the checked-in host-network deployment uses `0.0.0.0`.

Before opening state, startup enumerates up local interfaces. A specific `listenAddr` must be assigned to one of them; a wildcard requires at least one up address of the same family. Failure stops startup without selecting another interface or creating state. Socket binding remains the final authority and may still fail if the address changes or a port is unavailable.

Management admits the configured numeric Host, same-family numeric Hosts for a wildcard listener, and the optional configured hostname, always on the management port. Advertisements follow the address by which the client reached management:

1. A request using the configured hostname receives that canonical hostname in the subscription URL and SOCKS authority.
2. A non-hostname request to a wildcard listener must carry a canonical numeric Host. The service preserves that IP and substitutes only `proxy.port` when producing status, node details, and subscription bodies.
3. A non-hostname request to a specific listener uses the configured IP, which is also the only admitted numeric Host.

`localhost` is an implicit hostname only when `listenAddr` is wildcard or loopback. It does not need to be copied into `hostname`, is normalized to lowercase in advertisements, and cannot bypass a specific non-loopback bind. An explicitly configured `hostname: localhost` remains valid.

This intentionally does not inspect `RemoteAddr`, which identifies the client, or guess among LAN, WAN, VPN, and container interfaces. A LAN request therefore advertises the LAN IP it used; a public or upstream-NAT request advertises its public Host; and a VPN request advertises its VPN Host. Public forwarding must preserve the configured management and proxy ports, because there is no reliable way for the daemon to infer different external mappings. A proxy or gateway must preserve the original Host. State-changing requests and event streams additionally require an Origin exactly matching that Host, and CSRF checks remain enforced.

The process working directory is fixed at `/kfadapter`; configuration is always loaded from `./config.yaml`, and SQLite state is always stored under `./data`. Provider API origins are fixed by their protocol implementations. None of these paths or origins is configurable.

`/healthz` is the only unauthenticated operational endpoint; it returns a fixed non-cacheable success while the daemon is live and discloses no account, node, subscription, or upstream state.

### 4.2 Compose contract

Production Compose uses the host network and does not publish or translate ports:

```yaml
network_mode: host
```

The developer Compose file remains portable across Docker Desktop and Linux by using bridge networking with host-loopback port mappings.

There is one project service: `kfadapter`. Both Compose configurations declare only the bare logical named volume `db_data:` and mount it as `db_data:/kfadapter/data`, never as a parent-directory mount. The container executable is `/kfadapter/kfadapter` and its database path is `/kfadapter/data/state.db`. Production retains the Compose project name `kfadapter`, so Docker Engine names the managed volume `kfadapter_db_data`; developer Compose retains `kfadapter-local`, producing `kfadapter-local_db_data`. Neither Compose volume has `external` or `name` attributes. The image supplies an empty `0700`, UID `65532:65532` `/kfadapter/data` directory, so normal copy-up initializes a newly created volume. Retaining a volume preserves `state.db` and the locally durable provider and browser sessions across container recreation.

Both volumes are Compose-managed. `docker compose down -v` removes the active project's `db_data` volume and therefore its `state.db` and persisted sessions; plain `docker compose down` and force recreation retain it. First run needs no volume bootstrap: the supported production invocation uses `docker compose --env-file /dev/null -f compose.yaml up` so the same explicit image inputs validated by preflight create the volume and initialize its protected state directory without loading a project `.env`. Both Compose configurations mount the configuration read-only with `bind.create_host_path: false`, so a missing host `config.yaml` fails instead of being silently created as a directory. They run as numeric UID/GID `65532:65532`, use a read-only root filesystem, drop all capabilities, set `no-new-privileges`, bound resources and logs, and provide a size-limited `tmpfs` for `/tmp`.

The image working directory is `/kfadapter`; the service runs `./kfadapter`, loads `./config.yaml`, and stores SQLite at `./data/state.db`.

Production Compose runs `${KFADAPTER_IMAGE_REPOSITORY:-ghcr.io/oshinop/kfadapter}@${KFADAPTER_IMAGE_DIGEST}`; the digest is required and tags are never used. The Dockerfile builds the frontend in a digest-pinned `node:24-alpine` stage and the Go binary in a digest-pinned `golang:1.26.5-alpine` stage, then runs the result from digest-pinned `alpine:3.23`. `.github/workflows/ci.yml` runs frontend tests, Go vet and race tests, lint, govulncheck, Compose validation, and an image smoke test. Publishing to `ghcr.io` runs only after those pass: `latest` from `main`, and version tags from `v*`. The state directory remains owned by numeric UID/GID `65532:65532`.

The image and service do not require a privileged bind, Docker socket, host PID namespace, host `/sys`, host home directory, browser profile, or external-consumer state. A configuration or startup failure must stop the daemon rather than widen its bind or quietly select another address.

After both listeners bind, startup emits one safe endpoint line using the configured management and proxy addresses. It must not report a subscription path, selector credential, rendered subscription body, account identifier, session authority, or upstream secret.

With production host networking, `0.0.0.0` covers the OpenWrt host interfaces directly. The validated HTTP Host selects the client-facing address as described above; no interface-name heuristic or extra advertised-address field is required. Configuring one specific OpenWrt address restricts both listeners to that interface.

Host networking is not required by request-derived advertisement itself: a bridged container can use a wildcard `listenAddr` plus published ports. It is required when `listenAddr` names a specific OpenWrt host-interface address, because NIC validation and socket binding see only the container namespace in bridge mode. Production keeps `network_mode: host` so both wildcard and specific OpenWrt addresses have direct host-interface semantics.

### 4.3 Lifecycle

The healthcheck loads `./config.yaml`, checks HTTP `/healthz` through the configured management endpoint, and opens a bare TCP connection to the configured proxy endpoint without authenticating or opening an upstream tunnel. Health reporting is observability, not recovery: a critical accept-loop or supervisor failure exits the daemon for Compose restart.

On termination, the daemon stops accepting new browser and SOCKS work, cancels refreshes, drains established relays for a bounded period, closes remaining sockets, flushes protected state, and exits before the Compose grace period. No secret-bearing log or diagnostic file is written to the image filesystem.

### 4.4 State operations

On first deployment, set `KFADAPTER_IMAGE_DIGEST`, run `scripts/preflight.sh`, then run `docker compose --env-file /dev/null -f compose.yaml up -d`; Compose creates the managed `kfadapter_db_data` volume and copy-up initializes `/kfadapter/data`. The explicit null environment file is part of the production contract: it prevents a project `.env` from changing the repository after preflight. There is no separate state-volume bootstrap. Once the volume exists, its mountpoint must be a `0700` directory owned by the configured numeric runtime identity and either empty or contain exactly one regular, single-link `0600` `/kfadapter/data/state.db`; unrelated entries are rejected.

Backups are offline: stop `kfadapter`, then run `scripts/backup-state.sh [archive.tar.gz]`. Backup, restore, and upgrade resolve the managed production `kfadapter_db_data` volume. Backup revalidates the resolved mountpoint and file identity, requires every container using the volume to remain stopped, copies only `state.db` through no-follow file descriptors, verifies the SQLite header and source stability, and creates a collision-safe `0600` archive containing exactly one `state.db`. Restores run as root through `scripts/restore-state.sh archive.tar.gz`; they bound compressed and expanded input, reject ambiguous archive members, validate staged SQLite through an isolated digest-pinned read-only container with networking disabled, preserve the previous state directory for rollback, and atomically replace only a fully validated database.

`scripts/upgrade.sh` runs as root and requires an immutable replacement digest plus a healthy current digest-pinned service. The replacement repository defaults to `ghcr.io/oshinop/kfadapter`; `KFADAPTER_IMAGE_REPOSITORY` remains an optional untagged override. The script resolves `kfadapter_db_data`, verifies that the running service mounts that volume at `/kfadapter/data`, stops the daemon, creates a protected pre-upgrade backup, pulls and recreates only the requested digest, verifies the replacement mount identity, and waits for health. Any pull, start, mount, or health failure restores both the previous immutable image and the exact protected state archive; rollback also verifies its recreated mount and stops any partial or unhealthy prior service before reporting failure.
An upgrade rejects a tag-qualified or otherwise noncanonical current image before stopping the service or creating a backup, because the rollback validation path accepts only the same untagged repository-and-digest form.

## 5. Local browser access and API

Open management through the configured numeric address or optional hostname, for example `http://127.0.0.1:10809/` or `http://adapter.example.com:10809/`. Fragments and local-session shortcuts are not part of the interface.

On the first local visit, the UI obtains access status and asks the user to set and confirm an access token. The token is trimmed valid UTF-8 and must be 16 through 128 bytes after trimming. Setup is available exactly once. On later visits, an unauthenticated user enters the existing token to create a new local browser session; there is no reset API.

Session cookies are `HttpOnly` and `SameSite`. Their SHA-256 token hashes, CSRF records and expiry persist in `state.db`, so unexpired cookies survive recreation. Startup validates and prunes expired or excess records before admitting them. The browser obtains CSRF material through authenticated status and sends it on mutations. A successful access-token change invalidates every browser session, including event streams, and establishes a replacement session for its caller.

| Endpoint | Access rule | Result |
|---|---|---|
| `GET /api/v1/access/status` | None | Non-cacheable `{initialized, authenticated, csrfToken?, expiresAt?}`; the optional fields are present only for an authenticated session. |
| `POST /api/v1/access/setup` with `{token}` | Initial setup only | Valid first setup returns `201` and establishes a session; an already initialized installation returns `409`. |
| `POST /api/v1/access/login` with `{token}` | Initialized installation | Valid token returns `200` and establishes a session; an invalid token receives the uniform `401`; a throttled attempt receives `429`. |
| `POST /api/v1/access/token` with `{current, next}` | Session, CSRF and exact Origin | Argon2id-verifies `current`, requires a different valid `next`, persists a newly salted verifier, rotates subscription/SOCKS credentials, invalidates all browser sessions, and returns `200` with a replacement caller session. Current-token failures use the access-login throttle. |
| `POST /api/v1/access/logout` | Authenticated session | Locks the console by clearing only the local browser session. |
| `POST /api/v1/auth/logout` with `{provider}` | Authenticated session | Signs out only the named provider account while retaining local browser access and other providers. |
| `POST /api/v1/auth/login` with `{provider, account, password}` | Authenticated session | Adds the named provider account and returns only its redacted account view; an already-linked provider rejects a second account. |
| `POST /api/v1/control/refresh` with `{provider}` | Authenticated session | Refreshes only the named provider from its opaque persisted refresh state. |
| `GET /api/v1/status` | Authenticated session | Returns provider IDs and provider-keyed browser-safe account views containing `provider`, redacted `display`, provider-defined `tier`, `subscriptionActive`, and `subscriptionEndsAt` only for active subscriptions; raw account IDs and authority are omitted. |
| `GET /api/v1/nodes` | Authenticated session | Returns status-only eligible node rows without endpoints or credentials. |
| `GET /api/v1/nodes/{id}/details` | Authenticated session | Returns one non-cacheable, locally derived SOCKS profile for the current node. |
| `GET /api/v1/subscription/url` | Authenticated session | Returns reusable `{url}`. Ordinary status responses never contain the URL. |
| `GET /api/v1/subscription` | Authenticated session | Returns URL-free subscription metadata: active state and node count. |
| `POST /api/v1/nodes/{id}/probe` with `{}` | Authenticated session | Performs one bounded direct TCP reachability check to the relay host and port. It does not send provider authentication, a tunnel preface, or a destination. Success returns `{nodeId, health, tcpLatencyMs?, probedAt}`. |
| `GET /api/v1/events` | Authenticated session and exact same-origin `Origin` | Opens a bounded SSE stream for coarse browser-safe state and probe events; cookie validity is rechecked during the stream. |
| `POST /api/v1/diagnostics/export` with `{}` | Authenticated session | Downloads a redacted JSON diagnostic; credentials, URLs, authorities, and account identifiers are excluded. |

Every API response is non-cacheable. Protected mutations require `Content-Type: application/json`, an exact same-origin `Origin`, the browser session cookie, and the `X-CSRF-Token` obtained from authenticated access status. Failures use `application/problem+json` with `{code, status, title, detail?}`. The browser must branch on `code`, not provider text. Probe codes are `probe_busy` (`429`), `node_not_found` (`404`), `node_ineligible` and `node_snapshot_unavailable` (`409`), `stale_probe` (`409`), `tcp_probe_timeout` (`504`), and `tcp_probe_failed` (`502`).

`GET` or `HEAD /healthz` is the unauthenticated container liveness endpoint and returns only `ok` or `unhealthy`. It is not a control API. The external installation-bound `GET /sub/<uuid>` route is specified separately below and does not use a browser session.


After local access is established, users can link one account per provider. Removing a provider retains local browser access and all other providers. The installation-bound URL remains unchanged across account changes; the UI presents it for copying but never stores it in browser storage or history.

## 6. SOCKS5 adapter

The SOCKS server supports method negotiation, RFC 1929 username/password authentication, and `CONNECT` with IPv4, IPv6, and domain targets. KuaiFan WIFIIN nodes additionally support `UDP ASSOCIATE` with IPv4 datagram destinations; QuickFox's recovered native relay is TCP-only. Datagram support is an optional transport capability (`provider.DatagramTransport`): `UDP ASSOCIATE` on a TCP-only transport receives reply `0x07` before any UDP socket is bound, and `BIND` is always rejected with `0x07`. A transport that cannot reach a destination address type returns `provider.ErrAddressUnsupported`, which SOCKS maps to reply `0x08` (for example, IPv6 targets on QuickFox). Fragmented, domain-targeted, and IPv6-targeted UDP datagrams are discarded one at a time rather than leaking into a direct fallback; a discarded datagram never ends the association.

A URI's username selects a canonical eligible route and its password authenticates the installation. SOCKS first looks up the username in an atomically swapped map built from the current snapshot, then compares the shared UUIDv8 password in constant time. Node resolution is indexed, never a linear scan on authentication. Removed routes fail explicitly; an exact route reappearance deterministically resumes its username without falling back to another upstream. Pin revalidation compares `nodeKey` and opaque authority identity, not display labels.

For each `CONNECT`, the server authenticates and resolves a compact pin, checks registry-pointer identity, session, authority, and canonical eligible node before dial, establishes the observed upstream handshake, then checks the pin again before returning SOCKS success. An admitted relay keeps its compact pin and may drain across a later logout, refresh, or account change; it is never remapped. Elapsed time alone never refuses admission.

For each `UDP ASSOCIATE`, the server binds an ephemeral UDP socket to the TCP control connection's local address. It validates every datagram's RFC 1928 header (RSV and FRAG must be 0, ATYP must be known) and discards a failing datagram before it reaches the transport or pins a port; valid datagrams pass to the transport byte-for-byte. Every datagram is checked against the TCP peer IP, and the server either enforces the requested client port or pins the first valid source port. A requested `DST.ADDR` that differs from the TCP peer IP is accepted, because clients behind NAT report their own interface address; datagram-time peer filtering remains the security check. Closing the TCP control connection closes both the UDP socket and its upstream stream. Production host networking is required so LAN clients can reach the dynamically assigned UDP port.

The upstream UDP stream uses the Fanster-branded WIFIIN type-`0x23` handshake whose encrypted target is the selected WIFIIN node itself. Each continuously encrypted frame is `uint16 body length`, IPv4 address and port, `uint16 flow ID`, and UDP payload. The server echoes the flow ID in response frames. The implementation accepts zero-length upstream keepalives, handles arbitrary TCP fragmentation, and never resets the AES-CFB context between frames.

The WIFIIN server sends its IV with its first downstream payload, so the IV wait is not bounded by the handshake timeout. On the stream path, a read deadline is armed only after the client half-closes its write side, when the server must answer or close; until then the flow ends only on context cancellation or connection close. The UDP-over-TCP path never arms an IV deadline and relies on cancellation and control-connection close.

The observed data plane uses legacy AES-CFB and a legacy MD5-derived key schedule. It provides no modern AEAD guarantee. “Fanster” is a marketing name in available public material, not a recovered second wire specification; the adapter must not guess another transport. The UI must present the legacy cipher as a compatibility risk, and the adapter must keep strict certificate validation for its HTTPS control plane.

## 7. Subscription endpoint

### 7.1 Route and body

The sole external-consumer route is:

```http
GET /sub/<36-char-uuid>
```

The strict parser accepts only lowercase canonical UUIDv8 text with RFC 9562 variant `10`, exactly one path segment, and no escaped aliases or trailing slash. The path is sensitive and is never logged or included in errors. After acquiring a bounded response slot, the handler validates the strict path, compares its UUID in constant time, loads the immutable catalog atomically and renders. It has no mutation, database write or global request lock.

Malformed, revoked or unknown paths, unsupported methods, and empty selections return an empty non-cacheable `404` without redirect. Saturation is checked before path validation and returns the uniform empty `503` with `Retry-After: 1`, for valid and invalid paths alike. Optional `provider`, exact `group`, and case-insensitive `name` filters affect only presentation; duplicate parameters, empty values and unknown providers return the same empty `404`.

Success is standard padded Base64 of deterministically sorted, newline-delimited URI text, generated with URL-library escaping:

```text
socks5://n_<route-user>:<shared-instance-uuid-password>@127.0.0.1:10808#Node%2001
socks5://n_<other-user>:<shared-instance-uuid-password>@127.0.0.1:10808#Node%2002
```

The URI authority uses the configured hostname when the request used it; otherwise it uses the configured specific IP or validated numeric wildcard Host, with `proxy.port`. Advertisement remains request-local, so simultaneous requests with different Host headers never contaminate one another. Responses use `Cache-Control: no-store`; neither `304` nor persisted rendered-body caching is used.

### 7.2 Stability and token rotation

The URL, shared password and every route's username remain byte-identical across logout/login, account swaps, provider addition/removal, store reopen, and refreshes that change labels. Absent nodes are omitted and stop authenticating; their credentials work again when they return. Provider authority changes retain local credentials but invalidate a not-yet-admitted stale pin. Already admitted relays keep their compact pin and may drain without remapping.

Only authenticated `POST /api/v1/access/token` rotates the identity. A newly salted verifier changes the instance key, URL, usernames and shared password. The old URL immediately receives the uniform empty `404`, and the old password is rejected even with a new username. Every browser session is revoked and the caller receives a replacement session. A rejected current token is throttled by the existing access throttle; an invalid or unchanged next token is a separate `400` and is not counted as a current-token failure. There is no unauthenticated reset. Copy the replacement URL to external consumers after a token change; [`deploy/dae/config.dae.template`](../deploy/dae/config.dae.template) uses the UUID placeholder.

## 8. Security and observability

- Access-token verifier data, instance keys, subscription UUIDs, usernames, rendered bodies, passwords, account identifiers, session tokens, and provider secrets are redacted from logs, metrics, diagnostics, and routine APIs.
- Credentials and subscription-path tokens are never accepted through query parameters.
- Browser security uses a restrictive CSP, frame denial, exact host/origin handling, same-origin checks, CSRF protection, and no external frontend assets.
- Request bodies, control responses, rendered subscriptions, and response writers are bounded.
- Node metrics use opaque selectors rather than provider addresses. Rendered-body hashes are not metrics.
- The service starts and remains non-root, capability-free, read-only outside its state mount and bounded temporary storage.
- Current-state restores reject SQLite payloads with symlinks, special files, hard links, broad permissions, excess size, journals or unrelated entries, integrity failures, unknown or unsupported schemas, invalid foreign keys, invalid bounds, or inconsistent aggregates.

## 9. Verification requirements

Focused verification must cover observable behavior, including:

1. A missing configuration file defaults `listenAddr` to `127.0.0.1` with management port `10809` and proxy port `10808`; the checked-in deployment uses a wildcard with production host networking.
2. Startup rejects a specific IP not assigned to an up interface and a wildcard without an up same-family interface. Management admits the configured numeric Host, same-family numeric Hosts for a wildcard, optional configured hostname, and implicit `localhost` for wildcard or loopback binds. Client-facing SOCKS addresses advertise the hostname used or preserve the validated numeric Host while replacing only the port; request Origin remains exact.
3. First access through the bare local URL accepts only a trimmed valid UTF-8 token of 16–128 bytes, creates the sole verifier, and establishes a protected browser session. A second setup conflicts; bad login is uniformly unauthorized; throttling is observable.
4. Raw local access tokens and provider login accounts/passwords never appear in persistent state, diagnostics, logs, or routine API responses. SQLite retains the Argon2id verifier; active provider session authority remains durable until explicit provider logout.
5. An offline restore accepts exactly one current `state.db` only after file-identity, SQLite integrity, fixed-schema, foreign-key, and semantic aggregate validation. Corrupt state, a malformed or unsupported schema, and every rejected file form fail closed without committing the replacement.
6. Every structurally valid provider snapshot, its nodes, and selector map remain available after daemon and container recreation, even when its staleness hint has passed; browser sessions retain their separate expiry contract. Stale snapshots refresh immediately at startup. Rejection of one provider for 72 hours must not affect another provider's schedule or credentials. Transient failures for 48 hours must retain the snapshot, retry with no delay above 30 minutes, and recover on the first success. A partial refresh must persist a rotated token for the next attempt. Only explicit provider logout removes a snapshot; elapsed time never deletes authority or refuses a new tunnel.
7. A stability table checks URL, rendered credentials and node-details credentials across logout/login, account swaps, provider add/remove, store reopen and label-only refresh. Only access-token change rotates them; the old URL receives an empty `404`, the old SOCKS password is rejected, and the new URL/password and replacement browser session work.
8. Strict UUIDv8 paths return the exact Base64 body; malformed and revoked paths return the empty not-found contract. Saturation precedes path validation. Fifty concurrent subscriptions across three Host headers each render their own authority without a data race, database write or request-global mutation.
9. SOCKS authenticates the selector, rejects unsupported commands, dispatches eligible `CONNECT` requests through the selected KuaiFan WIFIIN or QuickFox native TCP transport, relays KuaiFan IPv4 `UDP ASSOCIATE` through the observed WIFIIN UOT transport, discards fragmented and unsupported-address UDP datagrams, preserves pre-admission pin checks, and never remaps an admitted flow.
10. Production and developer Compose declare the managed logical `db_data` volume, mounted at `/kfadapter/data`, with no external or custom-name override. Under the fixed `kfadapter` production project it resolves to `kfadapter_db_data`; under `kfadapter-local` it resolves to `kfadapter-local_db_data`. Both preserve `state.db` across container recreation while remaining non-root and read-only outside documented writable mounts. `docker compose down -v` deletes that project's managed volume and its persisted provider and browser sessions; plain `down` does not.
11. The real v8 fixture migrates to exact schema v9 with both provider accounts, refresh state and authorities retained, route IDs and exclusions remapped, browser cookie hashes matching the original raw tokens, and no re-login. Store tests cover context cancellation, read-only Load, busy errors, oldest-first session eviction and verifier-change revocation.
12. Release gates are clean `gofmt -l cmd internal`, `go vet ./...`, `golangci-lint run ./...`, `go test -race -count=1 ./...`, and `npm ci && npm run build && npm test` in `web`. State scripts contain no schema/table constants: isolated `validate-state` enforces v9. With no Python script test suite, run `python3 -m py_compile` on the four helpers and report that the archive round-trip was not executed.


## 10. References

- [RFC 1928: SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 1929: Username/Password Authentication for SOCKS V5](https://www.rfc-editor.org/rfc/rfc1929)
- [Docker Compose service reference](https://docs.docker.com/reference/compose-file/services/)
- [KuaiFan iOS 4.18.4 capture and IPA evidence](kuaifan-ios-4.18.4-analysis.md)
