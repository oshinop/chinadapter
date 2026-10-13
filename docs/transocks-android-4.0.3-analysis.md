# Transocks (穿梭) protocol dossier

> Evidence paths (`x/...`, `android/...`, `tv/...`, `router-rootfs-complete/...`) refer to the client workspace kept outside this repository at `clients/20261013/transocks/`. No credentials, tokens or account identifiers are recorded.

Date: 2026-10-13. **Static analysis only.** No account registration, login, or live API request was made. No chinadapter repository files were changed; no provider implementation or connectivity claim is delivered.

## 1. Conclusions and evidence boundary

- **Official Android 4.0.3 has a straightforward HTTPS/JSON control plane:** account-password login, a token-type/access-token `Authorization` header, an API2 line catalog, and per-line connect calls returning proxy credentials. The traced path has no application-layer signature or encrypted request body. This conclusion is limited to the official Android paths inspected, not every legacy Transocks API. [A1, A2, A3]
- **The active official Clash config builder emits ordinary Shadowsocks or Trojan, including optional Trojan-over-WebSocket.** SS requests advertise `chacha20-ietf-poly1305`. No SS plugin is emitted. [A4, A5]
- **[INFERENCE] Stock mihomo/sing-box should be able to use those ordinary SS/Trojan credentials directly.** Inspected native stream/packet framing has no extra Transocks account/device/token preamble. This is static interoperability evidence, not a connection test or proof that every local Clash patch equals upstream. [N1, N2]
- **“Free mobile”/anonymous mode still provisions a server-side device account.** The app calls device registration, receives generated username/password, and logs in normally. A bearer token alone is not evidence that free lines are usable without real-name/binding gates. No such registration was performed. [A6, A7]
- **Two implementation constraints remain unresolved:** renewing an account session without retaining its password, and obtaining usable credentials for every advertised node without invalidating earlier connect sessions. The app's automatic path requests only two configs at once; the server's lifetime/concurrency rules cannot be established from these clients. These are explicit unknowns, not silently narrowed “all nodes” support. [A4, A8; §6]

### Provenance

Evidence paths below are relative to `clients/20261013/transocks/x/`, except explicit `chinadapter/` paths. Primary artifacts: official Android 4.0.3 (`android/`, `android-raw/`), TV 4.0.8 (`tv/`, `tv-raw/`), and TX1 firmware (`router-rootfs-complete/`, decompiled `tran_accel.lua`). Android 4.4.4 from Aptoide (`android444/`, `android444-raw/`) has the assignment-supplied signer mismatch: `67888267…ce3505` versus official `29846aa1…0186f31c`. Treat it as **untrusted corroboration only**, never the sole basis for the official protocol. Download/signer provenance was supplied by the assignment, not independently attested by this review.

No concrete account values, tokens, passwords, device IDs, or user IDs are recorded. Wire field names are not account values. `[UNKNOWN]` denotes an unresolved fact; `[INFERENCE]` denotes a conclusion beyond directly observed code. Native addresses below are IDA virtual addresses for the named artifact and architecture, not portable offsets.

## 2. Official Android control plane

### 2.1 Hosts, HTTP, signing, and TLS

Production base URLs, in the official Android constant array:

1. `https://abscf2.fobwifi.com`
2. `https://b.kolavpn.xyz`
3. `https://b.kolavpn.win`
4. `https://b.transmoon.xyz`

`ApiServiceImp.g()` creates the Retrofit service; `ApiServiceImp.e()` rewrites request scheme/host/port to the currently selected base. `network.util.b.a()` advances after more than two failures, and `b()` indexes modulo the host list. Test hosts and placeholder `/api-domains` literals are not production bootstrap endpoints. [A1: `android/sources/com/transocks/common/network/a.java:122-158`, production array/static initialization and `a()`; `network/util/b.java:26-44`, `a/b`; `network/ApiServiceImp.java:116-128,184-185`, `e/g`.]

Requests use JSON and `Content-Type: application/json`. `Authorization` is the stored token type, a space, and access token; token-type storage defaults an empty type to `Bearer`. Both the common interceptor and the app's additional interceptor add this header only if absent. GET request models are converted to query maps by Gson, not signed. Gson normally omits null optional body fields. **No request signing/body encryption is present in the traced official login/catalog/connect route.** [A2: `ApiServiceImp.java:91-128,184-185`, `c/e/g`; `android/sources/com/alibaba/sdk/android/oss/common/utils/d.java:5`, header constant; `android/sources/com/transocks/common/preferences/AppPreferences.java:503-525`, `m1/n1`; `android/sources/com/transocks/common/utils/FunctionsKt.java:196-198`, `q`; `android/sources/com/fobwifi/transocks/app/BaseApplication.java:379-397`, `D/E`; `android/sources/b2/e.java:77-104`, `c/d/h`; `b2/m.java:279-285`, `x`.]

**TLS is not the stock Android trust configuration.** The release client supplies certificate streams from `network.util.a.a()` to a custom SSL helper; the call supplies no client-key/certificate parameters. `ApiServiceImp.j()` returns true for hostname verification. These are observed client behaviors, not recommended security policy for a new provider. [UNKNOWN] Whether the current production service requires the bundled trust roots, and whether normal WebPKI verification succeeds. Do not blindly copy hostname-verification bypasses. [A1: `ApiServiceImp.java:151-179`, `i/j`.]

### 2.2 Shared metadata and stable installation identity

`BaseRequest` wire fields are `device`, `mac`, `uuid`, `langue` (this spelling), `package_name`, `app_version`, `org`, `channel`, `width_height`, `realname`, `model`. Defaults include `device="Android"` and `realname=true`. Official app initialization sets `org="transocks_mix"`, Google channel `official`, and appId `35` in its configuration map. appId participates in local identity construction; it is **not itself a field of `BaseRequest`**. Version/package metadata comes from app initialization. [A3: `android/sources/com/transocks/common/repo/model/BaseRequest.java:19-67,124-180`, fields/default constructor; `BaseRequestKt.java:11`, `DEVICE`; `android/sources/com/fobwifi/transocks/app/BaseApplication.java:365-375`, `C`.]

The two identity fields are different:

- `mac` is cached by `utils.o.f()`. When absent it is constructed as a UUID from Java hash codes of appId plus build-property length residues and another local device string. It is not necessarily a NIC MAC address. [`android/sources/com/transocks/common/utils/o.java:43-66,158-169`, `c/f/l`.]
- `uuid` comes from `x1.a.i()` → `AppPreferences.B/A()`. The persisted installation string is initially derived by `utils.o.k()` as lowercase hexadecimal MD5 over Android ID, serial/build-derived material; device registration's `id` defaults to this same installation string. [`android/sources/x1/a.java:269-274`, `i`; `android/sources/com/transocks/common/preferences/AppPreferences.java:79-98`, `A/B`; `android/sources/com/transocks/common/utils/o.java:117-155`, `k`; `RegisterByDeviceRequest.java:14-42,82-85`, constructor/default.]

[UNKNOWN] Whether arbitrary stable non-Android installation values, different metadata, or a distinct namespace/device label are accepted by the current server. Do not rotate identity per request or assume the Pro/router namespace grants mobile/free entitlement.

### 2.3 Endpoints

All paths below use the selected HTTPS base. Body/query fields include base metadata unless the corresponding request model omits it.

| Method/path | Request and purpose | Evidence |
|---|---|---|
| `POST /api/1/login` | `LoginRequest`; account or generated-device credentials | `android/sources/b2/a.java:88-89`, `E` |
| `GET /api/1/user/misc-info` | base query map; fresh entitlement/account state | `b2/a.java:196-197`, `o` |
| `GET /api/2/line` | `GetLinesRequest(requestAll=true)` as query map | `b2/a.java:72-73`, `A`; `b2/e.java:103-104`, `h` |
| `POST /api/2/line/connect/{lineID}` | `ConnectRequest`; obtain one line's tunnel config | `b2/a.java:200-201`, `p`; `b2/e.java:77-78`, `c` |
| `POST /api/2/line/connectmultiple` | `ConnectRequest(lineCount=2)`; auto/multiple config selection | `b2/a.java:164-165`, `g`; `b2/e.java:83-84`, `d` |
| `POST /api/2/line/disconnect/{lineID}` | `DisconnectRequest(boostSession)` | `b2/a.java:84-85`, `D`; `DisconnectRequest.java:10-21`; `b2/e.java:88-89`, `e` |
| `GET /api/1/user/sessions` | base query map; list logged-in devices | `b2/a.java:104-105`, `I` |
| `POST /api/1/app/user/register` | `RegisterByDeviceRequest(id)`; provisions device account | `b2/a.java:76-77`, `B` |
| `GET /api/1/app/clash_rule` | app routing/config rules, not proxy credential acquisition | `b2/a.java:112-113`, `K`; `LinesManager.java:409-469`, `d` |

There are also logout, account-password-management, SMS, and QR endpoints, but those are not a substitute for a passwordless token refresh. [`b2/a.java:99-101,172-185,192-193,232-233`, annotated interface.]

### 2.4 Account/password login and result

Observed forms:

- Email/password: `auth_by="email"`, `email`, `password`, `auth_type="jwt"`, `autokick=1`, plus base metadata.
- Phone/password: `auth_by="mobile"`, `phone`, `cc`, `password`, with the same defaults.
- Username/password: modeled by `auth_by="username"`, `username`, `password`; used by device-account login.
- `qr_ticket` and `sms_code` are additional modeled `auth_by` values, not required for initial account-password support.

**The email UI forwards the password unchanged into the JSON model; it does not hash/encrypt it first.** Do not confuse installation-ID MD5 with password preprocessing. `autokick=1` is a client default that may evict other sessions; server policy and alternate accepted values are [UNKNOWN]. [A6: `android/sources/com/transocks/common/repo/model/LoginRequest.java:17-91,238-249`, fields, `AuthBy`, defaults; `android/sources/com/fobwifi/transocks/ui/login/email/EmailLoginFragment$dealClickEvents$1.java:58-69`, `invoke2`; `EmailLoginViewModel.java:71-75,98-99`, `l/k/j`; `android/sources/com/fobwifi/transocks/ui/login/phone/PhoneLoginViewModel.java:95-96`; `android/sources/b2/m.java:279-285`, `x`.]

Login JSON is flat, not a `data` wrapper. Relevant fields: `token:{access_token,exp,token_type}`, `user_id`, `transocks_id`, `expired`, `expire_at`, `expire_at_time`, `remaining_days`, `remaining_seconds`, `is_device_login`, `is_realname`, `password_setup`, plus email/phone/nick and advertisement-entitlement fields. Account/user identifiers must remain private. `Token` has no refresh-token member. [A8: `android/sources/com/transocks/common/repo/model/LoginResponse.java:17-74`, constructor/fields; `Token.java:13-24`; `android/sources/b2/m.java:94-99`, `E`, persistence.]

The common envelope has `code`, `status`, `error`, `errors`. Final resource mapping treats **`code==0` as success**. Do not mistake `20000` for success: the resource converter interprets it as `LOGOUT_IS_VIP`, even though the base model's no-argument default uses that number. Both HTTP status and body errors matter. [`android/sources/a2/b.java:13-28,75-76`; `android/sources/com/transocks/common/repo/resource/ResourceExtKt.java:87-103,138-155,316-323`, `i/k/v`; `ApiCodeError.java:91-95`.]

### 2.5 Anonymous/device “free mobile” mode

This is a **registered device-account workflow**, not an unauthenticated proxy:

1. `POST /api/1/app/user/register` with persistent `id` and base metadata.
2. Receive generated `username` and `password` in `RegisterByDeviceResponse`.
3. Persist those generated credentials; log in using `auth_by="username"`.
4. Use the returned normal token and free-line eligibility rules.

[A7: `android/sources/com/transocks/common/repo/model/RegisterByDeviceRequest.java:14-42,82-85`; `RegisterByDeviceResponse.java:13-25`; `android/sources/com/fobwifi/transocks/app/InitDataAction$registerAndLogin$1.java:28-43,80-97`, `i/h`.]

No values were provisioned or read from device storage. Supporting this later would require an explicit registration/provisioning decision and a credential-lifecycle design; it must not be secretly performed as account-login fallback. [UNKNOWN] Current free-service geography, eligibility, device quota, and server acceptance for non-Android installations.

### 2.6 Refresh and session expiry

While a token is accepted, the app reuses it for misc-info, catalog, and new connect responses. There is **no dedicated access-token refresh endpoint in the inspected official Retrofit interface**, and no refresh token in the login model. A model named `ResetToken` is for **forgotten-password reset**, not a session-renewal credential. [`android/sources/b2/a.java:71-241`, interface; `Token.java:13-24`; `ForgetPasswordResponse.java:14-19`, `reset_token`; `ResetToken.java:12-20`.]

On invalid authentication, `BaseFragment.h0()` clears the token and logs in with stored generated device username/password, or provisions a device account if absent. This can fall back to a different account; it is **not proof of renewing the user's paid account without its password**. [`android/sources/com/fobwifi/transocks/common/base/BaseFragment.java:413-447`, `h0`.]

[UNKNOWN] Passwordless renewal of a paid account token, exact token TTL, and whether `token.exp` is an absolute epoch or other expiry representation. The inspected persistence path stores access token/type, not the `exp` value. A future provider can refresh catalog/authority using the still-valid token, but must handle explicit rejection as requiring re-login if no alternative renewal is established. It must not retain the login password contrary to chinadapter's contract. [A8; `chinadapter/internal/provider/provider.go:64-70`, `Credentials`.]

### 2.7 VIP fields, eligibility, and device limits

`GetMiscInfoResponse` adds nullable `is_pro_user`, `default_protocol`, `google_subscription_status`, `realname_grace_state`, and membership/device-login/advertisement fields. Distinguish:

- `expired` / membership expiry and remaining time;
- `is_pro_user` (Pro membership indicator);
- `is_device_login` (device-account mode);
- `ads_free` / advertisement expiry (not synonymous with VPN VIP).

[`android/sources/com/transocks/common/repo/model/GetMiscInfoResponse.java:27-94`, fields.]

`LinesManager.h()` first checks real-name/grace/binding and password-setup gates, then allows `line.isFree` even if membership is expired; nonfree lines require unexpired membership. This is client admission logic, not a guarantee that the server accepts every resulting request. [`android/sources/com/transocks/base_mobile/lines/LinesManager.java:187-238`, `h`.]

VIP resource text advertises three simultaneous devices, but no numeric quota is returned in the inspected misc-info model. `GET /api/1/user/sessions` returns `list:[Device]`; each device includes `active_at`, `app_version`, `device`, `model`, `package_name`, `session`, `mac`. Session/device identifiers are sensitive. **[UNKNOWN]** Exact free/VIP/Pro/router limits and whether account-login, boost-session, node, and transport concurrency share a quota. Marketing text is not an authoritative server quota. [`android/resources/res/values/strings.xml:627,675`, `text_3_devices` / `tv_vip_device`; `GetSessionResponse.java:12-20`; `Device.java:14-43`.]

Selected explicit error codes for implementation:

| Code | Client interpretation |
|---|---|
| `20001` | Not authenticated |
| `20004` / `20005` | Invalid organization user / unknown organization |
| `20010` | Logged out by another device |
| `20012` / `20013` / `20014` | Frequent operation / server busy / outdated API |
| `40001` / `40002` / `40003` | Bad username/password / disabled account / out of devices |
| `40015` | Token invalid or expired |
| `40019` / `40020` / `40021` / `40022` | Connection session terminated / line removed / membership expired / line full |
| `40024` | Line-interaction secret expired or illegal public key (legacy encrypted path) |
| `40052` | Bind email or phone required |

[`android/sources/com/transocks/common/repo/ApiCodeError.java:91-183`, `Companion.a`.]

Do not translate transient network failures, capacity, membership expiry, or every server error into account-session rejection. Explicit authentication rejection, membership eligibility, and a terminated boost session are different states. [Implementation recommendation; `chinadapter/internal/provider/provider.go:22-37`, provider errors.]

### 2.8 Line catalog and connect schema

`GET /api/2/line` response is a flat `lines:[Line]` plus the envelope above. Relevant catalog fields and exact capitalization: `id:int`, `name`, `enName`, `category`, `domain`, `iPAddr`, `detectPort`, `https_host`, `isFree:bool`, `isRelay`, `location`, `sswURL`, `DisableIkev2`. Nullable fields should be preserved as optional. `cacheId` is a local Room primary key; `pingDelay` is transient/local. IDs `-1` and `-2` represent auto choices, not physical upstreams. **The catalog contains no full tunnel password/cipher authority.** [`android/sources/com/transocks/common/repo/model/GetLinesResponse.java:12-20`; `Line.java:25-82,100-119`, fields, `D/E/F/G/H`.]

Single and automatic connect requests explicitly choose `proto="SS"` and `methods=["chacha20-ietf-poly1305"]`. `available_proto` defaults to `["SS","Trojan","GTS"]`; other optional fields are `recommendLine`, `available_line`, `regionID`, `categoryID`, `enableMpx`, `exclude_line`, `lineCount`. Multiple connect sets `lineCount=2`. A response may therefore differ from the preferred protocol; inspect its actual discriminator. [A4: `android/sources/b2/e.java:77-104`, `c/d/h`; `android/sources/com/transocks/common/repo/model/ConnectRequest.java:16-66,119-130`, defaults/fields; `Cipher.java:11`; `Proto.java:24-33`.]

Connect response fields: `boostSession`, `config` or `configs`, `lineID`, `lineName`, `supportBT`, `iconUrl`, `protoName`. Each config has `host`, `proxyIP`, `inJson`, integer `proto`, and optional `SSConf`, `SSWConf`, `GTSConf`, `trojanConf`, `openvpnConf`. `Config.u()` maps integer `proto`: **0=SS, 1=GTS, 2=HTTP, 3=SSW, 5=Trojan, 6=Openvpn; other=auto**. `host` is not a protocol discriminator. The `boostSession` is retained for API disconnect; the inspected SS/Trojan wire framing does not send it as a preamble. [`android/sources/com/transocks/common/repo/model/ConnectResponse.java:18-39`; `Config.java:17-51,183-200`, `u`; `DisconnectRequest.java:10-21`; N1/N2 below.]

SS-family `BootsInfo` carries actual `server`, `port`, `password`, `method`; additional generic members cover SSW host/URL/username/MPX and GTS token/header-key/KCP/gateway/MTU. For Trojan the builder additionally parses `inJson` as `RemoteConnectConfig`: `remote_addr`, `remote_port`, `password:[string]`, `ssl:{sni,verify}`, `websocket:{enabled,host,path}`, `mux`, `run_type`. The first password is selected. Do not substitute catalog `detectPort` for the tunnel port, or assume `proxyIP` equals the dial endpoint. [`BootsInfo.java:20-107`; `RemoteConnectConfig.java:17-44`; `android/sources/com/transocks/base_mobile/lines/LinesManager.java:570-616`, `m`.]

[UNKNOWN] Whether acquiring a new line invalidates an earlier `boostSession`, whether credentials are reusable across TCP/UDP flows, their TTL, whether every catalog entry can coexist, and whether disconnect revokes a single config or broader state. The two-config auto path proves only the client's requested count, not an all-line account allowance. [A4; `DisconnectRequest.java:10-21`.]

## 3. Official Android data plane and stock-core compatibility

### 3.1 Config construction

`LinesManager.m()` extracts SS credentials for `Config.proto==0`; for Trojan (`proto==5`) it parses `inJson` and fills endpoint/password/SSL/WebSocket/mux into `trojanConf`. Other protocols fall back to SSConf in this particular builder. `LinesManager.d()` makes Clash proxy entries, sets HTTP 7890 / SOCKS 7891 / loopback controller `127.0.0.1:9090`, updates proxy groups, serializes Gson JSON, and converts it to YAML using Jackson. **JSON-to-YAML is format conversion, not cryptography.** [A5: `android/sources/com/transocks/base_mobile/lines/LinesManager.java:409-469,570-616`, `d/m`; `android/sources/com/transocks/common/utils/o.java:34-35`, conversion helper.]

| Protocol | What the official builder actually emits | Boundary |
|---|---|---|
| SS | `type:ss`, `server`, `port`, `cipher=method`, `password`, `udp:true` | Requests ChaCha20-IETF-Poly1305; no plugin/obfs fields emitted. |
| Trojan | `type:trojan`, `server`, `port`, `password`, `udp:true`, SNI/cert policy; optional `network:ws`, `ws-opts.path`, `ws-opts.headers.Host` | `skip-cert-verify` is inverse of `ssl.verify`; no mandatory vendor preamble found. |
| VMess | Generic model/native core supports VMess, but this API/config builder does not select it | Do not infer VMess service nodes from bundled generic support. |
| GTS / SSW / OpenVPN | Models/constants exist; not distinct selected Clash outbounds here | Legacy/custom paths must not be relabeled as plain SS/Trojan. |
| Hysteria / TUIC / QUIC upstream | No selection in the inspected builder; no corresponding branch in inspected core `ParseProxy` | No positive support evidence for these upstream protocols in official 4.0.3. |

[`LinesManager.java:129-166`, `F/G`; `android/sources/com/transocks/common/repo/model/Proxy.java:20-82`; `Proto.java:12-51`; N3, `ParseProxy`.]

Trojan's parsed mux settings are retained in `BootsInfo`, but the emitted `Proxy` constructor has no mux field. Do not automatically enable a vendor MPX/mux extension because `inJson.mux` exists. [A5, `LinesManager.java:134-166,605-610`; `Proxy.java:20-82`.]

### 3.2 Native core, patches, and framing

`go version -m android-raw/lib/arm64-v8a/libclash.so` reports Go 1.20.3, main `cfa/native`, `cfa => ../../main/golang (devel)`, build tag `official`, `github.com/Dreamacro/clash v1.7.1 => ./clash (devel)`, and `github.com/Dreamacro/go-shadowsocks2 v0.1.7`. This proves a locally built Clash replacement, **not an exhaustive patch list**. [Native build-info inspection of that exact file.]

Native evidence, same official ARM64 library:

- **N1:** `github.com/Dreamacro/clash/adapter/outbound.(*ShadowSocks).StreamConn` `0x4f4100`; `ListenPacketContext` `0x4f4a20`. Stream wraps with the Shadowsocks cipher and writes a serialized SOCKS destination. Packet mode uses a UDP socket and cipher packet wrapper. The inspected path has no additional app account/device-token header.
- **N2:** `transport/trojan.(*Trojan).WriteHeader` `0x4f0070`, `hexSha224` `0x4f0f10`; `outbound.(*Trojan).StreamConn` `0x4face0`, `plainStream` `0x4faa60`. Authentication is 56-character SHA-224(password), followed by conventional CRLF/command/target/CRLF framing. TLS and optional WebSocket transport are implemented in the expected outbound path; no Transocks identity preamble was observed.
- **N3:** `github.com/Dreamacro/clash/adapter.ParseProxy` `0x505f10` accepts SS, SSR, VMess, Trojan, Snell, SOCKS5, HTTP; unsupported type goes to an error. This is the native core's generic type support, not a list of Transocks service offers.
- **N4:** Android integration contains `cfa/native/config.UnmarshalAndPatch` `0x546ec0` (unmarshal then configured patch functions), `patchDns` `0x5479e0` (default DNS/system nameserver handling, including `dhcp://system`), `cfa/native/proxy.Start` `0x54b100` (local authenticated HTTP listener), and Android TUN/platform functions. These are positive examples of app/config integration. They do not establish that all fork changes are non-wire changes.
- **N5:** In its ordinary TLS/WS branch, `outbound.(*Trojan).ListenPacketContext` `0x4fb620` dials TCP, calls `plainStream`, sends a Trojan header, then wraps the stream in `trojan.PacketConn` (the generic core also retains a gun/gRPC branch, not emitted by this app builder). `transport/trojan.writePacket` `0x4f02b0` writes destination, big-endian uint16 payload length, separator, and payload; `WritePacket` `0x4f0510` divides payloads larger than `0x2000` (8192) into multiple records. This is an observed size-handling behavior to account for in datagram interoperability, not an assertion that large original datagrams are preserved or that the behavior is a Transocks-specific patch.

**[INFERENCE] Direct stock-core connection is plausible and strongly supported for ordinary returned SS/Trojan configs**, provided endpoint, actual cipher/password, TLS SNI/certificate policy, and optional WS host/path are reproduced. Android VPN permission, TUN, proxy groups, and local controller are not part of those proxy wire handshakes. Do not claim the same for GTS or SSW, and do not claim tested interoperability. [A5, N1/N2/N4.]

### 3.3 UDP and QUIC

Both emitted SS and Trojan entries set `udp:true`; native standard packet-capable paths exist. This is positive client capability evidence, **not confirmation that every server config permits working UDP**. [A5, `LinesManager.java:129-166`; N1/N5.]

The ordinary SS path carries proxy datagrams over UDP; ordinary Trojan carries datagram framing through its TCP/TLS/optional-WS stream transport. Destination QUIC may be carried as UDP traffic when the upstream permits it. That is different from the adapter using QUIC/Hysteria/TUIC as its upstream transport. [N1/N5; carrying destination QUIC is an INFERENCE, not an exercised capability.]

## 4. TV/router and legacy paths: corroboration, not a second current API recipe

### 4.1 TV 4.0.8

TV production URLs are the same four hosts (different fallback order). TV login supports `jwt` and `cookie`; its constructor defaults credentials/autokick and sets `auth_type` from `DEFAULT_AUTH`, and `setHttpMode()` chooses JWT. API manager retains cookies and tests for cookie name `ABS_FOBWIFISS`. These older mechanisms must not be conflated with the official Android token-only request path. [`tv/resources/res/values/arrays.xml:268-273`, `product_url`; `tv/sources/com/fob/core/f/a.java:46-101`, host selection/failure handling; `tv/sources/com/mine/shadowsocks/entity/ReqLogin.java:46-93`, constructor / `isJwt/setHttpMode`; `api/h.java:420-425`, `g`.]

Current TV request handler `j.b.a(LineInfo,boolean)` posts a JSON map to `/api/2/line/connect/{id}` with `proto`, `recommendLine`, `available_line`, `device`, `mac`; SSW adds `enableMpx:true` and supported methods. TV's SSW method list is `chacha20-ietf-poly1305`, `aes-256-gcm`, `aes-128-gcm`. These are TV capabilities, not proof that official Android offers every cipher. [`tv/sources/com/mine/shadowsocks/j/b.java:881-890`; `api/h.java:66-70`; `tv/sources/com/lvwind/shadowsocks/Constants.java:100-102`.]

An older encrypted connect DTO is also shipped: `ReqConnectJwt.Build()` produces `{pub_key,encrypted,t,sign}`. Its plaintext model includes `access_token`, `line_id`, protocol, boost-session, device/mac fields. It encrypts JSON using AES-256-CBC/PKCS7, derives 48 key/IV bytes by repeatedly hashing `previousDigest || secret || salt` with **SHA-256**, takes key[0:32] and IV[32:48], uses the last eight decimal timestamp characters as salt, base64-encodes ciphertext without wrapping, and signs `encrypted=<ciphertext>&pub_key=<public-key>&t=<timestamp>` using base64 HMAC-SHA1 with the secret. Catalog models retain `key:{exp,pub_key,secret}`. **No call to `ReqConnectJwt.Build()` was found in the inspected TV decompiled sources; do not impose this dormant/legacy envelope on current Android API2 connect.** Exact legacy hello/key acquisition and server use remain [UNKNOWN]. [`tv/sources/com/mine/shadowsocks/entity/ReqConnectJwt.java:10-50`, `PlainParams/Build`; `LineKeyInfo.java:7-10`; `RspLine.java:9-11`; `utils/i.java:20-24,124-142,254-278`, `d/a`; `tv/sources/m/a/d/c/a/a.java:10`, digest constant; `api/c.java:20-37`, legacy connect interface.]

TV SSW preparation supplies host, URL, username, method, password, and MPX flag to `Export.startWebsocket` / `Export.startWebsocketMpx`; ordinary Go SS uses `Export.startTCPUDP`. This is not evidence that a stock SIP003 plugin is interchangeable. A crucial reachability caveat: this TV artifact's `SsConfig.isUseGo()` returns false, despite retaining a flag; many Go-start branches are therefore dormant in this build. **[UNKNOWN] SSW's exact WS authentication, multiplexing, wire format, and stock-core compatibility.** [`tv/sources/com/mine/shadowsocks/vpn/StartSSHelper.java:372-403,581-586`; `tv/sources/com/lvwind/shadowsocks/operator/SsOperator.java:191-248`; `database/SsConfig.java:197-204`.]

### 4.2 TX1 router

Router UCI defaults use `org="transocks_pro"`, the same host set, and configured CA/client-certificate/key file paths. Do not assume that this namespace, router entitlement, or TLS identity is suitable for free mobile mode. [`router-rootfs-complete/etc/config/transocks_manager:5-19`.]

`router-rootfs-complete/usr/bin/appManager` contains the following Go SDK functions (IDA, MIPS):

- `router/abs.(*Abs).InitAbs` `0x2fdfb0`: defaults HTTPS and Pro org, installs a cookie jar and TLS configuration including supplied certificates; sets `InsecureSkipVerify=true`.
- `normalReq` `0x2fe470`: builds ordinary HTTP requests/JSON headers; the inspected login path is not the TV encrypted-connect DTO.
- `Loginwith` `0x2ff834`: `POST /api/1/login`.
- `LinesInCategory` `0x303418`: `GET /api/2/line`.
- `Connectv2` `0x303e40`: `POST /api/2/line/connect/{id}`.

This independently corroborates the API2 family; bundled certificate paths/function parameters are not proof of a current server-side mTLS requirement. [Named binary/functions/addresses above.]

The readable router acceleration Lua is mainly a **local acceleration/iptables/process launcher**, not the source of account login API requests. It selects `server`, `method`, `server_port`, `password`, `local_port`, writes proxy config, and starts `/usr/bin/ss-redir -c <config>`. It kills SS/SSR processes, and its relevant interception rules are TCP DNAT plus DNS handling; do not derive modern Android UDP support from this launcher. [`tran_accel.lua:1197-1223,1235-1236,1278-1303`, functions `L50_1/L51_1`; `:319-322,345-348,460-479`, iptables construction.]

### 4.3 GTS is genuinely custom

Official models distinguish `gts-kcp`, `gts-tcp`, `gts-udp`, and expose token/header-key/encryption/KCP/MTU/gateway material. This is not another name for ordinary Shadowsocks. [`android/sources/com/transocks/common/repo/model/Proto.java:18-51`; `BootsInfo.java:20-107`.]

TX1 `router-rootfs-complete/usr/bin/gts-cli` provides positive custom-protocol evidence (IDA, MIPS): `init_UDP_socket` `0x4037cc`; `encrypt_GTS_header` `0x403ac4` assembles an eight-byte header and DES-ECB encrypts it; `json_parse` `0x409e10` reads fields including server/port, header_key, encrypt, token/password, heartbeat/MTU; `crypto_encrypt` `0x405d84` generates an eight-byte nonce and calls `crypto_secretbox_salsa208poly1305` `0x405eb0`, which combines Salsa20/8 payload encryption and Poly1305 authentication; inverse routines are `crypto_decrypt` `0x405e20` and `crypto_secretbox_salsa208poly1305_open` `0x405f54`.

These inspected router functions are enough to reject “GTS is stock SS/Trojan/QUIC”; they are **not a complete GTS specification**. [UNKNOWN] Full packet layout, header/key derivation, sequencing/rekey/replay policy, all TCP/KCP variants, and modern server compatibility. **Stock mihomo/sing-box direct GTS support is not established; a separate custom transport would be required if future returned configs cannot be restricted to ordinary SS/Trojan.** [Named GTS binary/functions above; N3 lacks a GTS outbound.]

### 4.4 Untrusted 4.4.4 corroboration

The Aptoide artifact retains the same advertised `[SS,Trojan,GTS]` connect default and the same SS/Trojan config mapping; its `getProxyForTrojan`, `dealConnectForProto`, and connect builder do not establish a switch to Hysteria/TUIC. This agrees with official evidence, but the signer mismatch prevents treating it as authoritative newer official protocol behavior. [`android444/sources/com/transocks/common/repo/model/ConnectRequest.java:56-100`; `android444/sources/com/transocks/proxy/lines/LinesManager.java:588-620,735-740,1101-1154`, named methods.]

## 5. Mapping onto chinadapter

This section is an **implementation recommendation**, not code already implemented. Contract evidence: `chinadapter/internal/provider/provider.go:40-75,91-179,181-203`; `transport.go:9-71`.

| Contract member | Proposed Transocks mapping / requirement |
|---|---|
| `Driver.ID()` | Stable ID such as `transocks`. |
| `Driver.Login(ctx, Credentials)` | Use transient account/password + persisted `InstallationID`; call account login, misc-info, catalog, obtain actual supported configs; build a complete validated snapshot. Never auto-register a device account as hidden fallback. |
| `Driver.Refresh(ctx, Snapshot)` | Decode opaque stored token/type + stable metadata; refresh misc-info/catalog and valid authorities with the same token. Explicit token rejection requires re-login unless passwordless renewal is independently established. |
| `Snapshot.Account` | Private `user_id` → `UserID`; browser-safe redacted account display; tier derived from explicit membership/device fields; active subscription/end time separate from advertisement entitlement and token expiry. Respect `Account.Valid()`'s active/end-time invariant. |
| `Snapshot.RefreshState` | Opaque token/type, installation metadata, and state necessary for subsequent control calls; never the login password. The exact schema depends on resolving token expiry/concurrency policy. |
| `Snapshot.Authorities` | All secret proxy passwords, cipher/TLS/WS settings, and API boost-session material stay in opaque authority data. Nodes must remain secret-free. Maximum 16 authorities, each at most 1 MiB: group per protocol with a node-keyed private credential table rather than one authority per node if needed. |
| `Snapshot.Nodes` | Stable catalog ID plus actual protocol/endpoint returned by connect; name/category/location-derived presentation; `Eligible` from free/membership/gates; auto entries must be marked synthetic and resolved through returned configs. A catalog-only detect endpoint is not a usable tunnel node. |
| `Snapshot.ExpiresAt` | Refresh hint only, not automatic admission expiry. Token/member/authority lifetimes are separate; derive the refresh schedule only after establishing the returned time semantics. |
| `Transport.Protocol()` | Distinct identifiers for supported framing, e.g. `transocks-ss` and `transocks-trojan`; do not conflate GTS/SSW with them. |
| `Transport.RelayStream()` | Decode immutable authority for the pinned node, dial only selected upstream through `RelayRequest.Dial`, perform SS destination/cipher or Trojan TLS/WS/auth/destination setup, final `Admit`, then call `Ready` exactly once before relaying application bytes. No direct-destination fallback. |
| `DatagramTransport.RelayDatagrams()` | Implement the actual SS/Trojan datagram framing and use `PacketIO`'s SOCKS UDP framing. Advertise UDP only for implemented/usable protocol configs; otherwise TCP-only semantics yield SOCKS failure `0x07`. No claim of UDP availability based solely on `udp:true`. |

**Important all-node design constraint:** a control-plane connect call may return a changed actual endpoint or invalidate earlier boost sessions. A lazy connect request inside the transport must not silently change a pinned `NodeHost/NodePort` or bypass the runtime dial boundary. An eager per-node config snapshot must not advertise invalidated earlier credentials. Resolve this lifecycle before promising one simultaneous local endpoint per catalog node. [A4, connect/config schema in §2.8; `chinadapter/internal/provider/transport.go:9-31`, pinned relay contract.]

Existing `Credentials.Valid()` requires nonempty account/password/installation ID. Anonymous provisioning is not represented by a first-class credential-free operation. Generated device-password persistence would also conflict with the blanket password-retention rule if added without an explicit contract decision. Do not hide that incompatibility in opaque state. [`chinadapter/internal/provider/provider.go:64-75`.]

## 6. What a future implementation needs, and unresolved facts

### Established implementation inputs

- API host constants, official metadata namespace/channel, unmodified account-password JSON, Authorization construction, response envelope and error meanings: §§2.1–2.7.
- Catalog-to-connect separation, actual config discriminator, SS/Trojan endpoint/credential/TLS/WS extraction and disconnect-session schema: §2.8–§3.
- Static ordinary-wire compatibility evidence and explicit exclusion of unsupported custom protocols: §3–§4.
- Snapshot/authority/relay mapping and endpoint pinning constraints: §5.

### Unknowns that must not be fabricated

1. **Current-server acceptance and trust:** no live requests were made. Required metadata/namespace behavior, bundled CA need, server-side binding/real-name gates, and exact supported catalog contents remain unknown. [A1–A3, A7.]
2. **Paid-account renewal:** no refresh credential/endpoint found in the official path; device fallback is a separate registered account. Token expiry units/TTL and a passwordless renewal method remain unknown. [A8; §2.6.]
3. **All-node concurrency and authority lifetime:** two-config auto selection does not prove every line's credentials can coexist. Reuse, invalidation, connect/disconnect effects, and numeric device/tunnel quotas remain unknown. [A4; §2.7–2.8.]
4. **Per-node UDP and stock-core interoperability:** standard framing and `udp:true` are static evidence only; no SS/Trojan TCP/UDP or WS connection was exercised. [N1/N2, A5.]
5. **Fork completeness and custom protocols:** no source-level exhaustive Clash diff was available. GTS/SSW are not fully specified; newer official protocols cannot be inferred from the differently signed Aptoide app. [N3/N4; §4.]

### Verification a future implementation should perform

Use redacted static response/config fixtures to cover exact capitalization, code-zero success versus error codes, config-protocol fallback, nullable fields, first Trojan password, TLS/WS extraction, identity stability, secret-free node serialization, and endpoint pinning. Add protocol framing tests against established SS/Trojan libraries. Only with separate explicit authorization should a future integration check establish one account login's acceptance, token/boost-session lifetime, multi-node concurrency, and TCP/UDP behavior. **None of these implementation tests or live checks was run in this review.**

## 7. Deliverable status

The requested dossier is complete as a static, evidence-cited implementation study with unknowns explicitly marked. No chinadapter code edits, registration, account login, or personal-data API probes were performed. Native inspection used the already extracted artifacts; executable behavior/connectivity was not tested.
