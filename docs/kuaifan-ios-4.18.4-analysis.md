# KuaiFan iOS 4.18.4 and Windows protocol evidence

## Scope and conclusion

This report analyzes the supplied `full_auth_fetch_flows` capture, iOS 4.18.4 IPA, and Windows client. It separates observed wire facts from independently recovered client behavior and inference.

The missing catalog entries were caused by the adapter's legacy macOS request profile. The captured iOS profile is `IOS` / `THIRD` / `4.18.4`; three identical `getLines.do` responses contain 31 groups and 167 lines, including five music/video lines in group `2015` and four game lines in group `300`.

The iOS capture alone does not define a second Fanster wire protocol: all its lines identify `WIFIIN` and `aes-256-cfb`. Its implemented data plane remains the observed WIFIIN framing under KuaiFan's Fanster branding. The October Windows 4.7.6 beta review separately recovers SPEEDIN, selected by `WINDOWS/INTERNATIONAL/4.7.6`; the adapter now implements that Windows profile rather than treating a marketing name as a protocol selector. See the verification and cutover sections below.

## Evidence integrity

| Artifact | Size | SHA-256 |
|---|---:|---|
| `full_auth_fetch_flows` | 1,346,600 bytes | `fab004a0b6ab515c76238932b5c3ff9bab15b1450e4db1f13723ffb74bed90cd` |
| `cc.fancast.major_1442745175_4.18.4.zip` | — | `32cbecdc66480a8cced0fbe2d71c953e9b6fbc06fe30be7988dbd966f8130788` |
| `Payload/快帆.app/快帆` | 31,828,160 bytes | `fed8eb984dc7dcaec7166a3f248f00e70063c149e9b57d7556393e76eb5cfb2a` |
| `kuaifan_windows/speedin.exe` | 8,731,648 bytes | `668f6168d64912631dd0617de7aeb86ca0776fc465037749944660e492ea9abb` |
| `Payload/快帆.app/PlugIns/tunnel.appex/tunnel` | 709,680 bytes | `1109a077febec32895c329aad56b7149029bb4a3e272af6e00c447daff8f0e5e` |
| `Payload/快帆.app/Frameworks/Tquic.framework/Tquic` | 2,728,048 bytes | `485634306c20843c13721358054641c758514d0203e1dafc3dedfec272d5795d` |

The capture is a concatenated tnetstring mitmproxy export. It contains 70 HTTP flows: 64 to `ws.kuaifan.co`, four to `track.kuaifan.co`, and two to `rs.kuaifan.co`. KuaiFan request and response bodies were decoded with the AES-CBC/PBKDF2 compatibility codec implemented in `internal/provider/kuaifan/codec.go`. Credentials, tokens, and installation identifiers are intentionally omitted below.

## Authentication and session flow

The relevant post-login transaction is:

```text
client/conf.do
  -> user/login.do
  -> user/account/bound/list.do       ancillary
  -> utils/ip/query.do                ancillary
  -> user/refresh.do                  required session validation
  -> invpn/getAuthority.do
  -> invpn/getLines.do
```

The bound-account and IP-query responses do not supply an input used by refresh, authority, or line retrieval. They are application features, not authentication prerequisites.

### Login request profile

The captured `user/login.do` request uses these constants:

| Field | Captured value |
|---|---|
| `os` | `IOS` |
| `edition` | `THIRD` |
| `clientVersion` | `4.18.4` |
| `osVersion` | `27.0` |
| `deviceType` | `iPhone` |
| `manufacture` | `Apple Inc` |
| `promoPlatformCode` | `AppStore` |
| `packagename` | `cc.fancast.major` |
| `loginType` | `4` |
| `nickname` | empty string; exact lower-case wire key |
| `virtualMachine` | `false` |
| `withSimCard` | `true` |
| `mac` | `020000000000` |
| `extra` | empty object |

The captured identifiers are intentionally not all equal:

- `deviceId` and `openUdid` are the same 40-character install-persistent value.
- `uuid` is a separate 32-character install value.
- `udid`, `idfa`, and `imei` are empty.

The adapter reproduces this shape without reading hardware identifiers: its protected random installation ID is the 32-character `uuid`, while a domain-separated SHA-1-shaped pseudonymous value supplies `deviceId` and `openUdid`. The synthetic MAC is the captured constant. SHA-1 here supplies only the legacy identifier shape; it is not used as a security primitive.

### Independent Windows verifier confirmation

The supplied Windows `speedin.exe` is a .NET assembly protected by SmartAssembly 6.12.6.990. It was deobfuscated with de4dotEx 3.7.0 in an isolated temporary container; no recovered binary or analysis tooling was added to this repository. The recovered `cc.speedin.invpn.Controller.invpn.UserLoginManager` IL independently confirms the login verifier implemented here:

1. Format local time as `yyyyMMddHHmmssfff` and concatenate `deviceId + time`.
2. Split near the midpoint using a bounded random offset, adding an even offset and subtracting an odd offset.
3. Select four characters from the two halves using the timestamp's final four digits and append them to the concatenated input.
4. MD5 the UTF-8 bytes, render the digest as lower-case hexadecimal, then Base64-encode that hexadecimal text.
5. At Base64 offset 10, insert three random Base64-alphabet characters followed by the alphabet character whose index is one less than the split position.

The historical .NET Windows request builder calls this verifier with its stored `invpn_userGuid` as `deviceId`. The 4.7.6 beta instead passes the MAC slot, as traced in the October verification below; the current adapter follows that beta caller. It retains a synthetic MAC and converts the protected random 32-hex installation ID to an RFC 4122-shaped GUID without reading host hardware. The iOS profile keeps its separate SHA-1-shaped pseudonymous identifier.

### Required refresh

The iOS capture performs `user/refresh.do` after password login and before authority and line retrieval. Its request contains the login `userId` and login token. The response repeats `userId`, returns the current login token, and supplies `isVip` plus millisecond `vipEndTime` metadata. The Windows password response already supplies that profile, while periodic Windows refresh uses its recovered `lang`, `time`, and nonce fields.

The adapter enforces these invariants across the aggregate lifecycle:

1. iOS refresh succeeds before its authority or lines are fetched; periodic refresh succeeds for both clients.
2. Every login, refresh, and authority user ID must match across both profiles.
3. Each returned token must be non-empty; token rotation is accepted only within that profile's subsequent requests.
4. `isVip` must be a JSON boolean and `vipEndTime` a bounded integer millisecond timestamp; aggregate VIP uses intersection and the earliest expiry.
5. A VIP profile must have a non-zero expiry.
6. Failed refresh, authority, or line validation leaves the prior complete generation intact.

The validated VIP profile is published with the account snapshot rather than being replaced by placeholder non-VIP data.

## Complete line discovery

The catalog request profile is exactly:

```json
{
  "os": "IOS",
  "clientVersion": "4.18.4",
  "edition": "THIRD"
}
```

The normal envelope additionally supplies `userId`, refreshed `token`, `lang`, `time`, and `nonce`.

All three captured `getLines.do` responses have the same inventory:

| Property | Observation |
|---|---:|
| Groups | 31 |
| Lines | 167 |
| Group `2015` music/video lines | 5 |
| Group `300` game lines | 4 |
| Provider | 167 × `WIFIIN` |
| Method | 167 × `aes-256-cfb` |
| Edition | 167 × `THIRD` |
| OS | 167 × `IOS` |
| Embedded line password | 167 × `wifiin1234` |
| Mode | 165 × `1`; 2 × `0` |

The authority response remains the source of the active tunnel encryption key. The per-line `wifiin1234` value is catalog metadata and is not substituted for validated authority.

The earlier `MAC` / `MINOR` / `3.3.1` request selected a different, truncated server-side catalog. After adopting the iOS request, a second adapter defect still reduced the 167 decoded lines to 157 frontend nodes: node identity used only canonical provider, host, and port, even though KuaiFan intentionally reuses an endpoint in multiple logical groups. First-wins endpoint deduplication removed two group-`2015` entries that followed football entries, producing the reported three music/video nodes instead of five.

The captured inventory has 167 distinct `(groupId, canonical provider, canonical host, port)` tuples. Logical `line_…` node IDs and selector credentials therefore include `groupId` as well as the canonical endpoint. This preserves all 167 catalog rows while still collapsing spelling-equivalent duplicate endpoints within one group. Legacy endpoint-only `node_…` IDs and credentials are intentionally unsupported; this is a clean cutover.

Captured localized names use `zh_cn` and `zh_tw`, while requests use `zh-CN`. Locale comparison now normalizes case and `_`/`-` separators instead of falling back to the first English entry. Group `800` (`澳洲 ➩ 中国`) consequently retains its two captured labels `澳大利亚 ➩ 中国 · 2` and `澳大利亚 ➩ 中国 · 7`; group `2161` (`澳洲`) remains a separate two-line group numbered `1` and `2`.

## Fanster and tunnel analysis

### Facts

- KuaiFan's website and Apple listing market a proprietary “Fanster™” protocol but publish no framing, handshake, key schedule, or reference implementation.
- No `fanster` provider, alternate line schema, or second cipher appears in the 64 captured control flows.
- Every one of the 167 captured lines says `provider: WIFIIN` and `method: aes-256-cfb`.
- The embedded packet-tunnel extension has bundle identifier `cc.fancast.major.tunnel2`, executable `tunnel`, and extension point `com.apple.networkextension.packet-tunnel` with principal class `PacketTunnelProvider`.
- The packet-tunnel executable links Apple's `NetworkExtension`, `Foundation`, and `Network` frameworks. It does not link `Tquic.framework`.
- The main executable links `Tquic.framework`; linkage alone does not establish that Tquic carries the packet tunnel.
- The main executable, packet-tunnel executable, and Tquic executable all carry `LC_ENCRYPTION_INFO_64` with `cryptid = 1`. Their protected text cannot be treated as available static implementation evidence from this IPA.
- The IPA resources, capture schemas, and repository contain no recoverable second Fanster wire definition.

### Inference and implementation decision

The evidence supports “Fanster” being a product/technology brand covering the observed WIFIIN data plane, but does not prove that no other implementation exists in protected code. The adapter therefore implements only the wire format supported by packet evidence: WIFIIN TCP type `0x03`, WIFIIN UDP-over-TCP type `0x23`, continuous AES-256-CFB streams, the observed acknowledgement, and the legacy provider extension.

A separate Fanster transport must not be fabricated from the Tquic framework name. To implement one, the minimum missing evidence is either:

- a packet capture covering tunnel activation and application traffic while that mode is selected, including UDP/QUIC traffic; or
- a legally decrypted `tunnel` executable suitable for control-flow and constant recovery.

## Code boundary

KuaiFan-specific code resides under one boundary with separate profile implementations:

```text
internal/provider/kuaifan/
  client.go           shared hardened HTTPS transport and strict parsing
  client_profile.go   control-flow adapter contract
  ios_client.go       iOS login, refresh, authority, and catalog flow
  windows_client.go   Windows login, refresh, authority, and catalog flow
  profile/
    profile.go        shared immutable profile contract and verifier primitive
    ios.go            iOS 4.18.4 constants, login schema, and verifier
    windows.go        Windows 4.7.6 beta INTERNATIONAL constants and login schema
  codec.go            shared control-plane compatibility encryption
  driver*.go          KuaiFan dual-profile login/refresh/catalog transaction
  catalog.go          profile-specific opaque authorities and protocol identities
  transport.go        kuaifan-wifiin transport adapter
  wifiin/             observed iOS WIFIIN TCP and UDP-over-TCP wire
  speedin_authority.go  node-keyed Windows SPEEDIN credential contract
  speedin_transport.go kuaifan-speedin transport adapter
  speedin/            recovered Windows SPEEDIN AEAD wire
```

`internal/app` supplies transient credentials and protected installation randomness through the generic provider driver contract. `internal/store` persists the KuaiFan snapshot and its opaque profile authorities without interpreting them. `internal/socks` dispatches each immutable tunnel pin through the protocol registry; KuaiFan's WIFIIN and SPEEDIN adapters decode only their matching protocol authorities.

## Verification against Android 4.18.4.10 and Windows 4.7.6 beta (2026-10)

The full comparison matrices and file/function evidence index are in the October KuaiFan review, kept with the client workspace outside this repository (`clients/20261013/kuaifan/REVIEW.md`; `x/...` paths below are relative to that directory). SPEEDIN and Hysteria2 are specified in [kuaifan-speedin-hysteria2-analysis.md](kuaifan-speedin-hysteria2-analysis.md). The original review used recovered static code and the **prior live check**, without a fresh probe. The later adapter cutover below adopts the recovered beta control profile and distinguishes its fresh control-plane verification from tunnel interoperability. Static presence of a receiver is not proof of production selection or support for every extension.

### Control plane

The Windows beta retains the existing **AES-256-CBC** envelope: PBKDF2-HMAC-SHA1, 100 iterations, 32-byte derived key, the same normal/authority fixed material, Base64 and PKCS#7. Its exported names `aes128Encrypt`/`aes128Decrypt` do not describe the actual key width. Both fixed-material triples were compared against `internal/provider/kuaifan/codec.go` without recording their values. Evidence: beta `base.dll`, `CryptoUtils::aes128Encrypt @ 0x1000A910`, `aes128Decrypt @ 0x1000A570`, CBC helpers `0x10001AC0`/`0x100014C0`; `clients/20261013/kuaifan/x/control-beta-crypto.txt` and `control-beta-material-comparison.txt`, normal caller `core.dll!sub_1000FD50`, authority caller `sub_100149E0`.

The beta still uses `https://ws.kuaifan.co` and `/v4/client/conf.do`, `/v4/user/login.do`, `/v4/user/refresh.do`, `/v4/invpn/getAuthority.do`, and `/v4/invpn/getLines.do`. Its common envelope has the same 17-digit timestamp shape, but generates an eight-digit nonce for all of these requests, unlike the legacy Windows profile's fixed login/authority nonce. Evidence: `x/control-beta-requests.txt`, `CommonRequest` constructor `sub_10004A40`, endpoint initializers `sub_10001100`, `sub_100025E0`, `sub_10001380`, `sub_10001400`; `x/control-beta-provenance.txt`, login initializer `sub_100022E0`; `x/control-beta-schema.txt`, common serializer `sub_100224B0`.

| Element | Android 4.18.4.10 | Windows 4.7.6 beta |
|---|---|---|
| Control codec, fixed material and endpoints | **Not determinable** from inspected application/JNI material | **Confirmed** as above |
| Login fields/constants | **Not determinable**; do not derive API edition from a package namespace | **Changed:** `WINDOWS/INTERNATIONAL/4.7.6`, new legacy-Windows `manufacture` field, fewer legacy fields, generated nonce |
| Windows verifier | **Not determinable** | **Confirmed:** MAC + timestamp and the existing randomized MD5-hex/Base64 construction; not device ID |
| Refresh | **Not determinable** | Request field names **confirmed**; numeric `userId` differs from the adapter's Windows refresh string. Beta lifecycle and legacy `1/119` status rule **not determinable** |
| Authority | **Not determinable** | Request shape **confirmed**, nonce **changed**; response consumption **changed** to decrypted `authKey.userId` and separately stored authority token |
| `getLines` / edition gating | **Not determinable** | Request shape **confirmed**, selectors **changed** to `WINDOWS/INTERNATIONAL/4.7.6`; prior live check selects SPEEDIN, not WIFIIN |

The beta email/password login serializes `time/lang/nonce`, device fields `deviceId/mac/udid/openUdid/osVersion/manufacture/deviceType`, and `account/password/os/edition/clientVersion/promoPlatformCode/verify/loginType`. It does not emit the adapter's legacy Windows `openId/imei/uuid/idfa/signature/certification/packageName/sdkPartnerKey/sdkPartnerUserId/userId` fields. Email `loginType=4`, `deviceType=WINDOWS`, and `promoPlatformCode=speedin.cc` remain; `manufacture=Microsoft Corporation` and dynamically obtained `osVersion` differ from the adapter's fixed historical Windows fingerprint. The MAC-based verifier matches `ComputeWindowsVerify`; its beta helper also rejects timestamps shorter than 17 characters. Evidence: `x/native476/0x1001b750.txt`, login factory `sub_1001B750`; `x/control-beta-schema.txt`, `LoginRequest` serializer `sub_100233B0`; `x/control-beta-crypto.txt`, `SignUtils::makeVerifyCode @ 0x10010D60`; beta `base.dll`, `DeviceUtils::getDeviceType @ 0x1000B9C0`, `getManufacture @ 0x1000C2F0`, `getSysVersion @ 0x1000C310`; `core.dll`, `UserService::emailLogin @ 0x100678A0`.

The beta does **not** use the legacy Windows `cpOrderNo` authority path or consume iOS `encryptKey/encryptType` in its authority parser. It decrypts `authKey` and extracts `userId`, but the token passed to its downloaded proxy template is the **current User/session-model token**, not the separately stored authority response token. `LoginResponse` obtains that User from response `fields`, whose `token` is stored in `User+28`; `ProxyService::start` passes `User+28` and the decrypted authority user number to `makeProxyConfig`. Evidence: `x/control-beta-schema.txt`, authority parser `sub_100149E0`; `x/control-beta-provenance.txt`, `LoginResponse` parser `sub_10015F40`, User parser `sub_100194B0`, `ProxyService::start @ 0x10061430`, `makeProxyConfig @ 0x10060940`. The token domains must not be assumed interchangeable.

In the **prior live check**, a 4.3.30/`MAJOR` catalog request returned 92 WIFIIN/aes-256-cfb rows, while the same session with 4.7.6/`INTERNATIONAL` returned 92 SPEEDIN/aes-128-gcm rows. Changing only the advertised selectors is therefore not a compatible transport upgrade: the current adapter changes the request schema, authority mapping and transport identity together. This comparison does not isolate edition versus version as the cause or itself validate a beta login. Static selectors are independently visible in `x/native476/0x1004d270.txt`, `LineViewService::getLine @ 0x1004D270`. No complete edition matrix or minimum client-version gate was recovered. `THIRD` remains the captured iOS profile; `MAJOR` is historical Windows, replaced by the recovered beta `INTERNATIONAL` profile. Android's resource namespace does not establish an API edition.

### WIFIIN data plane and limits

| Element | Android native core | Beta retained WIFIIN core |
|---|---|---|
| TCP `0x03`, BE16 IV+ciphertext length, trailing clear port | **Confirmed** | **Confirmed**, not proof of beta selection |
| UOT `0x23` and continuous stream | **Confirmed** | **Confirmed**, not the beta's selected provider |
| AES-256-CFB, unsalted MD5-chain 32-byte key, directional 16-byte IV | **Confirmed** | **Confirmed** |
| Successful plaintext `00 00 00` ACK before response IV/ciphertext | **Confirmed** in server success path | **Confirmed** in server success path |
| Seven-field pipe-separated provider extension grammar | **Confirmed**; exact newest outgoing identity constants unknown | **Confirmed** in retained parser; newest emitted WIFIIN identity constants unknown |
| UOT address variants | IPv4 framing **confirmed**; decoder requires ATYP `0x01` | Same IPv4-only reference decoder |

Android evidence is in `x/native-go/`: `ReadAuthHeader @ 0xB11760` (`0xb11760.txt`), `PasswordToCipherKey @ 0xB0FF20`, CFB stream functions `0xB0E230/0xB0E4B0/0xB0F0F0/0xB0F7B0`, `(*Server).handleConnection @ 0xB13DA0`, `TransUdpToTcpPacket @ 0xB12890`, and `TransTcpToUdpPacket @ 0xB12CA0`. Beta evidence is in `x/wifiin-beta-compatibility.txt` from `x/win476/app/proxy.exe`: `ReadAuthHeader @ 0x117C5E0`, `PasswordToCipherKey @ 0x117AC80`, CFB stream functions `0x1179DF0/0x117A3E0`, `WriteAuthAnswer @ 0x117D760`, `(*Server).handleConnection @ 0x117EB00`, and UOT conversions `0x117D820/0x117DB70`. These are WIFIIN implementation findings, not a reinterpretation of SPEEDIN wire formats.

The native UOT converters confirm the IPv4 body format (length, ATYP 1, address, port, two-byte flow identifier, payload) but explicitly reject other ATYP values. The adapter's `wifiin/udp.go`, `udpAddressLength`, also accepts domain and IPv6 variants; production-server support for those extensions is **not determinable** from this review. Likewise, existing `ProviderExtensionForProfile` identity constants remain historical rather than independently re-established as newest outgoing-client values.

Android control-plane unknowns are substantial: the inspected application namespace contains resource code rather than login/API implementations, encrypt/decrypt JNI entry points delegate to `com/wifiin/encryption/dc` selectors, and `JNI_getVerifyCode @ 0x8B88` invokes an indirect helper. Neither native WIFIIN presence nor the adjacent Android/iOS version numbers establishes the Android request schema, crypto constants, edition, refresh policy, or authority mapping. Evidence: `x/jadx/sources/cc/oasis/minor1/R.java`, `x/native-go/0x8164.txt`, `0x8420.txt`, and `0x8b88.txt`.

### Adapter Windows beta cutover

The Windows adapter now sends the exact 18-field beta email/password shape above with generated eight-digit nonces, numeric refresh `userId`, and `WINDOWS/INTERNATIONAL/4.7.6` catalog selectors. It uses `manufacture=Microsoft Corporation` and a synthetic `osVersion=10.0`; unlike the native Windows client, it does not inspect persisted Windows device settings or the host OS. The MAC-based verifier enforces the beta's minimum 17-character timestamp. The iOS request profile, post-login refresh, WIFIIN authority and cipher remain unchanged.

Windows authority parsing decrypts `authKey.userId`, validates it against the session, and keeps the returned authority token separate. The opaque `windows` authority for `kuaifan-speedin` uses the **current session token**, including its rotated refresh value, and node-keyed line passwords. Eligible catalog rows must have `provider=SPEEDIN`, `method=aes-128-gcm`, and a bounded nonempty password. Other providers and explicitly different cipher methods remain ineligible metadata; a SPEEDIN row with a missing/invalid method, or a supported-cipher row with a missing/invalid password, fails the catalog transaction. Conflicting passwords for the same canonical endpoint fail rather than selecting an arbitrary credential. No secret catalog fields enter `provider.Node`.

Existing stored Windows WIFIIN refresh state **migrates on the next successful refresh**, without a password login: its persisted fields are protocol-neutral user IDs and login tokens. Both refreshed profiles must still identify the same user. The new complete snapshot replaces Windows WIFIIN authority/nodes with SPEEDIN authority/nodes atomically; a failed refresh or catalog fetch leaves the prior generation intact (rotated refresh tokens may be returned separately under the existing driver contract). Since protocol is part of canonical node identity, Windows node IDs and local SOCKS usernames change at that successful cutover. A server-rejected historical token follows the existing session-rejection behavior and may require a clean login; no compatibility transport shim is retained.

Remaining evidence gaps are the native beta's complete refresh lifecycle and `1/119` status semantics, its dynamically sourced device `osVersion`, and the minimum edition/version gate. Existing `1/119` Windows login/refresh acceptance and complete-login VIP parsing are retained, not claimed as a fully recovered beta lifecycle. The separate SPEEDIN transport report covers tunnel interoperability; successful control-plane validation alone does not prove data-plane connectivity.

Fresh control-plane verification on 2026-10-13 used exactly one real `Driver.Login` invocation (the driver's separate iOS and Windows profile logins), followed by one `Driver.Refresh`. Both complete snapshots validated: 152 deduplicated iOS WIFIIN nodes and 86 deduplicated Windows SPEEDIN nodes, two protocol-matched authorities, and 86 canonical per-node `aes-128-gcm` passwords in the Windows authority. The reused refreshed Windows session independently returned 30 groups and 92 SPEEDIN catalog rows for the Hysteria2 investigation; endpoint deduplication explains the 86 published Windows nodes. Current session-token binding and node-keyed credentials were checked without printing credentials, tokens, account identifiers or passwords. The throwaway `liveprobe` test was deleted; this check did not open a data-plane tunnel.

`go test -race -count=1 ./internal/provider/kuaifan/...` passed after the profile/catalog/tests cutover, including the unchanged iOS and WIFIIN packages. The permanent tests cover the beta login field set and verifier, generated nonces, numeric refresh user IDs, cipher/password eligibility and malformed rows, decrypted-authority failures and user binding, canonical per-node password conflicts, current-session-token selection, protocol-specific node identity, legacy-state migration and failed-refresh preservation.


## External references

- [KuaiFan official site](https://www.kuaifan.co/) — Fanster marketing claim.
- [Apple App Store listing, app ID 1442745175](https://apps.apple.com/us/app/%E5%BF%AB%E5%B8%86%E5%8A%A0%E9%80%9F%E5%99%A8-%E6%B5%B7%E5%A4%96%E5%9B%9E%E5%9B%BD%E9%9F%B3%E4%B9%90%E8%A7%86%E9%A2%91%E5%8A%A0%E9%80%9F%E5%99%A8/id1442745175) — version 4.18.4 and Fanster marketing claim.
