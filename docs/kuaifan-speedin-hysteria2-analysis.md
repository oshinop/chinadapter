# KuaiFan newer transports: implementation review

> Evidence paths (`x/...`, `android/...`, `tv/...`, `router-rootfs-complete/...`) refer to the client workspace kept outside this repository at `clients/20261013/kuaifan/`. No credentials, tokens or account identifiers are recorded.

Date: 2026-10-13. Scope: Android 4.18.4.10 and Windows beta 4.7.6 INTERNATIONAL. No chinadapter code changes, no new live login, and no live tunnel/interoperability test. Credentials and concrete account identifiers, tokens, passwords and device identifiers are omitted.

## Executive conclusions

1. **SPEEDIN is a provider-authenticated fork of classic Shadowsocks, not a stock Shadowsocks outbound.** Its `aes-128-gcm` cryptography and outer framing match SIP004/SIP007-era Shadowsocks AEAD, but its decrypted first request is `destination || provider authentication`, and its decrypted TCP response begins with a provider authentication answer. It is not SIP022/Shadowsocks 2022. The key comes from the proxy server `password`, not from the token or account ID. A stock Shadowsocks client would omit the request authentication and expose the response authentication bytes as application data. Evidence: Android `speedin.WriteTCPRequest` @ `0x9eaf20`, `WriteAuthInfo` @ `0x9ed710`, `Client.Process` @ `0x9e4e70`; Windows counterparts @ `0x9863a0`, `0x988940`, and `Account.AsAccount` @ `0x981de0` (dumps below).
2. **Android V2Ray QUIC and Windows Hysteria2 are different protocols.** Android's recovered code uses the older `github.com/lucas-clemente/quic-go` transport, optionally wrapped in V2Ray packet AEAD/header camouflage. Windows uses `github.com/v2fly/hysteria/core/v2` with `github.com/apernet/quic-go`; its recovered authentication, TCP framing and UDP datagram framing agree with the official Hysteria2 specification despite the fork's `international/protocol` package name. Evidence: `x/native-go/0xabb840.txt`, `clientSessions.openConnection`; `x/native476/0xf73050.txt`, `clientImpl.connect`; `0xecb180.txt`, `WriteTCPRequest`; `0xecbce0.txt`, `UDPMessage.Serialize`.
3. **The catalog profile is recovered:** `os=WINDOWS`, `edition=INTERNATIONAL`, `clientVersion=4.7.6`. The prior live observation supplied to this review was 92 `SPEEDIN`/`aes-128-gcm` rows versus 92 `WIFIIN`/`aes-256-cfb` rows for `WINDOWS`/`MAJOR`/`4.3.30` under the existing session. This report inherits that observation; it does not claim an independently captured request or repeat the login. Static beta catalog construction and serialization separately prove those selector fields (`LineViewService::getLine` @ `0x1004d270`; QueryLines serializer `sub_100247A0`).
4. **Implementation readiness:** SPEEDIN TCP has a sufficiently recovered codec and beta credential source chain for an implementation followed by controlled interoperability validation. SPEEDIN UDP is a native encrypted UDP protocol in the recovered client, with an auth block in each packet, but live server support and practical packet-size behavior remain unverified. Hysteria2's wire protocol is recognizable and a stock client is a reasonable candidate *once the actual selected-line/template auth and TLS settings are known*; those catalog mappings were not established. Library presence does not prove that any of the observed SPEEDIN rows uses Hysteria2.
5. **“Fanster” is not proven to be a single wire protocol.** No recovered caller or catalog discriminator cited here equates that marketing name with SPEEDIN, Android QUIC, or Windows Hysteria2. Do not dispatch on the marketing name.

## Evidence conventions and artifact map

All `x/...` paths below are relative to this report's directory. Android addresses refer to the analyzed ARM64 `x/apk/lib/arm64-v8a/libgojni.so`; its Go symbols use `v2ray.com/core/...`. Windows Go addresses refer to `x/win476/app/resources/proxy/proxy.exe`; its symbols use `kuaifan.co/core/v5/...`. Windows `0x100...` addresses refer to the beta control-plane DLL decompilation snapshots (`base.dll` / `core.dll`), as identified by the named C++ class and corresponding snapshot. Addresses are not interchangeable between binaries.

Go decompilation occasionally misidentifies register/stack arguments or omits secondary return values. The specifications below use the ordered calls, runtime struct fields and constants, not the apparent C prototype alone. `x/native476/wire-constants.json` preserves selected nonsecret constants and disassembly where this matters: the address parser's default port-last branch, AES-GCM factory, big-endian uint16 writer, Hysteria ALPN/auth header, SNI fallback and bandwidth unit.

Important evidence groups:

- SPEEDIN crypto: `x/native-go/0x9e9ca0.txt` (`PasswordToCipherKey`), `0x9e9f70.txt` (`hkdfSHA1`); `x/native476/0x983020.txt` (`GetCipher`), `0x983ad0.txt` (`AEADCipher.createAuthenticator`), `0x983ca0.txt` (nonce generator), `0x983cf0.txt` (`NewEncryptionWriter`), `0x97daa0.txt` (`AEADChunkSizeParser.Encode`), `0x97cb10.txt` (`AuthenticationWriter.seal`), `0x97ce50.txt` (`writeStream`), `0x97bc30.txt` (`AEADAuthenticator.Seal`).
- SPEEDIN TCP/auth: Android `0x9eaf20`, `0x9eb760`, `0x9ed710`, `0x9ed970`, `0x9e4e70`; Windows `0x9863a0`, `0x986b40`, `0x988940`, `0x988bb0`, `0x988040`; each has an address-named `.txt` dump in the appropriate native directory.
- SPEEDIN UDP: `x/native476/0x987090.txt` (`EncodeUDPPacket`), `0x984060.txt` (`AEADCipher.EncodePacket`), `0x984310.txt` (`DecodePacket`), `0x987660.txt` (`DecodeUDPPacket`), `0x987d10.txt` (`UDPReader.ReadMultiBuffer`), `0x987f40.txt` (`UDPWriter.WriteMultiBuffer`).
- Beta profile/config sources: `x/native476/0x1001b750.txt`, `0x1004d270.txt`, `0x10014e60.txt`, `0x100149e0.txt`, `0x10060940.txt`; `x/control-beta-requests.txt` and `x/control-beta-provenance.txt`.
- Hysteria: `x/native476/0xf72f50.txt`, `0xf73050.txt`, `0xeca530.txt`, `0xecb180.txt`, `0xecbce0.txt`, `0xf73970.txt`, `0xf7dd70.txt`, `0xf7e200.txt`, `0xf7e540.txt`, `0xf7eb30.txt`, `0xf7d410.txt`, `0xf74320.txt`, `0xf84500.txt`, `0xf84bf0.txt`, `0x1190220.txt`, `0x1189790.txt`.
- Android QUIC: `x/native-go/0xabc010.txt`, `0xabb840.txt`, `0xab9590.txt`, `0xaba630.txt`, `0xab9ed0.txt`, `0x9a70b0.txt`, `0xb2e600.txt`.

For the upstream comparison, see [Shadowsocks AEAD/SIP004/SIP007](https://shadowsocks.org/doc/aead.html) and the [official Hysteria2 protocol specification](https://v2.hysteria.network/docs/developers/Protocol/). These describe the standards; the local functions establish what KuaiFan actually implements.

## 1. Catalog profile and credential provenance

### 1.1 Request profile

| Request property | Beta value | Evidence |
| --- | --- | --- |
| `os` | `WINDOWS` | `LineViewService::getLine` @ `0x1004d270`, lines 56–60 of its dump; QueryLines serializer `sub_100247A0` in `x/control-beta-requests.txt`, lines 127–135 |
| `edition` | `INTERNATIONAL` | Same constructor; QueryLines serializer, lines 136–143 |
| `clientVersion` | `4.7.6` | Same constructor; QueryLines serializer, lines 144–151 |
| Login channel | `speedin.cc` | Beta login builder `sub_1001B750`, `x/native476/0x1001b750.txt`, lines 79–95 |

The login builder uses the same OS/edition/version triplet. Do not infer that edition alone determines the result: the prior observation changed the edition and client version together. The necessary profile is known; the minimal sufficient selector is not. There is no new live evidence in this review about an Android or iOS profile selecting SPEEDIN or Hysteria2.

### 1.2 Catalog fields versus proxy configuration fields

The beta line parser `sub_10014E60` reads `host`, `port`, `password`, `method`, `provider`, `os`, numeric `mode`, `ruleUrl` and `defaultRuleUrl` into its line object (`x/native476/0x10014e60.txt`, particularly lines 96–234). These are **catalog field names**, not necessarily the field names consumed by the Go core. This beta parser uses `mode`, not the existing adapter's metadata property `Model`; the cited parser does not establish a per-line `confUrl` field.

For a SPEEDIN outbound, the Go config builder consumes a server endpoint with these roles:

| Role | Catalog/client source | Go outbound server field |
| --- | --- | --- |
| Upstream endpoint | Selected line `host`, `port` | `address`, `port` |
| Cipher password | Selected line `password` / selected-line proxy password slot | `password` |
| Cipher selection | Catalog `method`; beta template substitution forces `aes-128-gcm` | `method` (builder calls it `Cipher`) |
| Provider selector | Catalog `provider=SPEEDIN`; actual proxy config contains protocol `speedin` | Outbound `protocol= speedin` |
| Numeric provider account identifier | Decrypted authority `authKey`'s `userId` | `userId` |
| Provider authentication token | **Current beta User/session model token** | `token` |
| Authentication OS | Beta substitution hardcodes `WINDOWS` | `os` |

The bundled `x/win476/app/resources/proxy/config.json` demonstrates the SPEEDIN server-field schema, but its literal credentials are deliberately not reproduced and should not be used as a live configuration. The Go `SpeedinClientConfig.Build` @ `0x118cc70` verifies address/port/password, copies account ID/token/OS/password into `speedin.Account`, and maps the configured cipher string. `Account.AsAccount` @ `0x981de0` derives the key from `Account.Password` and keeps `UserId`, `Token`, and `Os` as separate fields. Therefore **a token is not an AES password**, and the legacy WIFIIN authority encryption key should not automatically replace the newer selected-line password.

The beta's downloaded-template completion function `sub_1005D220` replaces `${address}` and `${port}` unconditionally, then, only when the template text contains `speedin`, replaces `${userId}`, `${token}`, `${password}`, `${os}` and `${method}`. The last two become `WINDOWS` and `aes-128-gcm`. Exact substitutions are in `x/control-beta-requests.txt`, lines 786–837. `ProxyService::makeProxyConfig` @ `0x10060940` downloads a selected template URL rather than constructing every outbound locally. This means a catalog provider string or cipher alone is not a complete description of every possible template's transport.

The endpoint/password provenance is also direct, not a guess from matching names: `sub_10014E60` stores host/port/password at Line offsets `+52`, `+8`, `+60`. `ProxyService::start` @ `0x10061430` calls Line copier `sub_10046850` into its Line subobject at ProxyService `+0x10`. Those values therefore become ProxyService offsets `+68`, `+24`, `+76`, exactly the slots substituted by `sub_1005D220`. Evidence: `x/control-beta-provenance.txt`, lines 682–723. The method slot is copied too, but the template callback still replaces `${method}` with the fixed AES-128-GCM string.

### 1.3 Important token correction

The beta does **not** feed the separately parsed authority response token directly into `${token}`:

1. LoginResponse parser `sub_10015F40` takes response JSON `fields` and constructs a `User` (`sub_10005630`).
2. The User parser `sub_100194B0` reads that object's `token` into User offset `+28`. Thus the login source is **LoginResponse.fields.token**, not a top-level JSON token and not `userInfo.token`.
3. `ProxyService::start` @ `0x10061430` calls `UserService::fetchAuthInfo` @ `0x10067b10`, then passes `IneAuthInfo+4` as the numeric account identifier and `(current UserService User)+28` as the token argument to `makeProxyConfig`.
4. `makeProxyConfig` carries that argument to `sub_1005D220`, which uses it for `${token}`. The current User may subsequently have been refreshed; the immediate source remains the current User model.

Evidence: `x/control-beta-provenance.txt`, `sub_10015F40`, `sub_100194B0`, and `ProxyService::start`, especially lines 497–509; `x/native476/0x100149e0.txt`, `sub_100149E0`, decrypts `authKey`, extracts `userId`, and separately stores the authority response token at `+8`. This separate storage is not proof that the stored authority token is used in the outbound. Preserving that distinction is necessary for a beta-compatible implementation. Android's corresponding account/token assembly provenance was not fully recovered here; do not assume it chooses the identical control-plane token without tracing its builder.

## 2. SPEEDIN specification

### 2.1 Cryptography for `aes-128-gcm`

Use the password bytes supplied in the server configuration:

```text
D1 = MD5(password)
Di = MD5(D(i-1) || password)          for longer supported key lengths
masterKey = first keyLength bytes of D1 || D2 || ...
subKey = HKDF-SHA1(masterKey, salt, info="ss-subkey", outputLength=keyLength)
```

For `aes-128-gcm`, `keyLength=16`, so `masterKey=MD5(password)`. This is classic Shadowsocks EVP_BytesToKey-style derivation, not Base64 decoding of a 2022 PSK and not a derivation from account ID/token/OS.

| Parameter | Recovered value |
| --- | --- |
| AES master/subkey length | 16 bytes |
| TCP salt length | 16 bytes, random for each outbound stream direction |
| UDP salt length | 16 bytes, random for each packet |
| GCM nonce length | 12 bytes |
| GCM authentication tag | 16 bytes |
| HKDF info | Exact ASCII `ss-subkey`, without terminator |
| AEAD additional authenticated data | No additional-data generator configured in recovered SPEEDIN constructors |
| Initial nonce | All zero bytes on first Seal/Open |
| TCP nonce progression | Little-endian increment once per AEAD operation; twice per chunk |
| UDP nonce | All zero for the one AEAD operation under each fresh packet subkey |

Evidence: `PasswordToCipherKey` @ `0x9e9ca0` / Windows `0x985100`; `hkdfSHA1` @ `0x9e9f70` / Windows `0x985440`; `GetCipher` @ `0x983020`, cipher enum 5 has `KeyBytes=16`, `IVBytes=16`; `createAesGcm` @ `0x982ec0` calls `crypto/aes.NewCipher` then `crypto/cipher.NewGCM` (`wire-constants.json`). `AEADCipher.createAuthenticator` @ `0x983ad0` initializes 12 bytes to `0xff`; its increasing-nonce closure @ `0x983ca0` increments from byte 0 with carry, and `AEADAuthenticator.Seal` @ `0x97bc30` calls the generator *before* Seal. Consequently the first nonce wraps to zero, not all `0xff`. The same authenticator is shared by the chunk-length parser and body writer (`NewEncryptionWriter` @ `0x983cf0`).

The core also contains AES-256-GCM and ChaCha20-Poly1305 AEAD choices (32-byte key/salt) and older stream ciphers (`GetCipher` @ `0x983020`; `speedinCipherFromString` @ `0x118c650`). They are not evidence that current INTERNATIONAL rows advertise those methods. The recommended initial implementation target is the observed AES-128-GCM profile.

### 2.2 Destination address header

The address is encoded in the classic Shadowsocks/SOCKS address-family form, with the **port last and big-endian**:

```text
IPv4:   0x01 || IPv4[4]                    || port_be16
Domain: 0x03 || domainByteLength_u8 || domainBytes || port_be16
IPv6:   0x04 || IPv6[16]                   || port_be16
```

Domain names are raw configured string bytes, not null-terminated; the writer rejects a domain length over 255. The first byte is an address-family byte, not a SPEEDIN version or a command field.

Evidence: `speedin.init` @ `0x98f120` sets the wire mappings 1/3/4; its `AddressFamilyByte` closures @ `0x97f160`, `0x97f1c0`, `0x97f220` fill the parser's maps. `common/protocol.NewAddressParser` @ `0x9248e0` defaults to the port-last serializer (disassembly retained in `wire-constants.json`); `addressParser.writeAddress` @ `0x925820` handles family-specific bytes/domain length; `portLastAddressParser.WriteAddressPort` @ `0x924f40` writes the address then `serial.WriteUint16` @ `0x65c1a0`, whose byte swap establishes network byte order. `WriteTCPRequest` @ `0x9863a0` invokes this serializer before auth.

On UDP decode the native code masks the first decrypted address byte with `0x0f` before parsing (`DecodeUDPPacket` @ `0x987660`, lines 143–153). The recovered encoder emits the ordinary address byte, not an extra high-nibble field. Meaning/validity of nonzero high-nibble extensions was not recovered.

### 2.3 Provider authentication block

The auth string is:

```text
ASCII_decimal_account_id || "|" || token_bytes || "|" || os_bytes
```

Its on-wire encoding inside the encrypted plaintext is:

```text
0x01 || authStringByteLength_be16 || authStringBytes
```

There is no trailing null byte or extra delimiter. Length is the string's byte length. The native reader expects auth version 1, splits the string on `|`, requires exactly three components, and parses the first as a decimal integer. This is a different format from chinadapter's existing WIFIIN provider extension: **do not append the legacy WIFIIN extension or order/package/device fields** to this SPEEDIN block. No timestamp, device identifier, request signature, order ID, or separate token-derived MAC is present in the recovered SPEEDIN writer.

Evidence: Android `WriteAuthInfo` @ `0x9ed710`, lines 21–42; Windows `WriteAuthInfo` @ `0x988940`; `ReadAuthInfo` @ `0x988040`, lines 121–167 and 216–226. Separate account/password fields in `Account.AsAccount` @ `0x981de0` also rule out token substitution as key material in this path. This describes the writer's complete block; it does not claim that the control plane never uses those other identifiers.

### 2.4 TCP framing and response handshake

Client-to-server:

```text
salt[16]
AEAD(subKey, nonce=0, plaintext=firstChunkLength_be16)       // 2 ciphertext + 16 tag
AEAD(subKey, nonce=1, plaintext=addressHeader || authBlock)  // plaintext length + 16 tag
AEAD(subKey, nonce=2, plaintext=nextChunkLength_be16)
AEAD(subKey, nonce=3, plaintext=applicationBytes)
...
```

Length means the **plaintext chunk length**, excluding the body tag. Native implementation detail: the generic writer calculates ciphertext length including overhead, but `AEADChunkSizeParser.Encode` explicitly subtracts the AEAD overhead before encrypting the 16-bit value. Do not accidentally encrypt `payloadLength+16` as the wire length.

The initial destination+auth buffer is written through the same encryption writer; subsequent application data follows through that writer and nonce sequence. It is not a second cipher stream or a new nonce sequence. The recovered initial writer does not add an unencrypted authentication preface or a second salt for auth. General chunk boundaries should not be exposed to the application.

Server-to-client uses its own salt/subkey/nonce sequence. `ReadTCPResponse` first obtains the response salt and decrypting reader. `Client.Process` then consumes exactly this decrypted provider answer before forwarding remaining bytes:

```text
status_u8 || detail_be16
```

Status 1 is accepted; a read error or any other status fails the connection. The native acceptance branch does **not** require a particular `detail` value. The semantic mapping of `detail` values and rejected status codes is unknown. This answer is inside the decrypted response stream, not a plaintext byte before the response salt. It may share a decrypted chunk with later application bytes, so an implementation must preserve buffered remainder.

Evidence: Android `WriteTCPRequest` @ `0x9eaf20`; Windows @ `0x9863a0`, lines 187–243; `NewEncryptionWriter` @ `0x983cf0`; `AuthenticationWriter.seal` @ `0x97cb10`; `AEADChunkSizeParser.Encode` @ `0x97daa0`; Android `ReadTCPResponse` @ `0x9eb760`, `ReadAuthAnswer` @ `0x9ed970`, and `Client.Process` @ `0x9e4e70`, lines 546–582. Windows equivalents are `0x986b40` and `0x988bb0`.

**Chunk limits:** the recovered Windows writer limits its serialized chunk buffer to 2048 bytes (`AuthenticationWriter.seal` @ `0x97cb10`, line 58). With an 18-byte encrypted length and 16-byte body tag, that gives a maximum emitted plaintext chunk of **2014 bytes**, absent padding. SPEEDIN's writer construction does not install a padding generator (`NewEncryptionWriter` @ `0x983cf0`). This is smaller than the standard AEAD protocol's 0x3fff maximum. Conservatively emit at most 2014 bytes; the live server's accepted maximum and all oversized-reader behavior have not been validated. Do not claim that this writer limit is itself an additional wire header or a server limit.

**Stock Shadowsocks conclusion:** the outer cryptography can be implemented with standard AEAD primitives, but a stock Shadowsocks outbound is not sufficient. A custom transport must insert the provider block immediately after the destination and consume the provider answer before reporting readiness or relaying application data. This follows directly from the native request/response calls above.

### 2.5 UDP framing

Each client UDP datagram is independently encoded:

```text
salt[16] || AEAD(subKey, nonce=0,
                 plaintext=addressHeader || authBlock || UDP_payload)
```

There is **no encrypted TCP-style length pair** and no outer session/packet ID in the recovered SPEEDIN encoder. Address and auth use the exact forms above. Every packet contains auth; this is not an auth-once-per-socket protocol. The native client reader uses `DecodeUDPPacket`, which decrypts a packet, consumes the address header, consumes `ReadAuthInfo`, and returns the remaining payload. Thus the recovered receive codec also expects an auth block after the address; omitting it would hand auth bytes to SOCKS clients or fail parsing. No `status_u8 || detail_be16` TCP auth answer is consumed by this UDP path.

Evidence: `EncodeUDPPacket` @ `0x987090`, lines 83–153 and 195–216; `AEADCipher.EncodePacket` @ `0x984060` derives the packet subkey from the leading salt and applies a single Seal; `AEADCipher.DecodePacket` @ `0x984310`; `DecodeUDPPacket` @ `0x987660`, lines 142–207; `UDPReader.ReadMultiBuffer` @ `0x987d10`, lines 67–80. UDP writer/readers operate on datagrams (`UDPWriter.WriteMultiBuffer` @ `0x987f40`), not a stream carrier.

The native encoder uses a pooled bounded buffer, copies at most its remaining space, and then the AEAD packet method separately checks room for the tag (`0x987090`, lines 195–210; `0x984060`, lines 77–84). Exact successful payload limits across address/auth sizes and oversize behavior should be established in codec tests; do not silently truncate application datagrams in a new implementation. No SPEEDIN fragmentation/reassembly scheme was recovered. **Live UDP server support, returned address/auth contents, and a remotely positive UDP admission signal remain unverified.**

## 3. Android QUIC: recovered V2Ray transport, not Hysteria2

`v2ray.com/core/transport/internet/quic.Dial` @ `0xabc010` obtains a QUIC transport config and creates/reuses a QUIC connection; `clientSessions.openConnection` @ `0xabb840` calls `github.com/lucas-clemente/quic-go.dialContext`. Its config sets a 12-byte connection ID, 8-second handshake timeout and 30-second max idle timeout. It returns an `interConn` backed by a QUIC stream, not a Hysteria UDP session.

### 3.1 QUIC security/obfuscation

The QUIC config has a `Key`, a `Security` choice and optional packet `Header` configuration. `QUICConfig.Build` @ `0xb2e600` copies `Key`, builds the optional header config, and maps security strings including AES-128-GCM and ChaCha20-Poly1305.

`quic.getAuth` @ `0xab9590` computes:

```text
keyHash = SHA256(configKeyBytes || "v2ray-quic-salt")
AES-128-GCM wrapper key = first 16 bytes of keyHash
ChaCha20-Poly1305 wrapper key = all 32 bytes of keyHash
```

The default/automatic security path selects AES-128-GCM; the `none` enum produces no packet AEAD. This is **an outer UDP packet wrapper around QUIC**, independent of SPEEDIN's Shadowsocks key. `sysConn.WriteTo` @ `0xaba630` optionally serializes the configured header, generates a random nonce of the AEAD's nonce size, and emits header/nonce/ciphertext. AES-GCM uses 12-byte nonce and 16-byte tag (`0xab9590`, lines 47–56); ChaCha20-Poly1305 is the normal 32-byte-key variant (`lines 58–67`). It is not the Hysteria Salamander algorithm. A concrete catalog-to-QUIC-key/security/header mapping was not recovered.

### 3.2 TLS and ALPN

Without explicit TLS config, `quic.Dial` constructs a config with `ServerName=quic.internal.v2ray.com` and `AllowInsecure=true` (`x/native-go/0xabc010.txt`, lines 36–43). With explicit TLS config, the dialer passes it through `tls.Config.GetTLSConfig` and a destination option (`0xabb840`, lines 187–205).

The recovered TLS builder uses configured `NextProtocol`; if that list is empty in this path it installs `h2` and `http/1.1` (`tls.Config.GetTLSConfig` @ `0x9a70b0`, lines 167–181). These are the recovered defaults, **not evidence of a live negotiated ALPN or an HTTP/3/Hysteria authentication exchange**. Explicit config can override them. Actual selected SNI, certificate roots/pins, ALPN and allowance for insecure verification remain dependent on unrecovered selected-line/template settings.

### 3.3 Catalog selection and feasibility

No cited caller proves that `provider=SPEEDIN`, `method=aes-128-gcm`, or a particular numeric `mode` forces this QUIC dialer. Do not translate those rows into Hysteria2 just because the binary contains QUIC. A V2Ray-compatible QUIC carrier plus custom SPEEDIN proxy would require both the carrier settings and the inner provider authentication; neither a stock Shadowsocks outbound nor a stock Hysteria2 outbound supplies this combination automatically. This is an implementation constraint inferred from the separately recovered SPEEDIN and QUIC layers, not a tested live transport stack.

## 4. Windows Hysteria2

### 4.1 Libraries and recognized protocol

The beta Go proxy contains:

- `github.com/v2fly/hysteria/core/v2/client` (`NewClient` @ `0xf72f50`, `clientImpl.connect` @ `0xf73050`, `TCP` @ `0xf73970`).
- `github.com/v2fly/hysteria/core/v2/international/protocol` (auth headers @ `0xeca530`, TCP request @ `0xecb180`, UDP serialization @ `0xecbce0`).
- `github.com/apernet/quic-go` and its HTTP/3 transport (`http3.Transport.dial` @ `0xf6e0a0`; types/calls in `0xf73050`).
- Separate KuaiFan proxy/transport integration: `proxy/hysteria2.ConnWriter.writeTCPHeader` @ `0xf84500`, `PacketWriter.WriteTo` @ `0xf84bf0`, and `transport/internet/hysteria2` client/TLS/UDP layer @ `0xf7dd70`, `0xf7e200`, `0xf7eb30`, `0xf7d410`.

This identifies the library families, not an exact upstream commit/version or a guarantee of unchanged internals. Those revisions were not recovered.

### 4.2 ALPN, auth and TLS

**ALPN:** the recovered HTTP/3 dialer installs `h3` for QUIC v1 (`http3.Transport.dial` @ `0xf6e0a0`, lines 56–90; exact constant at `0x14dc3c6` retained in `wire-constants.json`). This is not Android QUIC's `h2`/`http/1.1` default.

**Authentication:** `Hy2Config.Build` @ `0x1190220` copies its `Password` directly into the transport's `Config.Password`. `NewHyClient` @ `0xf7e200` copies this into Hysteria client `Config.Auth`. No password KDF, token hash or SPEEDIN auth-block construction appears in this recovered path. `clientImpl.connect` @ `0xf73050` sends HTTP/3:

```text
POST https://hysteria/auth
Hysteria-Auth: the configured auth string
Hysteria-CC-RX: decimal maximum receive bytes/second
Hysteria-Padding: generated padding
```

It requires HTTP status **233**; otherwise it closes with an auth error (`0xf73050`, lines 181–248). Header names/format are from `AuthRequestToHeader` @ `0xeca530`; the exact `Hysteria-Auth` constant is retained in `wire-constants.json`. This matches the official Hysteria2 authentication exchange. **The service's actual auth string might already be assembled by a remote template or other caller; direct copy does not prove which catalog/session field supplies it.** In particular, do not invent `account|token|WINDOWS` as Hysteria auth merely because SPEEDIN uses that string.

**TLS/SNI:** KuaiFan's `GetClientTLSConfig` @ `0xf7dd70` requires an explicit core TLS config and transfers `RootCAs`, `ServerName`, `InsecureSkipVerify` and `VerifyPeerCertificate` into Hysteria TLS config. Its destination option fills empty ServerName from the upstream destination (helper @ `0xf7df60`, retained in `wire-constants.json`); the HTTP/3 dialer also fills an empty name from its dial target (`0xf6e0a0`, lines 38–54). These are certificate/SNI configuration capabilities, not proof of a provider-wide fixed SNI or pin. Actual catalog/template TLS values and whether pinning is required remain unknown. Do not default to insecure TLS solely because Android's unrelated QUIC fallback does so.

### 4.3 Bandwidth and obfuscation

`Hy2Config` includes `Congestion.Type`, `Congestion.UpMbps`, `Congestion.DownMbps`, `UseUDPExtension`, and `IgnoreClientBandwidth` (`Hy2Config.Build` @ `0x1190220`). In `NewHyClient` @ `0xf7e200`, the two bandwidth values are copied to Hysteria `MaxTx` and `MaxRx` after multiplication by **125000**, converting Mbps to bytes per second (constant `0x210cb20`, `wire-constants.json`). The client sends `MaxRx` in `Hysteria-CC-RX` and processes server rate/UDP response headers (`clientImpl.connect` @ `0xf73050`). The actual line's configured bandwidth and congestion choice are not established.

**Salamander:** the recovered KuaiFan client connection factory creates a plain `net.UDPConn` and returns it directly (`NewHyClient.func1` @ `0xf7e540`, lines 16–49). `NewHyClient` uses this factory (`0xf7e200`, lines 69–87 and 145–150). There is no Salamander wrapper or obfuscation password passed in this recovered client factory/config conversion. Therefore the evidence-supported setting for *this path* is **no Salamander**, not a guessed shared obfs password. This is a path-level conclusion, not a claim that the complete linked binary could never contain another obfuscated path. HTTP padding is not Salamander packet obfuscation.

### 4.4 TCP and UDP formats

The recovered Hysteria core TCP request is:

```text
QUIC_varint(0x401)
QUIC_varint(addressByteLength) || ASCII_host_colon_port
QUIC_varint(paddingByteLength) || paddingBytes
```

`international/protocol.WriteTCPRequest` @ `0xecb180` emits decimal 1025 (=0x401) then address and padding lengths/bytes. `clientImpl.TCP` @ `0xf73970` opens a QUIC stream, writes that request and uses `ReadTCPResponse` to check it. The KuaiFan integration splits the same header across layers: transport `Dial` @ `0xf7eb30` emits 0x401, and proxy `ConnWriter.writeTCPHeader` @ `0xf84500` emits destination and padding; it does not insert the SPEEDIN user-ID/token/OS block. The latter enforces address length at most 2048 and chooses 64–511 bytes of random alphanumeric padding (lines 46–60). Padding distribution is a client choice, not an extra interoperability credential.

The UDP wire message matches official Hysteria2:

```text
sessionID_be32 || packetID_be16 || fragmentID_u8 || fragmentCount_u8
|| QUIC_varint(addressByteLength) || ASCII_host_colon_port || UDP_payload
```

`UDPMessage.Serialize` @ `0xecbce0`, lines 43–62, proves the fixed header/byte order/varint address length. `udpIOImpl.SendMessage` @ `0xf74320` serializes that message and passes it to the QUIC connection's datagram sender. `HyConn.WritePacket` @ `0xf7d410` builds/forwards UDP messages. Transport `Dial` @ `0xf7eb30`, lines 82–100, selects a native UDP session when the outbound network is UDP and `UseUdpExtension` is enabled. Consequently native SOCKS UDP relay through QUIC datagrams is available in the library; it is not necessarily enabled in a selected template or supported by the live server. Fragmentation/UDP support negotiation is handled by the Hysteria core; this review did not validate every fragmentation/reassembly edge case.

### 4.5 Which catalog fields select Hysteria2?

**Unknown, not inferred from the SPEEDIN rows.** The line parser retains `provider`, `method` and numeric `mode`; beta `makeProxyConfig` downloads a selected service-level template URL and selectively substitutes SPEEDIN values (`0x10014e60`, `0x10060940`, `sub_1005D220` in `x/control-beta-requests.txt`). The numeric mode-to-transport/template mapping is not established, and the cited line parser does not prove a per-line `confUrl`. The core has `Hysteria2ClientConfig.Build` @ `0x1189790`, which constructs target server address/port with a Hysteria proxy account, and a separate `Hy2Config.Build` @ `0x1190220`, which supplies transport auth/bandwidth. The recovered target builder does not establish a catalog credential-to-auth derivation.

No retained INTERNATIONAL catalog evidence cited here proves a `provider=HYSTERIA2` row, a special `method`/`mode` value, a particular template that activates Hysteria2, or a profile that returns one. A SPEEDIN AES-GCM row is sufficient evidence for custom SPEEDIN, not for Hysteria2. Establishing the Hysteria selector requires the actual remotely selected template and its source fields, not another guess at the cipher method.

### 4.6 Off-the-shelf compatibility assessment

| Candidate | Assessment |
| --- | --- |
| Stock Shadowsocks outbound for `SPEEDIN` | **No**, not by supplying host/port/password/method alone. Missing request auth block and response-answer consumption (`0x9863a0`, `0x988940`, `0x9e4e70`). |
| Standard Hysteria2 outbound (sing-box/mihomo or official client) for the recovered Windows Hysteria2 path | **Plausible, conditional; not live-tested.** Auth POST/status, h3, TCP 0x401/address/padding and UDP layout match official Hysteria2 (`0xf73050`, `0xeca530`, `0xf6e0a0`, `0xecb180`, `0xecbce0`). Supply the actual endpoint, auth string, SNI/trust policy and bandwidth; do not enable Salamander for the recovered plain-UDP factory. |
| Hysteria2 outbound for Android V2Ray QUIC | **No protocol equivalence established.** Different QUIC library, TLS defaults and optional packet AEAD wrapper (`0xabb840`, `0xabc010`, `0xab9590`, `0xaba630`). |

The `international/protocol` namespace alone is not a demonstrated incompatibility. Conversely, matching the examined fields is not a proof that every live server behavior or fork change is identical. No off-the-shelf client connection was attempted here.

## 5. Recommended chinadapter implementation plan

These are recommendations, not code changes made by this review. Contract evidence is `chinadapter/internal/provider/provider.go` (`Protocol`, `Authority`, `Node`) and `internal/provider/transport.go` (`Transport`, `DatagramTransport`, `RelayRequest`, `DatagramRequest`). The present KuaiFan path hardcodes `kuaifan-wifiin` and profile-level `Password/Method/Extension` (`kuaifan/driver.go`, `WIFIINProtocol`; `catalog.go`, `tunnelAuthority`, `snapshot`, `nodesFromLines`).

### 5.1 Protocol dispatch and snapshot/authority shape

- Add an explicit provider protocol identity such as **`kuaifan-speedin`** and its transport. Do not relabel it `kuaifan-wifiin`, generic Shadowsocks or Hysteria2. If Hysteria rows are later established, use a separately identified Hysteria2 transport; distinguish any V2Ray QUIC carrier from Hysteria2 rather than dispatching both on “QUIC”.
- Extend validated catalog parsing to retain newer `provider`, `method` and **per-line password** without leaking that password in `provider.Node`. Keep host/port/name/group/model secret-free as today. The current `kuaifan/lines.go`, `Line` and `parseLine`, do not provide the newer complete transport credential shape.
- A SPEEDIN private authority should contain numeric account identifier, the **current profile-specific User/session token**, auth OS, cipher method and selected-line cipher password. If passwords/methods differ by node, authorities must be assigned by compatible credential set/node rather than assuming one legacy authority per profile. Keep tokens out of node IDs and metadata; the existing `provider.Authority.Data` is the appropriate private boundary.
- Preserve token provenance when refreshing: selected-line cipher password, User/session authentication token, and the separately fetched authority token are different inputs. The beta-equivalent source for SPEEDIN is section 1.3, not an assumption that every field named `token` is interchangeable. Revalidate snapshots without mutating credentials pinned by an in-flight relay.
- Do not make arbitrary downloaded provider JSON an unrestricted adapter configuration. The evidence shows the native app uses templates; an adapter should decode only the supported transport settings needed for its provider contract, once their provenance is known. In particular, a line claiming SPEEDIN must not silently route through an unrelated/direct transport.

### 5.2 SPEEDIN TCP implementation

Implement a small provider-owned codec with Go's standard AES-GCM, MD5 password derivation and HKDF-SHA1. Reuse generic address parsing/relay lifecycle patterns where compatible, but not WIFIIN's wire extension. Establish the requested node connection through `RelayRequest.Dial`, send salt + encrypted destination/auth, obtain/decrypt response salt and consume the status/detail answer. Only after status 1 and the final `Admit` check should `Ready` be called and application bytes be relayed. Preserve response bytes read ahead while parsing auth; support partial reads/writes and independent directional nonce sequences. Emit native-compatible chunks at most 2014 plaintext bytes.

Tests to write/run during the later implementation: synthetic password/salt vectors, nonce carry, authenticated length/body corruption, IPv4/IPv6/domain headers, byte-counted auth string, coalesced and split response answer, rejected auth statuses, cancellation/handshake timeout, and isolation between authority snapshots. These are proposed acceptance checks, **not checks exercised in this report**.

### 5.3 SPEEDIN UDP

The recovered protocol is natively UDP and fits `DatagramTransport.RelayDatagrams` with per-packet salt/subkey/auth, remote address reconstruction and SOCKS UDP framing at the `PacketIO` boundary. It does not need TCP encapsulation for its datagram wire format. Before exposing the capability, establish live server UDP availability, packet bounds and how the adapter's authenticated `Ready`/admission semantics are satisfied without the TCP auth answer; that positive signal was not recovered in the UDP codec. Do not treat an unauthenticated local socket bind as evidence of provider authentication. Use synthetic tests for malformed packets, auth-block parsing, reply destination, oversized datagrams and lifecycle cleanup, then a controlled live UDP request if authorized.

### 5.4 Hysteria2 and QUIC

Do not hand-roll QUIC or import the entire provider's V2Ray fork just to use a recognizable wire protocol. Once a real Hysteria-selected template is obtained, first validate its endpoint/auth/TLS/bandwidth with an official or maintained Hysteria2 implementation. A maintained Go Hysteria2 client can provide TCP streams and native QUIC datagrams behind the existing transport interfaces. Pin connection reuse to the immutable endpoint/authority/TLS configuration and ensure socket creation respects the adapter's node-only dialing policy; the native Hysteria factory opens UDP sockets itself (`0xf7e540`), while chinadapter passes a `DialContextFunc`, so integration must explicitly reconcile that boundary instead of allowing unmanaged dialing.

A reusable Hysteria connection must complete HTTP/3 authentication, and each TCP relay must complete the destination response before `Ready`. Native UDP capability depends on server `Hysteria-UDP` negotiation and the chosen configuration, not merely on the existence of `SendMessage`. Preserve certificate verification by default; do not invent or disable pins. Implement Android V2Ray QUIC only if selected templates actually require it and the Key/Security/Header/TLS mapping is recovered; it is a separate carrier undertaking and not an automatic requirement for current SPEEDIN TCP support.

## 6. Explicit unknowns and validation boundary

| Unresolved point | What is known / evidence needed |
| --- | --- |
| Marketed Fanster-to-wire identity | No cited caller identifies one protocol by that name. |
| Android SPEEDIN account/token source chain | Wire `UserId/Token/Os` fields are recovered; its exact control-plane builder source was not established like the beta's chain. |
| Minimal catalog selector | The complete beta triplet is proven; prior comparison changed edition and version together. |
| Live SPEEDIN auth/tunnel success | No live tunnel probe in this review; native status 1 acceptance is proven. |
| Auth detail/error code meanings | Byte/uint16 framing and status 1 success known; detail semantics unknown. |
| Server chunk/payload maxima, anti-replay policy | Client emitted chunk limit and packet codec known; server acceptance window, salt-replay policy and oversize behavior not established. |
| Live SPEEDIN UDP and readiness | Native datagram codec has auth in both parsed directions; server availability and positive UDP admission signal unknown. |
| Actual Hysteria-selected catalog row/template/profile | Hysteria code exists; no proven discriminator or captured selected Hysteria template. |
| Hysteria auth derivation from service fields | Core copies configured Password unchanged; upstream template/caller assembly remains unknown. |
| Hysteria live SNI, roots/pins, rates and obfs | Configuration capabilities and plain-UDP client factory known; actual selected settings unknown. |
| Exact library revisions and complete fork compatibility | Package identities and examined standard wire formats known; no commit mapping or live stock-client test. |
| Android QUIC actual selection/key/header/TLS | Carrier code/defaults known; active catalog mapping and negotiated settings unknown. |

The completed deliverable is this evidence-backed specification and feasibility assessment. No credentials were read for a new login, no provider was contacted through a tunnel, no chinadapter build/test/lint was run, and no repository source files or commits were changed. The next validation should target the concrete unknowns above rather than repeat an already confirmed INTERNATIONAL catalog login.
