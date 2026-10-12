# chinadapter

chinadapter brings you back into China through the China-based VPN services you already pay for. It turns those accounts into one SOCKS5 proxy you can run at home.

Sign in to your accounts once in its web console, and chinadapter keeps the sessions alive, gathers every node they offer, and publishes them as a single subscription link. Point your proxy client or router at that link and every node shows up, ready to use.

It is meant for a home server or router: a small container that keeps working in the background, without you having to log in again or copy new links whenever something changes.

## What you get

- **One subscription link** for all your nodes, across every provider you link.
- **Stable addresses and credentials.** Your link and proxy logins stay the same when you sign out, switch accounts, add a provider, or restart.
- **Sessions that look after themselves.** Accounts refresh in the background, and the console tells you if one ever needs your attention.
- **A small web console** to link accounts, browse nodes, check their latency, and copy the link.

## Getting started

chinadapter runs with Docker Compose on a Linux machine.

1. Download [`compose.yaml`](compose.yaml) and [`config.yaml`](config.yaml) into a folder, and adjust `config.yaml` if you want different ports or a hostname.
2. Start it with `docker compose up -d`.
3. Open `http://<your-server>:10809`, choose an access token, link your accounts, and copy the subscription link into your client.

## Development

The Go backend lives in `cmd/` and `internal/`, and the web console in `web/`. See [`docs/design.md`](docs/design.md) for how the pieces fit together.

## Disclaimer

chinadapter is an unofficial project and is not affiliated with any VPN provider. Use it only with accounts you own.

## License

[MIT](LICENSE)
