package kuaifan

import (
	"context"
	"net/url"
	"strings"
)

// APIBase validates a remotely supplied control endpoint against the configured
// HTTPS hostname allowlist.
func (c *Client) APIBase(raw string) (*url.URL, error) {
	return parseApprovedBase(raw, c.allowedHosts)
}

// ClientConfig is the validated result of client/conf.do.
type ClientConfig struct {
	APIBase *url.URL
}

// FetchClientConfig obtains client configuration from the fixed bootstrap host.
// An absent or unapproved replacement is deliberately ignored in favor of the
// documented bootstrap API base.
func (c *Client) FetchClientConfig(ctx context.Context) (ClientConfig, error) {
	response, err := c.post(ctx, c.bootstrapBase, "/v4/client/conf.do", c.profile.configFields())
	if err != nil {
		return ClientConfig{}, err
	}
	if *response.Status != 1 {
		return ClientConfig{}, businessStatus(*response.Status)
	}
	base := cloneURL(c.bootstrapBase)
	if domain, ok := optionalNestedString(response.Fields, "domain", "ws"); ok && domain != "" {
		// Some observed config responses carry a host rather than a full URL;
		// construct HTTPS explicitly before applying the administrator allowlist.
		if !strings.Contains(domain, "://") {
			domain = "https://" + domain
		}
		if candidate, err := c.APIBase(domain); err == nil {
			base = candidate
		}
	}
	return ClientConfig{APIBase: base}, nil
}
