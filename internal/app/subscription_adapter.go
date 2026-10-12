package app

import (
	"context"
	"net/http"

	"github.com/oshinop/chinadapter/internal/credentials"
	"github.com/oshinop/chinadapter/internal/subscription"
	"github.com/oshinop/chinadapter/internal/web"
)

// NewSubscriptionAdapter exposes the immutable subscription catalog to web.
func NewSubscriptionAdapter(service *subscription.Service) web.SubscriptionService {
	if service == nil {
		return nil
	}
	return subscriptionAdapter{service: service}
}

type subscriptionAdapter struct{ service *subscription.Service }

func (a subscriptionAdapter) Metadata(context.Context) (web.SubscriptionMetadata, error) {
	metadata, err := a.service.Metadata()
	if err != nil {
		return web.SubscriptionMetadata{}, err
	}
	return web.SubscriptionMetadata{Active: metadata.Active, NodeCount: metadata.NodeCount}, nil
}

func (a subscriptionAdapter) SubscriptionURL(_ context.Context, baseURL, _ string) (web.SubscriptionURL, error) {
	url, err := a.service.SubscriptionURL(baseURL)
	if err != nil {
		return web.SubscriptionURL{}, err
	}
	return web.SubscriptionURL{URL: url}, nil
}

func (a subscriptionAdapter) ServeSubscription(w http.ResponseWriter, r *http.Request, _, socksAddress string) {
	a.service.HandleSubscription(w, r, socksAddress)
}

func (a subscriptionAdapter) ParseSubscriptionPath(requestPath string) (string, bool) {
	return credentials.ParseSubscriptionPath(requestPath)
}
