package web

import (
	"context"
	"net/http"

	"github.com/kfadapter/kfadapter/internal/subscription"
)

// NewSubscriptionAdapter exposes the immutable subscription catalog to web.
func NewSubscriptionAdapter(service *subscription.Service) SubscriptionService {
	if service == nil {
		return nil
	}
	return subscriptionAdapter{service: service}
}

type subscriptionAdapter struct{ service *subscription.Service }

func (a subscriptionAdapter) Metadata(context.Context) (SubscriptionMetadata, error) {
	metadata, err := a.service.Metadata()
	if err != nil {
		return SubscriptionMetadata{}, err
	}
	return SubscriptionMetadata{Active: metadata.Active, NodeCount: metadata.NodeCount}, nil
}

func (a subscriptionAdapter) SubscriptionURL(_ context.Context, baseURL, _ string) (SubscriptionURL, error) {
	url, err := a.service.SubscriptionURL(baseURL)
	if err != nil {
		return SubscriptionURL{}, err
	}
	return SubscriptionURL{URL: url}, nil
}

func (a subscriptionAdapter) ServeSubscription(w http.ResponseWriter, r *http.Request, _, socksAddress string) {
	a.service.HandleSubscription(w, r, socksAddress)
}
