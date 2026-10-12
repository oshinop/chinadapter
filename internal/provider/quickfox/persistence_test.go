package quickfox

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
	storepkg "github.com/kfadapter/kfadapter/internal/store"
	"github.com/kfadapter/kfadapter/internal/subscription"
)

func TestQuickFoxSnapshotSurvivesSQLiteRestart(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := storepkg.NewSQLiteStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(t.Context()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	node := state.Node{Provider: ProviderID, Protocol: NativeProtocol, AuthorityID: authorityID, Host: "34.160.111.145", Port: 80, Name: "西雅图专线", Group: "国内模式 / 美国节点", Model: "国内模式", Eligible: true}
	node.ID, err = provider.NodeID(node.Route())
	if err != nil {
		t.Fatal(err)
	}
	providerSnapshot := provider.Snapshot{
		Provider:  ProviderID,
		Account:   provider.Account{UserID: "15904241", Display: "a•••@example.com", Tier: vipTier, SubscriptionActive: true, SubscriptionEndsAt: now.Add(24 * time.Hour)},
		ExpiresAt: now.Add(time.Hour), RefreshState: []byte(`{"token":"0123456789abcdef0123456789abcdef","userId":15904241,"deviceCode":"00112233-4455-4677-8899-aabbccddeeff"}`),
		Authorities: map[string]provider.Authority{authorityID: {Protocol: NativeProtocol, Data: []byte(`{"token":"0123456789abcdef0123456789abcdef","userId":15904241,"appId":0}`)}},
		Nodes:       []provider.Node{{ID: node.ID, AuthorityID: node.AuthorityID, Protocol: node.Protocol, Host: node.Host, Port: node.Port, Name: node.Name, Group: node.Group, Model: node.Model, Eligible: true}},
	}
	if err := provider.ValidateSnapshot(providerSnapshot, ProviderID, now); err != nil {
		t.Fatal(err)
	}
	persistent, err := store.Update(t.Context(), func(candidate *state.PersistentState) error {
		if err := candidate.SetAccessToken("correct horse battery token"); err != nil {
			return err
		}
		authority, err := candidate.Identity()
		if err != nil {
			return err
		}
		credentials, _ := authority.Credentials(node.Route())
		node.Selector = credentials.Username
		refs, err := state.BuildSelectors([]state.Node{node}, authority)
		if err != nil {
			return err
		}
		candidate.ActiveSession = &state.RuntimeSnapshot{Generation: 1, CreatedAt: now, ExpiresAt: providerSnapshot.ExpiresAt, Providers: map[provider.ID]provider.Snapshot{ProviderID: providerSnapshot}, Nodes: []state.Node{node}, Selectors: refs}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := subscription.NewService(subscription.ServiceConfig{Store: store, SocksAddress: "127.0.0.1:10808"})
	if err != nil {
		t.Fatal(err)
	}
	originalURL, err := service.SubscriptionURL("http://console.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	reopened, err := storepkg.NewSQLiteStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close(t.Context())
	restored, err := subscription.NewService(subscription.ServiceConfig{Store: reopened, SocksAddress: "127.0.0.1:10808"})
	if err != nil {
		t.Fatal(err)
	}
	if url, err := restored.SubscriptionURL("http://console.example"); err != nil || url != originalURL {
		t.Fatal("subscription URL changed across restart")
	}
	loaded, err := reopened.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveSession == nil || !reflect.DeepEqual(loaded.ActiveSession.Providers[ProviderID], providerSnapshot) || loaded.ActiveSession.Nodes[0].Protocol != NativeProtocol {
		t.Fatal("QuickFox snapshot did not round trip")
	}
	before, _ := persistent.Identity()
	after, _ := loaded.Identity()
	if before.Password() != after.Password() {
		t.Fatal("installation credentials changed across restart")
	}
}
