package subscription

import (
	"os"
	"testing"

	"github.com/oshinop/chinadapter/internal/store"
)

func TestSubscriptionMetadataHasNoFetchProof(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(t.Context())
	if _, err := store.LoadOrCreate(t.Context()); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{Store: store, SocksAddress: "127.0.0.1:10808"})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := service.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Active || metadata.NodeCount != 0 {
		t.Fatalf("unexpected inactive metadata: %#v", metadata)
	}
}
