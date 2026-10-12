package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	domain "github.com/oshinop/chinadapter/internal/state"
)

func replacePersistentStateTx(ctx context.Context, tx *sql.Tx, state domain.PersistentState) error {
	if err := domain.ValidatePersistentState(state); err != nil {
		return fmt.Errorf("refusing invalid persistent state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM state_metadata WHERE id = 1"); err != nil {
		return corruptDatabase(err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO state_metadata (id, installation_id) VALUES (1, ?)", state.InstallationID); err != nil {
		return corruptDatabase(err)
	}
	if state.AccessTokenVerifier != nil {
		verifier := state.AccessTokenVerifier
		if _, err := tx.ExecContext(ctx, "INSERT INTO access_token_verifier (id, memory_kib, iterations, parallelism, salt, hash) VALUES (1, ?, ?, ?, ?, ?)", verifier.Parameters.MemoryKiB, verifier.Parameters.Iterations, verifier.Parameters.Parallelism, verifier.Salt, verifier.Hash); err != nil {
			return corruptDatabase(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO preferences (id, reveal_endpoints, refresh_policy) VALUES (1, ?, ?)", boolInt(state.Preferences.RevealEndpoints), state.Preferences.RefreshPolicy); err != nil {
		return corruptDatabase(err)
	}
	excluded := make([]string, 0, len(state.Preferences.ExcludedNodeIDs))
	for nodeID := range state.Preferences.ExcludedNodeIDs {
		excluded = append(excluded, nodeID)
	}
	sort.Strings(excluded)
	excludedStatement, err := tx.PrepareContext(ctx, "INSERT INTO excluded_node_ids (node_id, preference_id) VALUES (?, 1)")
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = excludedStatement.Close() }()
	for _, nodeID := range excluded {
		if _, err := excludedStatement.ExecContext(ctx, nodeID); err != nil {
			return corruptDatabase(err)
		}
	}
	if state.ActiveSession != nil {
		if err := insertActiveSessionTx(ctx, tx, state.ActiveSession); err != nil {
			return err
		}
	}
	return nil
}

func insertActiveSessionTx(ctx context.Context, tx *sql.Tx, snapshot *domain.RuntimeSnapshot) error {
	if snapshot == nil {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO active_session (id, generation, created_at_ns, expires_at_ns) VALUES (1, ?, ?, ?)", snapshot.Generation, nanos(snapshot.CreatedAt), nanos(snapshot.ExpiresAt)); err != nil {
		return corruptDatabase(err)
	}
	providerIDs := make([]string, 0, len(snapshot.Providers))
	for id := range snapshot.Providers {
		providerIDs = append(providerIDs, string(id))
	}
	sort.Strings(providerIDs)
	providerStatement, err := tx.PrepareContext(ctx, "INSERT INTO active_session_providers (provider_id, session_id, expires_at_ns, user_id, account_display, account_tier, subscription_active, subscription_ends_at_ns, refresh_state) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = providerStatement.Close() }()
	authorityStatement, err := tx.PrepareContext(ctx, "INSERT INTO active_session_authorities (provider_id, authority_id, protocol, authority) VALUES (?, ?, ?, ?)")
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = authorityStatement.Close() }()
	for _, rawID := range providerIDs {
		providerSnapshot := snapshot.Providers[provider.ID(rawID)]
		account := providerSnapshot.Account
		if _, err := providerStatement.ExecContext(ctx, rawID, nanos(providerSnapshot.ExpiresAt), account.UserID, account.Display, account.Tier, boolInt(account.SubscriptionActive), nullableNanos(account.SubscriptionEndsAt), providerSnapshot.RefreshState); err != nil {
			return corruptDatabase(err)
		}
		authorityIDs := make([]string, 0, len(providerSnapshot.Authorities))
		for authorityID := range providerSnapshot.Authorities {
			authorityIDs = append(authorityIDs, authorityID)
		}
		sort.Strings(authorityIDs)
		for _, authorityID := range authorityIDs {
			authority := providerSnapshot.Authorities[authorityID]
			if _, err := authorityStatement.ExecContext(ctx, rawID, authorityID, string(authority.Protocol), authority.Data); err != nil {
				return corruptDatabase(err)
			}
		}
	}
	nodeStatement, err := tx.PrepareContext(ctx, "INSERT INTO active_session_nodes (position, session_id, node_id, provider_id, protocol, authority_id, host, port, name, group_name, model, weight, auto, eligible, excluded, health, udp_health, tcp_rtt_ns, probed_at_ns) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = nodeStatement.Close() }()
	for index, node := range snapshot.Nodes {
		if _, err := nodeStatement.ExecContext(ctx, index, node.ID, string(node.Provider), string(node.Protocol), node.AuthorityID, node.Host, node.Port, node.Name, node.Group, node.Model, node.Weight, boolInt(node.Auto), boolInt(node.Eligible), boolInt(node.Excluded), string(node.Health), string(node.UDPHealth), int64(node.TCPRTT), nullableNanos(node.ProbedAt)); err != nil {
			return corruptDatabase(err)
		}
	}
	return nil
}

func loadPersistentStateTx(ctx context.Context, tx *sql.Tx) (domain.PersistentState, error) {
	var state domain.PersistentState
	if err := tx.QueryRowContext(ctx, "SELECT installation_id FROM state_metadata WHERE id = 1").Scan(&state.InstallationID); err != nil {
		return domain.PersistentState{}, corruptDatabase(err)
	}
	var memory, iterations, parallelism int64
	var salt, hash []byte
	err := tx.QueryRowContext(ctx, "SELECT memory_kib, iterations, parallelism, salt, hash FROM access_token_verifier WHERE id = 1").Scan(&memory, &iterations, &parallelism, &salt, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return domain.PersistentState{}, corruptDatabase(err)
	default:
		if memory < 0 || memory > int64(^uint32(0)) || iterations < 0 || iterations > int64(^uint32(0)) || parallelism < 0 || parallelism > int64(^uint8(0)) {
			return domain.PersistentState{}, corruptDatabase(errors.New("invalid verifier parameters"))
		}
		state.AccessTokenVerifier = &domain.AccessTokenVerifier{Parameters: domain.Argon2idParameters{MemoryKiB: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism)}, Salt: append([]byte(nil), salt...), Hash: append([]byte(nil), hash...)}
	}
	var reveal int64
	if err := tx.QueryRowContext(ctx, "SELECT reveal_endpoints, refresh_policy FROM preferences WHERE id = 1").Scan(&reveal, &state.Preferences.RefreshPolicy); err != nil {
		return domain.PersistentState{}, corruptDatabase(err)
	}
	value, err := intBool(reveal)
	if err != nil {
		return domain.PersistentState{}, corruptDatabase(err)
	}
	state.Preferences.RevealEndpoints = value
	state.Preferences.ExcludedNodeIDs = make(map[string]bool)
	excludedRows, err := tx.QueryContext(ctx, "SELECT node_id FROM excluded_node_ids WHERE preference_id = 1")
	if err != nil {
		return domain.PersistentState{}, corruptDatabase(err)
	}
	defer excludedRows.Close()
	for excludedRows.Next() {
		var nodeID string
		if err := excludedRows.Scan(&nodeID); err != nil {
			return domain.PersistentState{}, corruptDatabase(err)
		}
		if _, duplicate := state.Preferences.ExcludedNodeIDs[nodeID]; duplicate {
			return domain.PersistentState{}, corruptDatabase(errors.New("duplicate excluded node id"))
		}
		state.Preferences.ExcludedNodeIDs[nodeID] = true
	}
	if err := excludedRows.Close(); err != nil {
		return domain.PersistentState{}, corruptDatabase(err)
	}
	if err := excludedRows.Err(); err != nil {
		return domain.PersistentState{}, corruptDatabase(err)
	}
	active, err := loadActiveSessionTx(ctx, tx)
	if err != nil {
		return domain.PersistentState{}, err
	}
	state.ActiveSession = active
	if state.ActiveSession != nil {
		authority, err := state.Identity()
		if err != nil {
			return domain.PersistentState{}, corruptDatabase(err)
		}
		state.ActiveSession.Selectors, err = domain.BuildSelectors(state.ActiveSession.Nodes, authority)
		if err != nil {
			return domain.PersistentState{}, corruptDatabase(err)
		}
		state.ActiveSession.IndexNodes()
		for index := range state.ActiveSession.Nodes {
			credentials, _ := authority.Credentials(state.ActiveSession.Nodes[index].Route())
			state.ActiveSession.Nodes[index].Selector = credentials.Username
		}
	}
	if err := domain.ValidatePersistentState(state); err != nil {
		return domain.PersistentState{}, corruptDatabase(err)
	}
	return state, nil
}

func loadActiveSessionTx(ctx context.Context, tx *sql.Tx) (*domain.RuntimeSnapshot, error) {
	var snapshot domain.RuntimeSnapshot
	var created, expires int64
	err := tx.QueryRowContext(ctx, "SELECT generation, created_at_ns, expires_at_ns FROM active_session WHERE id = 1").Scan(&snapshot.Generation, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, corruptDatabase(err)
	}
	snapshot.CreatedAt = time.Unix(0, created).UTC()
	snapshot.ExpiresAt = time.Unix(0, expires).UTC()
	snapshot.Providers = make(map[provider.ID]provider.Snapshot)
	providerRows, err := tx.QueryContext(ctx, "SELECT provider_id, expires_at_ns, user_id, account_display, account_tier, subscription_active, subscription_ends_at_ns, refresh_state FROM active_session_providers WHERE session_id = 1 ORDER BY provider_id")
	if err != nil {
		return nil, corruptDatabase(err)
	}
	defer providerRows.Close()
	for providerRows.Next() {
		var rawID, userID, display, tier string
		var providerExpires, activeValue int64
		var subscriptionEnds sql.NullInt64
		var refreshState []byte
		if err := providerRows.Scan(&rawID, &providerExpires, &userID, &display, &tier, &activeValue, &subscriptionEnds, &refreshState); err != nil {
			return nil, corruptDatabase(err)
		}
		active, err := intBool(activeValue)
		if err != nil {
			return nil, corruptDatabase(err)
		}
		id := provider.ID(rawID)
		if _, duplicate := snapshot.Providers[id]; duplicate {
			return nil, corruptDatabase(errors.New("duplicate provider session"))
		}
		snapshot.Providers[id] = provider.Snapshot{
			Provider: id, ExpiresAt: time.Unix(0, providerExpires).UTC(), RefreshState: append([]byte(nil), refreshState...),
			Account:     provider.Account{UserID: userID, Display: display, Tier: tier, SubscriptionActive: active, SubscriptionEndsAt: timeFromNullable(subscriptionEnds)},
			Authorities: make(map[string]provider.Authority),
		}
	}
	if err := providerRows.Close(); err != nil {
		return nil, corruptDatabase(err)
	}
	if err := providerRows.Err(); err != nil {
		return nil, corruptDatabase(err)
	}
	authorityRows, err := tx.QueryContext(ctx, "SELECT provider_id, authority_id, protocol, authority FROM active_session_authorities ORDER BY provider_id, authority_id")
	if err != nil {
		return nil, corruptDatabase(err)
	}
	defer authorityRows.Close()
	for authorityRows.Next() {
		var rawID, authorityID, rawProtocol string
		var authorityData []byte
		if err := authorityRows.Scan(&rawID, &authorityID, &rawProtocol, &authorityData); err != nil {
			return nil, corruptDatabase(err)
		}
		id := provider.ID(rawID)
		providerSnapshot, available := snapshot.Providers[id]
		if !available {
			return nil, corruptDatabase(errors.New("authority references absent provider"))
		}
		if _, duplicate := providerSnapshot.Authorities[authorityID]; duplicate {
			return nil, corruptDatabase(errors.New("duplicate provider authority"))
		}
		providerSnapshot.Authorities[authorityID] = provider.Authority{Protocol: provider.Protocol(rawProtocol), Data: append([]byte(nil), authorityData...)}
		snapshot.Providers[id] = providerSnapshot
	}
	if err := authorityRows.Close(); err != nil {
		return nil, corruptDatabase(err)
	}
	if err := authorityRows.Err(); err != nil {
		return nil, corruptDatabase(err)
	}
	nodeRows, err := tx.QueryContext(ctx, "SELECT node_id, provider_id, protocol, authority_id, host, port, name, group_name, model, weight, auto, eligible, excluded, health, udp_health, tcp_rtt_ns, probed_at_ns FROM active_session_nodes WHERE session_id = 1 ORDER BY position")
	if err != nil {
		return nil, corruptDatabase(err)
	}
	defer nodeRows.Close()
	for nodeRows.Next() {
		var node domain.Node
		var rawProvider, rawProtocol string
		var port, auto, eligible, excluded, rtt int64
		var probed sql.NullInt64
		var health, udp string
		if err := nodeRows.Scan(&node.ID, &rawProvider, &rawProtocol, &node.AuthorityID, &node.Host, &port, &node.Name, &node.Group, &node.Model, &node.Weight, &auto, &eligible, &excluded, &health, &udp, &rtt, &probed); err != nil {
			return nil, corruptDatabase(err)
		}
		if port < 0 || port > 65535 {
			return nil, corruptDatabase(errors.New("invalid active node port"))
		}
		var conversionErr error
		if node.Auto, conversionErr = intBool(auto); conversionErr != nil {
			return nil, corruptDatabase(conversionErr)
		}
		if node.Eligible, conversionErr = intBool(eligible); conversionErr != nil {
			return nil, corruptDatabase(conversionErr)
		}
		if node.Excluded, conversionErr = intBool(excluded); conversionErr != nil {
			return nil, corruptDatabase(conversionErr)
		}
		node.Provider, node.Protocol = provider.ID(rawProvider), provider.Protocol(rawProtocol)
		node.Port, node.Health, node.UDPHealth, node.TCPRTT, node.ProbedAt = uint16(port), domain.NodeHealth(health), domain.UDPHealth(udp), time.Duration(rtt), timeFromNullable(probed)
		snapshot.Nodes = append(snapshot.Nodes, node)
		providerSnapshot, available := snapshot.Providers[node.Provider]
		if !available {
			return nil, corruptDatabase(errors.New("node references absent provider"))
		}
		providerSnapshot.Nodes = append(providerSnapshot.Nodes, provider.Node{
			ID: node.ID, AuthorityID: node.AuthorityID, Protocol: node.Protocol, Host: node.Host, Port: node.Port,
			Name: node.Name, Group: node.Group, Model: node.Model, Weight: node.Weight, Auto: node.Auto, Eligible: node.Eligible,
		})
		snapshot.Providers[node.Provider] = providerSnapshot
	}
	if err := nodeRows.Close(); err != nil {
		return nil, corruptDatabase(err)
	}
	if err := nodeRows.Err(); err != nil {
		return nil, corruptDatabase(err)
	}
	return &snapshot, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func intBool(value int64) (bool, error) {
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("invalid boolean value")
	}
}

func nanos(value time.Time) int64 { return value.UTC().UnixNano() }

func nullableNanos(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return nanos(value)
}

func timeFromNullable(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(0, value.Int64).UTC()
}
