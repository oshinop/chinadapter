package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/web"
)

// Probe measures only one bounded direct TCP connection to the selected
// upstream node. It never starts SOCKS authentication or sends a destination.
func (r *Runtime) Probe(ctx context.Context, nodeID string) (web.ProbeResult, error) {
	if r == nil {
		return web.ProbeResult{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.ProbeResult{}, errRuntimeStopped
	}
	current := r.manager.Current()
	if !state.SessionUsable(current, r.now()) {
		return web.ProbeResult{}, &problemError{cause: provider.ErrNoSession, code: "node_snapshot_unavailable", status: http.StatusConflict}
	}
	node, found := current.NodeByID(nodeID)
	if !found {
		return web.ProbeResult{}, &problemError{cause: errors.New("node not found"), code: "node_not_found", status: http.StatusNotFound}
	}
	if !node.TunnelEligible() {
		return web.ProbeResult{}, &problemError{cause: errors.New("node ineligible"), code: "node_ineligible", status: http.StatusConflict}
	}
	target := probeTarget{id: node.ID, selector: node.Selector, provider: string(node.Provider), host: node.Host, port: node.Port}
	select {
	case r.probeSlots <- struct{}{}:
		defer func() { <-r.probeSlots }()
	default:
		return web.ProbeResult{}, &problemError{cause: ErrProbeBusy, code: "probe_busy", status: http.StatusTooManyRequests}
	}

	probeCtx, cancel := context.WithTimeout(ctx, r.probeTimeout)
	defer cancel()
	started := r.now()
	connection, dialErr := r.dial(probeCtx, "tcp", net.JoinHostPort(node.Host, strconv.Itoa(int(node.Port))))
	finished := r.now().UTC()
	latency := finished.Sub(started)
	if latency < 0 {
		latency = 0
	}
	if connection != nil {
		_ = connection.Close()
	}
	health := state.NodeHealthHealthy
	if dialErr != nil {
		health = state.NodeHealthUnhealthy
	}
	result := web.ProbeResult{NodeID: nodeID, Health: string(health), ProbedAt: finished}
	if latency > 0 {
		result.TCPLatencyMS = int(latency.Round(time.Millisecond) / time.Millisecond)
	}

	r.mutations.Lock()
	if !r.alive.Load() {
		r.mutations.Unlock()
		return web.ProbeResult{}, errRuntimeStopped
	}
	latest := r.manager.Current()
	if !target.matches(latest) || !state.SessionUsable(latest, r.now()) {
		r.mutations.Unlock()
		return result, &problemError{cause: ErrStaleProbe, code: "stale_probe", status: http.StatusConflict}
	}
	updated, updateErr := r.updateProbe(latest, nodeID, health, latency, finished)
	r.mutations.Unlock()
	if updateErr != nil {
		return result, updateErr
	}
	if updated != nil {
		r.publish("probe", probeEvent{NodeID: nodeID, Health: string(health), TCPLatencyMS: result.TCPLatencyMS, ProbedAt: finished})
		r.publishState()
	}
	if dialErr != nil {
		return result, tcpProbeProblem(dialErr, probeCtx.Err())
	}
	return result, nil
}

type probeTarget struct {
	id       string
	selector string
	provider string
	host     string
	port     uint16
}

func (target probeTarget) matches(snapshot *state.RuntimeSnapshot) bool {
	if snapshot == nil {
		return false
	}
	node, found := snapshot.NodeByID(target.id)
	return found && node.ID == target.id && node.Selector == target.selector && string(node.Provider) == target.provider && node.Host == target.host && node.Port == target.port
}

func (r *Runtime) updateProbe(current *state.RuntimeSnapshot, nodeID string, health state.NodeHealth, latency time.Duration, observed time.Time) (*state.RuntimeSnapshot, error) {
	if !state.SessionUsable(current, observed) {
		return nil, errors.New("app: no active node snapshot")
	}
	next := current.Clone()
	next.Generation++
	for index := range next.Nodes {
		if next.Nodes[index].ID == nodeID {
			next.Nodes[index].Health = health
			next.Nodes[index].TCPRTT = latency
			next.Nodes[index].ProbedAt = observed
			break
		}
	}
	if err := r.manager.Commit(next); err != nil {
		return nil, err
	}
	return next, nil
}
