// Package tsnetid resolves caller identity from a tsnet-embedded listener.
//
// This is D2's identity source: the tailnet tells us which node a request came
// from, in-process via tsnet's LocalClient WhoIs (the D6 spike shelled out to
// `tailscale whois`; production does not).
package tsnetid

import (
	"context"
	"fmt"

	"tailscale.com/client/local"

	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Resolver resolves a peer address to a tailnet identity via WhoIs.
type Resolver struct {
	client *local.Client
}

// New builds a Resolver over a tsnet server's LocalClient.
func New(client *local.Client) *Resolver { return &Resolver{client: client} }

// Resolve implements server.IdentityResolver.
//
// NodeID carries the node's STABLE id, which survives renames and is what
// machine records are keyed on; NodeName is carried for human-readable audit
// only and is never used for an authorization decision.
func (r *Resolver) Resolve(ctx context.Context, remoteAddr string) (store.Identity, error) {
	if r.client == nil {
		return store.Identity{}, fmt.Errorf("tsnetid: no local client configured")
	}
	who, err := r.client.WhoIs(ctx, remoteAddr)
	if err != nil {
		return store.Identity{}, fmt.Errorf("tsnetid: whois %s: %w", remoteAddr, err)
	}
	if who == nil || who.Node == nil {
		return store.Identity{}, fmt.Errorf("tsnetid: whois %s: no node identity", remoteAddr)
	}
	id := store.Identity{
		NodeID:   string(who.Node.StableID),
		NodeName: who.Node.ComputedName,
	}
	if id.NodeName == "" {
		id.NodeName = who.Node.Name
	}
	if who.UserProfile != nil {
		id.UserID = who.UserProfile.LoginName
	}
	if id.NodeID == "" {
		return store.Identity{}, fmt.Errorf("tsnetid: whois %s: empty stable node id", remoteAddr)
	}
	return id, nil
}
