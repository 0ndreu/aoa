// Command dpop-redis is a REFERENCE implementation (not a maintained package)
// of aoa.DPoPReplayCache backed by Redis, for multi-instance DPoP replay
// protection. Copy redisReplay into your own service and wire it via
// BearerOpts.DPoPReplay.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/0ndreu/aoa"
	"github.com/redis/go-redis/v9"
)

// redisReplay records each jti with SET NX PX: the first writer succeeds
// (not a replay); a subsequent SET NX for the same jti fails (a replay), until
// the key's TTL expires. The operation is atomic and shared across all RS instances.
type redisReplay struct {
	rdb    *redis.Client
	prefix string
}

func newRedisReplay(rdb *redis.Client) *redisReplay {
	return &redisReplay{rdb: rdb, prefix: "dpop:jti:"}
}

// Seen satisfies aoa.DPoPReplayCache.
func (c *redisReplay) Seen(ctx context.Context, jti string, exp time.Time) (bool, error) {
	ttl := time.Until(exp)
	if ttl <= 0 {
		ttl = time.Second // already-expired proofs still get a brief guard window
	}
	ok, err := c.rdb.SetNX(ctx, c.prefix+jti, 1, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis replay check: %w", err)
	}
	// ok == true  -> key did not exist -> first use (not a replay)
	// ok == false -> key existed       -> replay
	return !ok, nil
}

// compile-time check that the reference type satisfies the interface.
var _ aoa.DPoPReplayCache = (*redisReplay)(nil)

func main() {
	addr := "localhost:6379"
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer func() { _ = rdb.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis not reachable at %s: %v\n(start one with: docker run -p 6379:6379 redis)", addr, err)
	}

	cache := newRedisReplay(rdb)

	// demonstrate the contract: first use false, replay true.
	exp := time.Now().Add(time.Minute)
	first, _ := cache.Seen(ctx, "demo-jti", exp)
	replay, _ := cache.Seen(ctx, "demo-jti", exp)
	fmt.Printf("first use seen=%v (want false), replay seen=%v (want true)\n", first, replay)

	if first || !replay {
		log.Fatal("redisReplay contract violated")
	}

	// wire it into the middleware exactly like this:
	fmt.Println("wire via: aoa.BearerOpts{DPoP: aoa.DPoPRequired, DPoPReplay: cache, ...}")
}
