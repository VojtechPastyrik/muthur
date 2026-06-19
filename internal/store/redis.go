package store

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a Store backed by Redis (or a Redis-compatible server such as
// DragonflyDB). State is shared across muthur-central replicas and survives
// restarts, which is what makes cross-replica dedup, a warm analysis cache, and
// durable feedback possible.
type Redis struct {
	client *redis.Client
	prefix string
}

// NewRedis dials the server at url (a redis:// or rediss:// connection string)
// and verifies connectivity with PING. All keys are namespaced with prefix to
// keep muthur state isolated from anything else sharing the instance.
func NewRedis(ctx context.Context, url, prefix string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opt)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Redis{client: client, prefix: prefix}, nil
}

func (r *Redis) k(key string) string { return r.prefix + key }

func (r *Redis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	val, err := r.client.Get(ctx, r.k(key)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("redis get: %w", err)
	}
	return val, true, nil
}

func (r *Redis) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	if err := r.client.Set(ctx, r.k(key), val, ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	return nil
}

func (r *Redis) SetNX(ctx context.Context, key string, val []byte, ttl time.Duration) (bool, error) {
	set, err := r.client.SetNX(ctx, r.k(key), val, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis setnx: %w", err)
	}
	return set, nil
}

func (r *Redis) Delete(ctx context.Context, key string) error {
	if err := r.client.Del(ctx, r.k(key)).Err(); err != nil {
		return fmt.Errorf("redis del: %w", err)
	}
	return nil
}

func (r *Redis) ListByPrefix(ctx context.Context, prefix string) ([][]byte, error) {
	pattern := r.k(prefix) + "*"
	var keys []string
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("redis scan: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	vals, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis mget: %w", err)
	}
	out := make([][]byte, 0, len(vals))
	for _, v := range vals {
		s, ok := v.(string)
		if !ok {
			continue // key expired between SCAN and MGET
		}
		out = append(out, []byte(s))
	}
	return out, nil
}

func (r *Redis) Kind() string { return "redis" }

func (r *Redis) Close() error { return r.client.Close() }
