package engine

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDAGOrderAndConcurrency(t *testing.T) {
	var mu sync.Mutex
	order := []string{}
	mk := func(id string) TaskFunc {
		return func(ctx context.Context) error {
			mu.Lock()
			order = append(order, id)
			mu.Unlock()
			return nil
		}
	}
	tasks := []Task{
		{ID: "a", Run: mk("a")},
		{ID: "b", DependsOn: []string{"a"}, Run: mk("b")},
		{ID: "c", DependsOn: []string{"a"}, Run: mk("c")},
		{ID: "d", DependsOn: []string{"b", "c"}, Run: mk("d")},
	}
	eng := New(4, time.Second)
	res, err := eng.Run(context.Background(), tasks)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 4 {
		t.Fatalf("got %d results", len(res))
	}
	pos := map[string]int{}
	for i, id := range order {
		pos[id] = i
	}
	if !(pos["a"] < pos["b"] && pos["a"] < pos["c"] && pos["b"] < pos["d"] && pos["c"] < pos["d"]) {
		t.Fatalf("bad topo order: %v", order)
	}
}

func TestDAGSkipsOnFailure(t *testing.T) {
	tasks := []Task{
		{ID: "a", Run: func(ctx context.Context) error { return context.Canceled }},
		{ID: "b", DependsOn: []string{"a"}, Run: func(ctx context.Context) error { return nil }},
	}
	eng := New(2, time.Second)
	res, _ := eng.Run(context.Background(), tasks)
	byID := map[string]Status{}
	for _, r := range res {
		byID[r.ID] = r.Status
	}
	if byID["a"] != StatusFailed {
		t.Errorf("a status=%v want failed", byID["a"])
	}
	if byID["b"] != StatusSkipped {
		t.Errorf("b status=%v want skipped", byID["b"])
	}
}

func TestDAGCycleDetection(t *testing.T) {
	tasks := []Task{
		{ID: "a", DependsOn: []string{"b"}, Run: func(context.Context) error { return nil }},
		{ID: "b", DependsOn: []string{"a"}, Run: func(context.Context) error { return nil }},
	}
	if _, err := New(2, time.Second).Run(context.Background(), tasks); err == nil {
		t.Fatal("expected cycle error")
	}
}
