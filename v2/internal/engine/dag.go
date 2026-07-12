// Package engine is the DAG scheduler. Tasks declare dependencies; independent
// tasks run concurrently up to a worker limit; each task has its own timeout and
// an optional cache key so unchanged work is skipped (incremental recon).
package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// TaskFunc is the unit of work. It receives the shared context and returns an
// error; a non-nil error marks the task failed (dependents are skipped).
type TaskFunc func(ctx context.Context) error

// Task is a node in the DAG.
type Task struct {
	ID        string
	DependsOn []string
	Timeout   time.Duration // 0 = inherit engine default
	CacheKey  string        // if set and already cached, task is skipped
	Run       TaskFunc
}

// Status of a finished task.
type Status int

const (
	StatusOK Status = iota
	StatusFailed
	StatusSkipped // dependency failed
	StatusCached
	StatusTimeout
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusFailed:
		return "failed"
	case StatusSkipped:
		return "skipped"
	case StatusCached:
		return "cached"
	case StatusTimeout:
		return "timeout"
	}
	return "?"
}

// TaskResult reports one task's outcome.
type TaskResult struct {
	ID       string
	Status   Status
	Err      error
	Duration time.Duration
}

// Engine runs a DAG of tasks.
type Engine struct {
	Concurrency    int
	DefaultTimeout time.Duration
	Cache          Cache
	OnStart        func(id string)
	OnFinish       func(TaskResult)

	mu      sync.Mutex
	results map[string]TaskResult
}

// Cache decides whether a task's work can be skipped.
type Cache interface {
	Has(key string) bool
	Set(key string)
}

// New returns an engine with sane defaults.
func New(concurrency int, defaultTimeout time.Duration) *Engine {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Engine{
		Concurrency:    concurrency,
		DefaultTimeout: defaultTimeout,
		results:        map[string]TaskResult{},
	}
}

// Run topologically schedules tasks, running independent ones in parallel.
func (e *Engine) Run(ctx context.Context, tasks []Task) ([]TaskResult, error) {
	index := map[string]Task{}
	for _, t := range tasks {
		if _, dup := index[t.ID]; dup {
			return nil, fmt.Errorf("duplicate task id: %s", t.ID)
		}
		index[t.ID] = t
	}
	if err := detectCycle(index); err != nil {
		return nil, err
	}

	remaining := map[string]bool{}
	for id := range index {
		remaining[id] = true
	}
	done := map[string]Status{} // completed task -> status
	sem := make(chan struct{}, e.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for len(remaining) > 0 {
		// Find tasks whose dependencies are all complete.
		ready := []string{}
		mu.Lock()
		for id := range remaining {
			t := index[id]
			ok := true
			for _, dep := range t.DependsOn {
				if _, fin := done[dep]; !fin {
					ok = false
					break
				}
			}
			if ok {
				ready = append(ready, id)
			}
		}
		mu.Unlock()

		if len(ready) == 0 {
			// Nothing ready but tasks remain: dependencies failed/skipped upstream.
			break
		}
		sort.Strings(ready)

		for _, id := range ready {
			t := index[id]
			mu.Lock()
			delete(remaining, id)
			// If any dependency failed/skipped/timed-out, skip this task.
			skip := false
			for _, dep := range t.DependsOn {
				if st := done[dep]; st == StatusFailed || st == StatusSkipped || st == StatusTimeout {
					skip = true
					break
				}
			}
			mu.Unlock()

			if skip {
				res := TaskResult{ID: id, Status: StatusSkipped}
				e.record(res)
				mu.Lock()
				done[id] = StatusSkipped
				mu.Unlock()
				continue
			}
			if t.CacheKey != "" && e.Cache != nil && e.Cache.Has(t.CacheKey) {
				res := TaskResult{ID: id, Status: StatusCached}
				e.record(res)
				mu.Lock()
				done[id] = StatusCached
				mu.Unlock()
				continue
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(t Task) {
				defer wg.Done()
				defer func() { <-sem }()
				res := e.runOne(ctx, t)
				e.record(res)
				mu.Lock()
				done[t.ID] = res.Status
				mu.Unlock()
			}(t)
		}
		wg.Wait() // wait for this wave before scheduling the next
	}

	// Any tasks never scheduled are marked skipped.
	for id := range remaining {
		res := TaskResult{ID: id, Status: StatusSkipped}
		e.record(res)
	}

	out := make([]TaskResult, 0, len(e.results))
	for _, r := range e.results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (e *Engine) runOne(ctx context.Context, t Task) TaskResult {
	if e.OnStart != nil {
		e.OnStart(t.ID)
	}
	to := t.Timeout
	if to <= 0 {
		to = e.DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	start := time.Now()
	errc := make(chan error, 1)
	go func() { errc <- t.Run(cctx) }()

	var res TaskResult
	res.ID = t.ID
	select {
	case err := <-errc:
		res.Duration = time.Since(start)
		res.Err = err
		if err != nil {
			res.Status = StatusFailed
		} else {
			res.Status = StatusOK
			if t.CacheKey != "" && e.Cache != nil {
				e.Cache.Set(t.CacheKey)
			}
		}
	case <-cctx.Done():
		res.Duration = time.Since(start)
		res.Status = StatusTimeout
		res.Err = cctx.Err()
	}
	return res
}

func (e *Engine) record(r TaskResult) {
	e.mu.Lock()
	e.results[r.ID] = r
	e.mu.Unlock()
	if e.OnFinish != nil {
		e.OnFinish(r)
	}
}

func detectCycle(index map[string]Task) error {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var visit func(string, []string) error
	visit = func(id string, path []string) error {
		color[id] = gray
		for _, dep := range index[id].DependsOn {
			if _, ok := index[dep]; !ok {
				return fmt.Errorf("task %q depends on unknown task %q", id, dep)
			}
			switch color[dep] {
			case gray:
				return fmt.Errorf("dependency cycle: %v -> %s", append(path, id), dep)
			case white:
				if err := visit(dep, append(path, id)); err != nil {
					return err
				}
			}
		}
		color[id] = black
		return nil
	}
	ids := make([]string, 0, len(index))
	for id := range index {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if color[id] == white {
			if err := visit(id, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
