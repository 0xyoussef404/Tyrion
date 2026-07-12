package store

import (
	"testing"

	"github.com/0xyoussef404/tyrion/internal/model"
)

func TestPutQueryFlushReload(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Put(&model.Endpoint{ID: "a", Template: "x.com/api/users/{integer}", Score: 80})
	st.Put(&model.Endpoint{ID: "b", Template: "x.com/blog/post", Score: 10})
	st.Put(&model.Endpoint{ID: "c", Template: "x.com/api/admin", Score: 60})

	got, err := st.Query(model.KindEndpoint, "score>50 and template contains api")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("query got %d, want 2", len(got))
	}

	in, _ := st.Query(model.KindEndpoint, "score in [10, 80]")
	if len(in) != 2 {
		t.Fatalf("in-query got %d, want 2", len(in))
	}

	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Count(model.KindEndpoint) != 3 {
		t.Fatalf("reloaded count %d, want 3", st2.Count(model.KindEndpoint))
	}
}

func TestQueryOr(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	st.Put(&model.Asset{ID: "1", Host: "a.x.com", Alive: true})
	st.Put(&model.Asset{ID: "2", Host: "b.x.com", Alive: false})
	got, err := st.Query(model.KindAsset, "alive=true or host contains b.x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("or-query got %d, want 2", len(got))
	}
}
