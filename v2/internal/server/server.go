// Package server exposes the store over HTTP: a small JSON API plus a
// single-page dashboard. It is intentionally dependency-free (net/http +
// embedded HTML) so `tyrion serve` works from the single binary.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/0xyoussef404/tyrion/internal/store"
)

// Server serves projects under a base directory.
type Server struct {
	base string
}

// New creates a server rooted at base (the directory holding project folders).
func New(base string) *Server { return &Server{base: base} }

// Listen starts the HTTP server (blocking).
func (s *Server) Listen(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/kinds", s.handleKinds)
	mux.HandleFunc("/api/records", s.handleRecords)
	fmt.Printf("Tyrion dashboard on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) projectDir(name string) string {
	return filepath.Join(s.base, name, ".tyrion")
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(s.base)
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.base, e.Name(), ".tyrion")); err == nil {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	writeJSON(w, names)
}

func (s *Server) handleKinds(w http.ResponseWriter, r *http.Request) {
	proj := r.URL.Query().Get("project")
	st, err := store.Open(s.projectDir(proj))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := map[string]int{}
	for _, k := range st.Kinds() {
		out[k] = st.Count(k)
	}
	writeJSON(w, out)
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st, err := store.Open(s.projectDir(q.Get("project")))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	kind := q.Get("kind")
	var recs []map[string]any
	if expr := q.Get("q"); expr != "" {
		recs, err = st.Query(kind, expr)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	} else {
		recs = st.All(kind)
	}
	if len(recs) > 1000 {
		recs = recs[:1000]
	}
	writeJSON(w, recs)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

const dashboardHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tyrion Dashboard</title>
<style>
 :root[data-theme="dark"]{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--accent:#58a6ff;--hover:#1f2630}
 :root[data-theme="light"]{--bg:#ffffff;--panel:#f6f8fa;--border:#d0d7de;--fg:#1f2328;--accent:#0969da;--hover:#eef1f4}
 *{box-sizing:border-box}
 body{font-family:ui-monospace,Menlo,Consolas,monospace;background:var(--bg);color:var(--fg);margin:0;transition:background .2s,color .2s}
 header{padding:12px 18px;background:var(--panel);border-bottom:1px solid var(--border);font-weight:bold;color:var(--accent);display:flex;align-items:center;justify-content:space-between}
 header .t{letter-spacing:.5px}
 #theme{cursor:pointer;background:var(--bg);color:var(--fg);border:1px solid var(--border);border-radius:20px;padding:5px 12px;font-family:inherit;font-size:12px}
 .wrap{display:flex;height:calc(100vh - 49px)}
 .side{width:250px;border-right:1px solid var(--border);padding:12px;overflow:auto}
 .main{flex:1;padding:12px;overflow:auto}
 select,input{background:var(--bg);color:var(--fg);border:1px solid var(--border);padding:7px;width:100%;margin-bottom:8px;border-radius:6px;font-family:inherit}
 .kind{padding:6px 9px;cursor:pointer;border-radius:6px;font-size:13px}
 .kind:hover{background:var(--hover)}
 .kind b{color:var(--accent);float:right}
 table{border-collapse:collapse;width:100%;font-size:12px}
 td,th{border:1px solid var(--border);padding:5px 8px;text-align:left;vertical-align:top}
 th{background:var(--panel);position:sticky;top:0}
 tr:hover td{background:var(--hover)}
 .hint{opacity:.6;font-size:12px}
</style></head><body>
<header><span class="t">TYRION · Recon Intelligence Dashboard</span>
 <button id="theme" onclick="toggleTheme()">◑ theme</button></header>
<div class="wrap">
 <div class="side">
  <select id="proj"></select>
  <input id="q" placeholder='query e.g. score>50 and template contains api'>
  <div class="hint">Enter to re-run query</div>
  <div id="kinds" style="margin-top:10px"></div>
 </div>
 <div class="main"><div id="table" class="hint">Select a project and a kind on the left.</div></div>
</div>
<script>
let P=document.getElementById('proj'),K=document.getElementById('kinds'),T=document.getElementById('table'),Q=document.getElementById('q'),cur='';
function setTheme(t){document.documentElement.setAttribute('data-theme',t);localStorage.setItem('tyrion-theme',t)}
function toggleTheme(){setTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark')}
setTheme(localStorage.getItem('tyrion-theme')||'dark');
async function j(u){return (await fetch(u)).json()}
async function loadProjects(){let ps=await j('/api/projects');P.innerHTML=ps.map(p=>'<option>'+p+'</option>').join('');if(ps.length)loadKinds()}
async function loadKinds(){let k=await j('/api/kinds?project='+encodeURIComponent(P.value));K.innerHTML=Object.entries(k).sort().map(([n,c])=>'<div class="kind" onclick="show(\''+n+'\')">'+n+' <b>'+c+'</b></div>').join('')}
async function show(kind){cur=kind;let u='/api/records?project='+encodeURIComponent(P.value)+'&kind='+kind;if(Q.value)u+='&q='+encodeURIComponent(Q.value);let rows=await j(u);if(!rows||!rows.length){T.innerHTML='<span class="hint">no records</span>';return}
 let cols=[...new Set(rows.flatMap(r=>Object.keys(r)))].slice(0,12);
 T.innerHTML='<table><tr>'+cols.map(c=>'<th>'+c+'</th>').join('')+'</tr>'+rows.map(r=>'<tr>'+cols.map(c=>'<td>'+fmt(r[c])+'</td>').join('')+'</tr>').join('')+'</table>'}
function fmt(v){if(v==null)return '';if(Array.isArray(v))return v.join(', ');return (''+v).slice(0,240).replace(/</g,'&lt;')}
P.onchange=loadKinds;Q.onkeydown=e=>{if(e.key==='Enter'&&cur)show(cur)};
loadProjects();
</script></body></html>`
