#!/bin/bash

# ============================================
#  Tyrion404 - Advanced Reconnaissance Tool
#  Author: Tyrion
#  Description: Automated recon for bug bounty & security assessments
# ============================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Feature flags
ENABLE_DIRSEARCH=false
ENABLE_SECRETFINDER=false
ENABLE_TAKEOVER=false
ENABLE_GF=false
ENABLE_PORT_SCAN=false
ENABLE_PARALLEL=false
ENABLE_MOREURLS=false
ENABLE_GREP=false
ENABLE_GOWITNESS=false
ENABLE_BRUTEFORCE=false
ENABLE_JSDEEP=false
ENABLE_ASN=false
ENABLE_VHOST=false
ENABLE_ARJUN=false
ENABLE_NUCLEI_FULL=false
ENABLE_WAF=false
ENABLE_VERIFY=false
ENABLE_CORS=false
ENABLE_METHODS=false
ENABLE_BYPASS=false
ENABLE_SWAGGER=false
ENABLE_VALIDATE=false
ENABLE_APIDISC=false
ENABLE_SITEMAP=false
CUSTOM_WORDLIST=""

TOTAL_STEPS=0
CURRENT_STEP=0
CURRENT_TOOL_PID=""
CURRENT_TOOL_NAME=""
SCAN_PAUSED=false
CHECKPOINT_FILE=""
LAST_COMPLETED_KEY=""
CURRENT_RUNNING_KEY=""

# ─────────────────────────────────────────────────────────────
# Checkpoint
# ─────────────────────────────────────────────────────────────
checkpoint_save() {
    [ -n "$CHECKPOINT_FILE" ] && { grep -qxF "${1}=done" "$CHECKPOINT_FILE" 2>/dev/null || echo "${1}=done" >> "$CHECKPOINT_FILE"; }
}
checkpoint_done() {
    local r=1; [ -f "$CHECKPOINT_FILE" ] && grep -qxF "$1=done" "$CHECKPOINT_FILE" 2>/dev/null && r=0; return $r
}
checkpoint_init() { CHECKPOINT_FILE=".checkpoint"; }

# ─────────────────────────────────────────────────────────────
# Interrupt / Exit
# ─────────────────────────────────────────────────────────────
handle_interrupt() {
    echo ""
    stop_heartbeat
    [ -n "$CURRENT_TOOL_PID" ] && { kill -- -${CURRENT_TOOL_PID} 2>/dev/null; wait "$CURRENT_TOOL_PID" 2>/dev/null; CURRENT_TOOL_PID=""; }
    [ -n "$LAST_COMPLETED_KEY" ] && { checkpoint_save "$LAST_COMPLETED_KEY"; print_warning "Interrupted — checkpoint saved: $LAST_COMPLETED_KEY"; } || print_warning "Interrupted — no completed steps saved"
    print_info "Run same command again to resume"
    stty sane 2>/dev/null; exit 1
}
handle_exit() { stty sane 2>/dev/null; }
start_heartbeat() { :; }
stop_heartbeat() {
    [ -n "$HEARTBEAT_PID" ] && { kill "$HEARTBEAT_PID" 2>/dev/null; wait "$HEARTBEAT_PID" 2>/dev/null; HEARTBEAT_PID=""; }
}

# ─────────────────────────────────────────────────────────────
# Step runner
# ─────────────────────────────────────────────────────────────
run_step() {
    local label="$1" key="$2" func="$3"
    if checkpoint_done "$key"; then
        CURRENT_STEP=$((CURRENT_STEP + 1))
        print_info "⏭  Skipping: $label (already completed)"
        return
    fi
    print_step "$label"
    CURRENT_RUNNING_KEY="$key"
    $func
    LAST_COMPLETED_KEY="$key"
    checkpoint_save "$key"
    CURRENT_RUNNING_KEY=""
}

calculate_total_steps() {
    # Base: enum, dns, live, url, param, js, + 7 always-on intelligence blocks
    TOTAL_STEPS=14
    [ "$ENABLE_BRUTEFORCE" = true ]   && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_GOWITNESS" = true ]    && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_PORT_SCAN" = true ]    && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_TAKEOVER" = true ]     && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_GF" = true ]           && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_GREP" = true ]         && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_DIRSEARCH" = true ]    && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_SECRETFINDER" = true ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_MOREURLS" = true ]     && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_JSDEEP" = true ]       && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_ASN" = true ]          && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_VHOST" = true ]        && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_ARJUN" = true ]        && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_NUCLEI_FULL" = true ]  && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_WAF" = true ]          && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_VERIFY" = true ]       && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_CORS" = true ]         && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_METHODS" = true ]      && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_BYPASS" = true ]       && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_SWAGGER" = true ]      && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_VALIDATE" = true ]     && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_APIDISC" = true ]      && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_SITEMAP" = true ]      && TOTAL_STEPS=$((TOTAL_STEPS + 1))
}

# ─────────────────────────────────────────────────────────────
# Print
# ─────────────────────────────────────────────────────────────
show_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}  ████████╗██╗   ██╗██████╗ ██╗ ██████╗ ███╗   ██╗ ██╗  ██╗ ██████╗  ██╗  ██╗${NC}"
    echo -e "${CYAN}${BOLD}     ██╔══╝╚██╗ ██╔╝██╔══██╗██║██╔═══██╗████╗  ██║ ██║  ██║██╔═████╗ ██║  ██║${NC}"
    echo -e "${CYAN}${BOLD}     ██║    ╚████╔╝ ██████╔╝██║██║   ██║██╔██╗ ██║ ███████║██║██╔██║ ███████║${NC}"
    echo -e "${CYAN}${BOLD}     ██║     ╚██╔╝  ██╔══██╗██║██║   ██║██║╚██╗██║ ╚════██║████╔╝██║ ╚════██║${NC}"
    echo -e "${CYAN}${BOLD}     ██║      ██║   ██║  ██║██║╚██████╔╝██║ ╚████║      ██║╚██████╔╝      ██║${NC}"
    echo -e "${CYAN}${BOLD}     ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝ ╚═════╝       ╚═╝${NC}"
    echo ""
    echo -e "${DIM}${CYAN}                       by Tyrion404  ·  Advanced Recon Automation${NC}"
    echo -e "${DIM}${CYAN}  ─────────────────────────────────────────────────────────────────────────────${NC}"
    echo ""
}

print_success() { echo -e "  ${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "  ${RED}[✗]${NC} $1"; }
print_warning() { echo -e "  ${YELLOW}[!]${NC} $1"; }
print_info()    { echo -e "  ${CYAN}[*]${NC} $1"; }

print_step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo -e "  ${BOLD}${BLUE}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${BLUE}│${NC}  ${BOLD}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${BOLD}${1}${NC}"
    echo -e "  ${BOLD}${BLUE}│${NC}  ${DIM}Started: $(date '+%H:%M:%S')${NC}"
    echo -e "  ${BOLD}${BLUE}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "  ${BOLD}${MAGENTA}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${MAGENTA}│${NC}  ${BOLD}${1}${NC}"
    echo -e "  ${BOLD}${MAGENTA}│${NC}  ${DIM}$(date '+%H:%M:%S')${NC}"
    echo -e "  ${BOLD}${MAGENTA}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
}

print_skip_hint() { echo -e "  ${DIM}${YELLOW}↵  ENTER to skip  |  P to pause${NC}"; }

# ─────────────────────────────────────────────────────────────
# run_with_skip — ENTER to skip, P to pause, C to continue
# ─────────────────────────────────────────────────────────────
run_with_skip() {
    local tool_name="$1"; shift
    local cmd="$@"
    CURRENT_TOOL_NAME="$tool_name"
    SCAN_PAUSED=false

    setsid bash -c "$cmd" &
    CURRENT_TOOL_PID=$!
    local tool_pgid=$CURRENT_TOOL_PID

    while kill -0 "$CURRENT_TOOL_PID" 2>/dev/null; do
        IFS= read -t 0.5 -r -n 1 _key 2>/dev/null
        local rc=$?
        if [ $rc -eq 0 ]; then
            if [[ "$_key" == "" || "$_key" == $'\n' || "$_key" == $'\r' ]]; then
                [ "$SCAN_PAUSED" = true ] && kill -SIGCONT -- -${tool_pgid} 2>/dev/null && SCAN_PAUSED=false
                kill -- -${tool_pgid} 2>/dev/null; wait "$CURRENT_TOOL_PID" 2>/dev/null
                print_warning "Skipped: $CURRENT_TOOL_NAME — partial results saved"
                CURRENT_TOOL_PID=""; CURRENT_TOOL_NAME=""; SCAN_PAUSED=false; return 2
            elif [[ "$_key" == "p" || "$_key" == "P" ]]; then
                [ "$SCAN_PAUSED" = false ] && { kill -SIGSTOP -- -${tool_pgid} 2>/dev/null; SCAN_PAUSED=true; echo ""; echo -e "  ${BOLD}${YELLOW}⏸  PAUSED — C to continue | ENTER to skip${NC}"; }
            elif [[ "$_key" == "c" || "$_key" == "C" ]]; then
                [ "$SCAN_PAUSED" = true ] && { kill -SIGCONT -- -${tool_pgid} 2>/dev/null; SCAN_PAUSED=false; echo -e "  ${GREEN}▶  Resumed — $CURRENT_TOOL_NAME continuing...${NC}"; }
            fi
        fi
    done

    wait "$CURRENT_TOOL_PID"; local exit_code=$?
    CURRENT_TOOL_PID=""; CURRENT_TOOL_NAME=""; SCAN_PAUSED=false
    return $exit_code
}

get_timestamp()     { date '+%Y-%m-%d %H:%M:%S'; }

# ─────────────────────────────────────────────────────────────
# Dependency check
# ─────────────────────────────────────────────────────────────
check_dependencies() {
    print_section "Checking Dependencies"
    local core=("subfinder" "assetfinder" "httpx" "gospider" "waybackurls" "katana" "paramspider" "jq" "curl")
    local missing=() optional=()
    for t in "${core[@]}"; do
        command -v "$t" &>/dev/null && print_success "$t" || { print_warning "$t NOT installed"; missing+=("$t"); }
    done
    # Optional enhanced tools
    for t in "github-subdomains" "gitlab-subdomains" "chaos" "crobat" "tlsx" "alterx" "dnsgen" "puredns" "asnmap" "cdncheck" "uro" "unfurl" "jsluice" "cariddi" "arjun" "kxss" "dalfox" "ffuf" "wafw00f"; do
        command -v "$t" &>/dev/null && print_success "$t" || { print_warning "$t not found (optional)"; optional+=("$t"); }
    done
    [ "$ENABLE_DIRSEARCH" = true ]    && { command -v dirsearch &>/dev/null && print_success "dirsearch" || { print_warning "dirsearch NOT installed"; optional+=("dirsearch"); }; }
    [ "$ENABLE_SECRETFINDER" = true ] && { command -v secretfinder &>/dev/null && print_success "secretfinder" || { print_warning "secretfinder NOT installed"; optional+=("secretfinder"); }; }
    [ "$ENABLE_TAKEOVER" = true ] || [ "$ENABLE_NUCLEI_FULL" = true ] && { command -v nuclei &>/dev/null && print_success "nuclei" || { print_warning "nuclei NOT installed"; optional+=("nuclei"); }; }
    [ "$ENABLE_GF" = true ]           && { command -v gf &>/dev/null && print_success "gf" || { print_warning "gf NOT installed"; optional+=("gf"); }; }
    [ "$ENABLE_GOWITNESS" = true ]    && { command -v gowitness &>/dev/null && print_success "gowitness" || { print_warning "gowitness NOT installed"; optional+=("gowitness"); }; }
    if [ "$ENABLE_PORT_SCAN" = true ]; then
        for t in naabu nmap dnsx; do command -v $t &>/dev/null && print_success "$t" || { print_warning "$t NOT installed"; optional+=("$t"); }; done
    fi
    if [ "$ENABLE_MOREURLS" = true ]; then
        for t in gau hakrawler; do command -v $t &>/dev/null && print_success "$t" || { print_warning "$t NOT installed"; optional+=("$t"); }; done
    fi
    if [ "$ENABLE_BRUTEFORCE" = true ]; then
        command -v dnsx &>/dev/null && print_success "dnsx" || { print_warning "dnsx NOT installed"; optional+=("dnsx"); }
        [ -f "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt" ] && print_success "SecLists wordlist" || print_warning "SecLists not found — sudo apt install seclists"
    fi
    [ ${#missing[@]} -gt 0 ]   && print_warning "Missing required: ${missing[*]}"
    [ ${#optional[@]} -gt 0 ]  && print_info    "Optional (install for more coverage): ${optional[*]}"
    [ ${#missing[@]} -eq 0 ]   && print_success "Core dependencies OK"
    echo ""
}

# ─────────────────────────────────────────────────────────────
# Usage
# ─────────────────────────────────────────────────────────────
usage() {
    echo -e "  ${BOLD}Usage:${NC}  $0 ${CYAN}<domain>${NC} ${YELLOW}[flags]${NC}"
    echo ""
    echo -e "  ${DIM}${CYAN}─────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}Subdomain:${NC}"
    echo -e "    ${CYAN}-parallel${NC}            Run enumeration tools in parallel"
    echo -e "    ${CYAN}-bruteforce${NC}          Active bruteforce + dnsgen/alterx permutations"
    echo ""
    echo -e "  ${BOLD}Infrastructure:${NC}"
    echo -e "    ${CYAN}-asn${NC}                 ASN & CIDR mapping (asnmap), cloud asset detection"
    echo -e "    ${CYAN}-vhost${NC}               Virtual host discovery (ffuf)"
    echo -e "    ${CYAN}-waf${NC}                 WAF detection (wafw00f) per live host"
    echo ""
    echo -e "  ${BOLD}URL & Params:${NC}"
    echo -e "    ${CYAN}-moreurls${NC}            Extra URL gathering (GAU + Hakrawler)"
    echo -e "    ${CYAN}-arjun${NC}               Deep parameter discovery (Arjun)"
    echo ""
    echo -e "  ${BOLD}JavaScript:${NC}"
    echo -e "    ${CYAN}-jsdeep${NC}              Download all JS + extract endpoints/params/secrets"
    echo -e "    ${CYAN}-secret${NC}              SecretFinder on JS files"
    echo ""
    echo -e "  ${BOLD}Analysis:${NC}"
    echo -e "    ${CYAN}-gf${NC}                  GF patterns — classify URLs by vuln type"
    echo -e "    ${CYAN}-grep${NC}                Grep juicy URLs (configs, backups, APIs, secrets)"
    echo -e "    ${CYAN}-nuclei${NC}              Full Nuclei scan (exposures + misconfigs + CVEs)"
    echo -e "    ${CYAN}-takeover${NC}            Subdomain takeover check"
    echo ""
    echo -e "  ${BOLD}Active:${NC}"
    echo -e "    ${CYAN}-dir${NC}                 Directory bruteforce (Dirsearch)"
    echo -e "    ${CYAN}-dir /path/wordlist${NC}  Custom wordlist"
    echo -e "    ${CYAN}-port${NC}                Port scan (Naabu + Nmap)"
    echo -e "    ${CYAN}-gowitness${NC}           Screenshot live hosts"
    echo ""
    echo -e "  ${DIM}${CYAN}─────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}Network Intelligence (makes HTTP requests):${NC}"
    echo -e "    ${CYAN}-verify${NC}              Probe BIGRAC endpoints (status/content-type)"
    echo -e "    ${CYAN}-swagger${NC}             Download & parse OpenAPI/Swagger specs"
    echo -e "    ${CYAN}-cors${NC}                CORS misconfiguration checker"
    echo -e "    ${CYAN}-methods${NC}             HTTP method discovery (OPTIONS)"
    echo -e "    ${CYAN}-bypass${NC}              Generate 403/401 bypass payloads + curls"
    echo -e "    ${CYAN}-validate${NC}            Validate extracted JS endpoints live"
    echo -e "    ${CYAN}-apidisc${NC}             API version/variant discovery"
    echo -e "    ${CYAN}-sitemap${NC}             Sitemap + robots.txt intelligence"
    echo ""
    echo -e "  ${BOLD}Always-on Intelligence (no flag):${NC}"
    echo -e "    Response clustering  ·  Target scoring  ·  TOP_100_TARGETS"
    echo -e "    JS route mapper  ·  GraphQL extractor  ·  Secret classification"
    echo -e "    Cloud buckets  ·  IDOR clusters  ·  Tech playbooks  ·  Historical diff"
    echo -e "    Wordlist learning  ·  Report pack  ·  Smart recon summary"
    echo ""
    echo -e "  ${BOLD}Examples:${NC}"
    echo -e "    ${CYAN}$0 target.com${NC}"
    echo -e "    ${CYAN}$0 target.com -parallel -bruteforce -asn${NC}"
    echo -e "    ${CYAN}$0 target.com -moreurls -jsdeep -gf -grep -arjun${NC}"
    echo -e "    ${CYAN}$0 target.com -moreurls -jsdeep -verify -swagger -cors -bypass${NC}"
    echo -e "    ${CYAN}$0 target.com -parallel -moreurls -jsdeep -dir -secret -gf -gowitness -nuclei -verify -swagger -cors -bypass -methods -validate${NC}"
    echo ""
    exit 1
}

# ═════════════════════════════════════════════════════════════
# STEP FUNCTIONS
# ═════════════════════════════════════════════════════════════

step_subdomain_enum() {
    if [ "$ENABLE_PARALLEL" = true ]; then
        print_info "Parallel subdomain enumeration..."
        command -v subfinder         &>/dev/null && { subfinder -d "$DOMAIN" -o subs_subfinder.txt -silent 2>/dev/null & pid_sub=$!; }
        command -v assetfinder       &>/dev/null && { assetfinder --subs-only "$DOMAIN" > subs_assetfinder.txt 2>/dev/null & pid_asset=$!; }
        command -v github-subdomains &>/dev/null && { github-subdomains -d "$DOMAIN" -o subs_github.txt 2>/dev/null & pid_gh=$!; }
        command -v gitlab-subdomains &>/dev/null && { gitlab-subdomains -d "$DOMAIN" -o subs_gitlab.txt 2>/dev/null & pid_gl=$!; }
        command -v chaos             &>/dev/null && { chaos -d "$DOMAIN" -o subs_chaos.txt -silent 2>/dev/null & pid_chaos=$!; }
        command -v crobat            &>/dev/null && { crobat -s "$DOMAIN" > subs_crobat.txt 2>/dev/null & pid_crobat=$!; }
        { command -v curl &>/dev/null && command -v jq &>/dev/null; } && {
            (timeout 30 curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | jq -r '.[].name_value // empty' 2>/dev/null | sed 's/^\*\.//' | grep -v '@' | sort -u > subs_crtsh.txt) & pid_crt=$!
        }
        command -v curl &>/dev/null && {
            (timeout 30 curl -s "https://shrewdeye.app/domains/$DOMAIN.txt" > subs_shrewdeye.txt 2>/dev/null) & pid_shrew=$!
            (timeout 30 curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | cut -d',' -f1 | grep -v "error" > subs_hackertarget.txt) & pid_ht=$!
            (timeout 30 curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1" 2>/dev/null | grep -oP "[\w.-]+\.$DOMAIN" | sort -u > subs_rapiddns.txt) & pid_rdns=$!
        }
        { command -v curl &>/dev/null && command -v jq &>/dev/null; } && {
            (timeout 30 curl -s "https://anubisdb.com/anubis/subdomains/$DOMAIN" 2>/dev/null | jq -r '.[]' 2>/dev/null | sort -u > subs_anubis.txt) & pid_anubis=$!
        }
        if command -v tlsx &>/dev/null; then
            (echo "$DOMAIN" | tlsx -san -cn -silent 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$DOMAIN" | sort -u > subs_tlsx.txt) & pid_tlsx=$!
        fi
        print_info "Waiting for all tools..."
        for var in pid_sub pid_asset pid_gh pid_gl pid_chaos pid_crobat pid_crt pid_shrew pid_ht pid_rdns pid_anubis pid_tlsx; do
            [ -n "${!var:-}" ] && wait "${!var}" 2>/dev/null
        done
        print_success "Parallel enumeration complete"
    else
        command -v subfinder &>/dev/null && { print_info "Subfinder..."; subfinder -d "$DOMAIN" -o subs_subfinder.txt -silent 2>/dev/null && print_success "Subfinder done" || print_warning "Subfinder failed"; } || print_warning "Subfinder not installed"
        command -v assetfinder &>/dev/null && { print_info "Assetfinder..."; assetfinder --subs-only "$DOMAIN" > subs_assetfinder.txt 2>/dev/null && print_success "Assetfinder done" || print_warning "Assetfinder failed"; } || print_warning "Assetfinder not installed"
        command -v github-subdomains &>/dev/null && { print_info "GitHub Subdomains..."; github-subdomains -d "$DOMAIN" -o subs_github.txt 2>/dev/null && print_success "github-subdomains done" || print_warning "github-subdomains failed"; }
        command -v gitlab-subdomains &>/dev/null && { print_info "GitLab Subdomains..."; gitlab-subdomains -d "$DOMAIN" -o subs_gitlab.txt 2>/dev/null && print_success "gitlab-subdomains done" || print_warning "gitlab-subdomains failed"; }
        command -v chaos &>/dev/null && { print_info "Chaos..."; chaos -d "$DOMAIN" -o subs_chaos.txt -silent 2>/dev/null && print_success "Chaos done" || print_warning "Chaos failed"; }
        command -v crobat &>/dev/null && { print_info "Crobat..."; crobat -s "$DOMAIN" > subs_crobat.txt 2>/dev/null && print_success "Crobat done" || print_warning "Crobat failed"; }
        if command -v tlsx &>/dev/null; then
            print_info "TLS certificate SAN enumeration..."
            echo "$DOMAIN" | tlsx -san -cn -silent 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$DOMAIN" | sort -u > subs_tlsx.txt
            [ -s subs_tlsx.txt ] && print_success "tlsx: $(wc -l < subs_tlsx.txt) subdomains via SAN" || print_warning "tlsx: no results"
        fi
        if command -v curl &>/dev/null && command -v jq &>/dev/null; then
            print_info "crt.sh..."
            local crt_r; crt_r=$(timeout 30 curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null)
            if echo "$crt_r" | jq -e . >/dev/null 2>&1; then
                echo "$crt_r" | jq -r '.[].name_value // empty' | sed 's/^\*\.//' | grep -v '@' | sort -u > subs_crtsh.txt
                [ -s subs_crtsh.txt ] && print_success "crt.sh: $(wc -l < subs_crtsh.txt)" || print_warning "crt.sh: no results"
            fi
        fi
        if command -v curl &>/dev/null; then
            print_info "Shrewdeye / HackerTarget / RapidDNS / Anubis..."
            timeout 30 curl -s "https://shrewdeye.app/domains/$DOMAIN.txt" > subs_shrewdeye.txt 2>/dev/null
            curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | cut -d',' -f1 | grep -v "error" > subs_hackertarget.txt
            curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1" 2>/dev/null | grep -oP "[\w.-]+\.$DOMAIN" | sort -u > subs_rapiddns.txt
            command -v jq &>/dev/null && curl -s "https://anubisdb.com/anubis/subdomains/$DOMAIN" 2>/dev/null | jq -r '.[]' 2>/dev/null | sort -u > subs_anubis.txt
            print_success "Passive API sources done"
        fi
    fi
}

step_bruteforce() {
    local wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
    if command -v dnsx &>/dev/null && [ -f "$wordlist" ]; then
        print_info "Checking wildcard DNS..."
        local wc_result; wc_result=$(dig "randomxyz99notreal.${DOMAIN}" +short 2>/dev/null | head -1)
        if [ -n "$wc_result" ]; then
            print_warning "Wildcard DNS detected — bruteforce skipped"
        else
            print_success "No wildcard — safe to bruteforce"
            print_skip_hint
            run_with_skip "dnsx-bruteforce" "dnsx -d \"$DOMAIN\" -w \"$wordlist\" -a -silent -o subs_bruteforce.txt 2>/dev/null"
            local ex=$?
            if [ $ex -eq 0 ] || [ $ex -eq 2 ]; then
                [ -s subs_bruteforce.txt ] && print_success "Bruteforce: $(wc -l < subs_bruteforce.txt) subdomains" || print_warning "Bruteforce: no new results"
            fi
        fi
    else
        ! command -v dnsx &>/dev/null && print_warning "dnsx not installed" || print_warning "SecLists not found"
    fi

    # Permutations via alterx
    if command -v alterx &>/dev/null && [ -f all_subs.txt ] 2>/dev/null; then
        print_info "Generating permutations with alterx..."
        alterx -l all_subs.txt -o alterx_perms.txt -silent 2>/dev/null
        if [ -s alterx_perms.txt ]; then
            print_info "Resolving $(wc -l < alterx_perms.txt) permutations..."
            if command -v puredns &>/dev/null; then
                puredns resolve alterx_perms.txt -r /usr/share/seclists/Miscellaneous/dns-resolvers.txt -w subs_alterx_resolved.txt 2>/dev/null || \
                dnsx -l alterx_perms.txt -a -silent -o subs_alterx_resolved.txt 2>/dev/null
            else
                dnsx -l alterx_perms.txt -a -silent -o subs_alterx_resolved.txt 2>/dev/null
            fi
            [ -s subs_alterx_resolved.txt ] && print_success "Permutations resolved: $(wc -l < subs_alterx_resolved.txt)" || print_warning "No permutations resolved"
        fi
    fi

    # dnsgen as alternative
    if command -v dnsgen &>/dev/null && [ -f all_subs.txt ] 2>/dev/null && ! command -v alterx &>/dev/null; then
        print_info "Generating permutations with dnsgen..."
        dnsgen all_subs.txt 2>/dev/null | dnsx -a -silent -o subs_dnsgen_resolved.txt 2>/dev/null
        [ -s subs_dnsgen_resolved.txt ] && print_success "dnsgen resolved: $(wc -l < subs_dnsgen_resolved.txt)"
    fi
}

step_dns_resolution() {
    if ls subs_*.txt 1>/dev/null 2>&1; then
        cat subs_*.txt 2>/dev/null | grep -v '@' | sort -u > all_subs.txt
        total_subs=$(wc -l < all_subs.txt)
        print_success "Total unique subdomains: $total_subs"
    else
        print_error "No subdomain files found"; total_subs=0
    fi
}

step_live_host_check() {
    if [ -s all_subs.txt ] && command -v httpx &>/dev/null; then
        print_info "httpx probe (status + title + server + size)..."
        setsid bash -c "cat all_subs.txt | httpx -silent -status-code -title -web-server -content-length -o live_hosts_detailed.txt 2>/dev/null" &
        CURRENT_TOOL_PID=$!; wait $CURRENT_TOOL_PID; local ex=$?; CURRENT_TOOL_PID=""
        if [ $ex -eq 0 ]; then
            awk '{print $1}' live_hosts_detailed.txt > live_hosts.txt 2>/dev/null
            live_hosts=$(wc -l < live_hosts.txt 2>/dev/null || echo 0)
            print_success "httpx done — live hosts: $live_hosts"

            # CDN check
            if command -v cdncheck &>/dev/null && [ -s live_hosts.txt ]; then
                print_info "CDN / origin detection..."
                cdncheck -i live_hosts.txt -o cdncheck_results.txt -silent 2>/dev/null
                [ -s cdncheck_results.txt ] && print_success "cdncheck: $(wc -l < cdncheck_results.txt) results" || print_warning "cdncheck: no results"
            fi
        else
            print_error "httpx failed"; live_hosts=0
        fi
    else
        print_warning "httpx not installed or no subdomains"; live_hosts=0
    fi

    technologies="N/A"
    if [ -s live_hosts.txt ] && command -v httpx &>/dev/null; then
        print_info "Tech detection..."
        if cat live_hosts.txt | httpx -tech-detect -silent -o tech_detect.txt 2>/dev/null; then
            [ -s tech_detect.txt ] && { technologies=$(grep -oP '\[.*?\]' tech_detect.txt 2>/dev/null | tr -d '[]' | tr '\n' ',' | sed 's/,$//' | head -c 200); print_success "Tech detection done"; }
        fi
    fi
}

step_waf_detection() {
    if [ -s live_hosts.txt ] && command -v wafw00f &>/dev/null; then
        print_info "WAF detection with wafw00f..."
        print_skip_hint
        run_with_skip "wafw00f" "wafw00f -i live_hosts.txt -o tyrion_waf.txt 2>/dev/null"
        local ex=$?
        if [ $ex -eq 0 ] || [ $ex -eq 2 ]; then
            [ -s tyrion_waf.txt ] && print_success "WAF scan: $(wc -l < tyrion_waf.txt) results" || print_warning "No WAF detected"
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts" || print_warning "wafw00f not installed — pip install wafw00f"
    fi
}

step_gowitness() {
    if [ -s live_hosts.txt ] && command -v gowitness &>/dev/null; then
        mkdir -p gowitness_output
        print_info "Screenshotting live hosts..."
        print_skip_hint
        run_with_skip "gowitness" "gowitness scan file -f live_hosts.txt --screenshot-path gowitness_output --write-db --write-db-uri sqlite://gowitness_output/gowitness.sqlite3 2>/dev/null"
        local ex=$?
        if [ $ex -eq 0 ] || [ $ex -eq 2 ]; then
            gowitness_count=$(ls gowitness_output/*.jpeg gowitness_output/*.png 2>/dev/null | wc -l)
            print_success "Screenshots: $gowitness_count"
            if [ "$gowitness_count" -gt 0 ]; then
                gowitness report generate --db-uri sqlite://gowitness_output/gowitness.sqlite3 --screenshot-path gowitness_output --zip-name gowitness_output/report.zip 2>/dev/null && \
                command -v unzip &>/dev/null && { unzip -o gowitness_output/report.zip -d gowitness_output/report/ 2>/dev/null; rm -f gowitness_output/report.zip; print_success "Report: gowitness_output/report/report.html"; }
            fi
        else
            print_error "Gowitness failed"; failed_tools+=("gowitness")
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts to screenshot" || print_warning "gowitness not installed"
    fi
}

step_port_scan() {
    if [ -s live_hosts.txt ] && command -v dnsx &>/dev/null && command -v naabu &>/dev/null; then
        print_info "Resolving domains to IPs..."
        sed 's|https\?://||' live_hosts.txt | cut -d'/' -f1 | sort -u > domains_for_port.txt
        dnsx -a -resp-only -silent < domains_for_port.txt | sort -u > ips.txt 2>/dev/null
        local ip_count; ip_count=$(wc -l < ips.txt 2>/dev/null || echo 0)
        print_success "Resolved $ip_count IPs"
        if [ "$ip_count" -gt 0 ]; then
            print_skip_hint
            run_with_skip "naabu" "naabu -l ips.txt -o open_ports.txt 2>/dev/null"
            local ex=$?
            if [ $ex -eq 0 ] || [ $ex -eq 2 ]; then
                [ -s open_ports.txt ] && { port_count=$(wc -l < open_ports.txt); print_success "Naabu: $port_count open ports"; } || print_warning "No open ports found"
                if command -v nmap &>/dev/null && [ -s open_ports.txt ]; then
                    local port_list; port_list=$(cut -d':' -f2 open_ports.txt | grep -E '^[0-9]+$' | awk '$1>=1&&$1<=65535' | sort -u | tr '\n' ',' | sed 's/,$//')
                    [ -n "$port_list" ] && { run_with_skip "nmap" "nmap -iL ips.txt -p \"$port_list\" -sV -oN ports_detailed.txt 2>/dev/null"; [ $? -eq 0 ] && print_success "Nmap done — ports_detailed.txt"; }
                fi
            fi
        fi
    else
        print_warning "dnsx / naabu not installed, or no live hosts"
    fi
}

step_asn_mapping() {
    if command -v asnmap &>/dev/null; then
        print_info "ASN mapping for $DOMAIN..."
        asnmap -d "$DOMAIN" -o asn.txt 2>/dev/null
        [ -s asn.txt ] && print_success "ASN info: $(wc -l < asn.txt) lines"
        grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}' asn.txt > cidrs.txt 2>/dev/null
        [ -s cidrs.txt ] && print_success "CIDRs: $(wc -l < cidrs.txt)"
        if command -v prips &>/dev/null && [ -s cidrs.txt ]; then
            while read cidr; do prips "$cidr"; done < cidrs.txt | sort -u > ips_from_asn.txt
            [ -s ips_from_asn.txt ] && print_success "IPs from ASN CIDRs: $(wc -l < ips_from_asn.txt)"
        fi
    else
        print_warning "asnmap not installed — go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    fi

    # Cloud asset detection from live hosts
    if [ -s live_hosts.txt ]; then
        grep -iE '(amazonaws|s3\.|azure|blob\.core|googleapis|googleusercontent|cloudfront|fastly|akamai|firebase|digitalocean|heroku|vercel|netlify)' live_hosts.txt > cloud_assets.txt 2>/dev/null
        [ -s cloud_assets.txt ] && print_success "Cloud assets detected: $(wc -l < cloud_assets.txt)" || print_info "No obvious cloud assets in live hosts"
    fi
}

step_takeover() {
    if [ -s live_hosts.txt ] && command -v nuclei &>/dev/null; then
        print_skip_hint
        if [ -d "$HOME/nuclei-templates/http/takeovers" ]; then
            run_with_skip "nuclei-takeover" "nuclei -l live_hosts.txt -t ~/nuclei-templates/http/takeovers -o takeover_results.txt 2>/dev/null"
            local ex=$?
            if [ $ex -eq 0 ] || [ $ex -eq 2 ]; then
                if [ -s takeover_results.txt ]; then
                    takeover_count=$(grep -c . takeover_results.txt 2>/dev/null || echo 0)
                    [ "$takeover_count" -gt 0 ] && { print_success "TAKEOVER: $takeover_count potential vulnerabilities!"; while read l; do echo -e "    ${RED}►${NC} $l"; done < takeover_results.txt; } || print_success "No takeovers found"
                else
                    print_success "No takeovers found"
                fi
            fi
        else
            print_error "Nuclei templates missing — run: nuclei -update-templates"
        fi
    else
        print_warning "nuclei not installed or no live hosts"
    fi
}

step_nuclei_full() {
    if [ -s live_hosts.txt ] && command -v nuclei &>/dev/null; then
        print_info "Full Nuclei scan (exposures + misconfigs + CVEs)..."
        print_skip_hint
        local templates=""
        [ -d "$HOME/nuclei-templates/http/exposures" ]       && templates="$templates -t ~/nuclei-templates/http/exposures"
        [ -d "$HOME/nuclei-templates/http/misconfigurations" ] && templates="$templates -t ~/nuclei-templates/http/misconfigurations"
        [ -d "$HOME/nuclei-templates/http/vulnerabilities" ]  && templates="$templates -t ~/nuclei-templates/http/vulnerabilities"
        [ -d "$HOME/nuclei-templates/http/cves" ]             && templates="$templates -t ~/nuclei-templates/http/cves"
        [ -d "$HOME/nuclei-templates/http/takeovers" ]        && templates="$templates -t ~/nuclei-templates/http/takeovers"
        if [ -n "$templates" ]; then
            run_with_skip "nuclei-full" "nuclei -l live_hosts.txt $templates -o tyrion_nuclei.txt -silent 2>/dev/null"
            local ex=$?
            [ $ex -eq 0 ] || [ $ex -eq 2 ] && { [ -s tyrion_nuclei.txt ] && print_success "Nuclei findings: $(wc -l < tyrion_nuclei.txt)" || print_success "Nuclei: no findings"; }
        else
            run_with_skip "nuclei-full" "nuclei -l live_hosts.txt -as -silent -o tyrion_nuclei.txt 2>/dev/null"
            [ $? -eq 0 ] && print_success "Nuclei auto-scan done"
        fi
    else
        print_warning "nuclei not installed or no live hosts"
    fi
}

step_url_gathering() {
    if [ -s live_hosts.txt ]; then
        if command -v gospider &>/dev/null; then
            print_info "Gospider..."
            print_skip_hint
            run_with_skip "gospider" "gospider -S live_hosts.txt -o gospider_output -t 5 -c 10 -d 3 --sitemap --robots -a -w 2>/dev/null"
        else print_warning "Gospider not installed"; fi

        if command -v waybackurls &>/dev/null; then
            print_info "Waybackurls..."
            print_skip_hint
            run_with_skip "waybackurls" "cat live_hosts.txt | waybackurls > wayback.txt 2>/dev/null"
        else print_warning "Waybackurls not installed"; fi

        if command -v katana &>/dev/null; then
            print_info "Katana..."
            print_skip_hint
            run_with_skip "katana" "katana -list live_hosts.txt -o katana.txt -silent -d 3 -jc -kf all -aff -ef png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css,mp4,mp3 2>/dev/null"
        else print_warning "Katana not installed"; fi

        if command -v cariddi &>/dev/null; then
            print_info "Cariddi (crawl + secrets + endpoints)..."
            print_skip_hint
            run_with_skip "cariddi" "cat live_hosts.txt | cariddi -plain -s -e -err 2>/dev/null | tee cariddi_output.txt | grep -oE 'https?://[^ ]+' | sort -u > cariddi_urls.txt"
        fi

        if [ "$ENABLE_MOREURLS" = true ]; then
            command -v gau &>/dev/null && { print_info "GAU..."; print_skip_hint; run_with_skip "gau" "echo \"$DOMAIN\" | gau > gau.txt 2>/dev/null"; } || print_warning "GAU not installed"
            command -v hakrawler &>/dev/null && { print_info "Hakrawler..."; print_skip_hint; run_with_skip "hakrawler" "cat live_hosts.txt | hakrawler > hakrawler.txt 2>/dev/null"; } || print_warning "Hakrawler not installed"
        fi
    else
        print_warning "No live hosts — skipping URL gathering"
    fi

    # Extract gospider URLs
    if [ -d gospider_output ] && [ -n "$(find gospider_output -maxdepth 1 -type f -print -quit 2>/dev/null)" ]; then
        find gospider_output -type f -exec cat {} + 2>/dev/null | grep -oE 'https?://[^ "'"'"']+' | sort -u > gospider_urls.txt
    fi

    local junk_ext='\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|mp4|mp3|avi|mov|wmv|webm|ogg|wav|bmp|tiff|psd|webp|otf)(\?|#|$)'
    local all_sources="wayback.txt katana.txt gau.txt hakrawler.txt gospider_urls.txt cariddi_urls.txt"
    local found_any=false
    for f in $all_sources; do [ -f "$f" ] && found_any=true; done

    if [ "$found_any" = true ]; then
        cat $all_sources 2>/dev/null | sort -u > allurls_raw.txt
        grep -viE "$junk_ext" allurls_raw.txt > allurls_preclean.txt; rm -f allurls_raw.txt

        # uro deduplication
        if command -v uro &>/dev/null; then
            print_info "Deduplicating with uro..."
            uro < allurls_preclean.txt > allurls.txt 2>/dev/null || mv allurls_preclean.txt allurls.txt
            print_success "uro dedup done"
        else
            mv allurls_preclean.txt allurls.txt
        fi

        # unfurl for structure analysis
        if command -v unfurl &>/dev/null && [ -s allurls.txt ]; then
            cat allurls.txt | unfurl --unique paths  > url_paths.txt 2>/dev/null
            cat allurls.txt | unfurl --unique keys   > url_param_keys.txt 2>/dev/null
            cat allurls.txt | unfurl --unique domains > url_domains.txt 2>/dev/null
            print_success "unfurl: paths/keys/domains extracted"
        fi

        total_urls=$(wc -l < allurls.txt 2>/dev/null || echo 0)
        print_success "Total URLs: $total_urls (merged + cleaned)"
    else
        print_warning "No URL files to merge"; total_urls=0
    fi
}

step_param_discovery() {
    if command -v paramspider &>/dev/null; then
        print_info "ParamSpider..."
        print_skip_hint
        run_with_skip "paramspider" "paramspider -d \"$DOMAIN\" 2>/dev/null"
        local ex=$?
        if [ $ex -eq 0 ] || [ $ex -eq 2 ]; then
            local pf=""
            [ -f "results/${DOMAIN}.txt" ] && pf="results/${DOMAIN}.txt"
            [ -z "$pf" ] && [ -f "output/${DOMAIN}.txt" ] && pf="output/${DOMAIN}.txt"
            [ -z "$pf" ] && pf=$(find . -maxdepth 3 -name "${DOMAIN}.txt" 2>/dev/null | head -1)
            [ -n "$pf" ] && [ -f "$pf" ] && { cp "$pf" params.txt; param_count=$(wc -l < params.txt); print_success "ParamSpider: $param_count parameters"; } || print_warning "ParamSpider output not found"
        fi
    else print_warning "ParamSpider not installed"; fi
}

step_arjun() {
    if [ -s live_hosts.txt ] && command -v arjun &>/dev/null; then
        print_info "Arjun — deep parameter discovery..."
        print_skip_hint
        run_with_skip "arjun" "arjun -i live_hosts.txt -oT arjun_params.txt --stable 2>/dev/null"
        local ex=$?
        if [ $ex -eq 0 ] || [ $ex -eq 2 ]; then
            [ -s arjun_params.txt ] && print_success "Arjun: $(wc -l < arjun_params.txt) parameter findings" || print_warning "Arjun: no parameters found"
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts for Arjun" || print_warning "arjun not installed — pip install arjun"
    fi
}

step_js_extraction() {
    if [ -s allurls.txt ]; then
        print_info "Filtering JS / PHP / JSON / sensitive files..."
        grep -E "\.js"   allurls.txt > javascript.txt 2>/dev/null
        grep -E "\.php"  allurls.txt > php.txt 2>/dev/null
        grep -Ei '\.json($|\?|&)' allurls.txt > json.txt 2>/dev/null
        grep -Ei '/(swagger|openapi|api-docs|v2\/api-docs|swagger-resources)(\.json|/|$|\?)|\b(json|config|metadata|schema|manifest|openapi|swagger)(\.json|\.yaml|\.yml)?(\?|$)|\.(yaml|yml)($|\?|&)|(/|^)(package|config|composer|manifest)\.json($|\?|&)|/(\.env|env|config\.php|db\.sql|dump\.sql|backup|\.htpasswd|credentials|robots\.txt)$' allurls.txt | sort -u > BIGRAC.txt 2>/dev/null
        # GraphQL / Swagger endpoints
        grep -iE '/(graphql|graphiql|graph|__schema|query|mutation)(\?|$|/)' allurls.txt | sort -u >> BIGRAC.txt 2>/dev/null
        sort -u BIGRAC.txt -o BIGRAC.txt 2>/dev/null

        js_count=$(wc -l < javascript.txt 2>/dev/null || echo 0)
        php_count=$(wc -l < php.txt 2>/dev/null || echo 0)
        json_count=$(wc -l < json.txt 2>/dev/null || echo 0)
        bigrac_count=$(wc -l < BIGRAC.txt 2>/dev/null || echo 0)
        print_success "JS: $js_count  PHP: $php_count  JSON: $json_count  BIGRAC/API: $bigrac_count"
    else
        print_warning "No URLs to filter"
    fi
}

step_jsdeep() {
    if [ -s allurls.txt ]; then
        mkdir -p js_files js_analysis

        # Collect all JS URLs
        grep -Ei '\.js($|\?)' allurls.txt | sort -u > js_to_download.txt
        local js_dl_count; js_dl_count=$(wc -l < js_to_download.txt 2>/dev/null || echo 0)
        print_info "Downloading $js_dl_count JavaScript files..."

        while IFS= read -r js_url; do
            local fname; fname=$(echo "$js_url" | sed 's#https\?://##; s#[/?&=:+]#_#g')
            fname="${fname:0:200}.js"
            curl -k -L --max-time 15 --silent "$js_url" -o "js_files/$fname" 2>/dev/null
        done < js_to_download.txt

        local dl_count; dl_count=$(find js_files -type f -size +0c 2>/dev/null | wc -l)
        print_success "Downloaded: $dl_count JS files"

        # jsluice — structured extraction
        if command -v jsluice &>/dev/null; then
            print_info "jsluice — extracting URLs & secrets..."
            find js_files -type f | while read -r f; do
                jsluice urls "$f" 2>/dev/null | jq -r '.url // empty' 2>/dev/null
            done | grep -v '^$' | sort -u > js_analysis/jsluice_endpoints.txt

            find js_files -type f | while read -r f; do
                jsluice secrets "$f" 2>/dev/null
            done > js_analysis/jsluice_secrets_raw.txt 2>/dev/null
            jq -r '. | "\(.kind): \(.value)"' js_analysis/jsluice_secrets_raw.txt 2>/dev/null | sort -u > js_analysis/jsluice_secrets.txt

            [ -s js_analysis/jsluice_endpoints.txt ] && print_success "jsluice endpoints: $(wc -l < js_analysis/jsluice_endpoints.txt)"
            [ -s js_analysis/jsluice_secrets.txt ]   && print_success "jsluice secrets:   $(wc -l < js_analysis/jsluice_secrets.txt)"
        fi

        # grep-based extraction fallback / supplement
        print_info "Regex extraction from JS files..."
        grep -RhoE '["'"'"'](/[a-zA-Z0-9_./?=&%@#!$*()+,;:-]{2,})["'"'"']' js_files/ 2>/dev/null | tr -d '"'"'" | sort -u > js_analysis/js_paths.txt
        grep -RhoE '(https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+)' js_files/ 2>/dev/null | sort -u > js_analysis/js_absolute_urls.txt
        grep -RhoE '[?&][a-zA-Z0-9_-]{2,}=' js_files/ allurls.txt 2>/dev/null | sed 's/^[?&]//' | sort -u > js_analysis/params_from_js.txt

        # Secrets via regex
        grep -RhoE '(api[_-]?key|apikey|secret|token|password|passwd|aws_|stripe[_-]?key|firebase|google[_-]?api|private[_-]?key)\s*[=:]\s*["'"'"'][^"'"'"']{8,}["'"'"']' js_files/ 2>/dev/null | sort -u > js_analysis/js_secrets_regex.txt

        # Reconstruct full endpoints
        if [ -s live_hosts.txt ] && [ -s js_analysis/js_paths.txt ]; then
            print_info "Reconstructing full endpoints from JS paths..."
            mkdir -p reconstructed_endpoints
            while IFS= read -r host; do
                while IFS= read -r path; do
                    echo "${host%/}${path}"
                done < js_analysis/js_paths.txt
            done < live_hosts.txt | sort -u > reconstructed_endpoints/full_endpoints.txt
            [ -s reconstructed_endpoints/full_endpoints.txt ] && print_success "Reconstructed: $(wc -l < reconstructed_endpoints/full_endpoints.txt) endpoints"
        fi

        local pc; pc=$(wc -l < js_analysis/js_paths.txt 2>/dev/null || echo 0)
        local ac; ac=$(wc -l < js_analysis/js_absolute_urls.txt 2>/dev/null || echo 0)
        local mc; mc=$(wc -l < js_analysis/params_from_js.txt 2>/dev/null || echo 0)
        local sc; sc=$(wc -l < js_analysis/js_secrets_regex.txt 2>/dev/null || echo 0)
        print_success "JS Deep — paths: $pc  abs_urls: $ac  params: $mc  secrets: $sc"
    else
        print_warning "allurls.txt empty — run URL gathering first"
    fi
}

step_vhost() {
    if [ -s live_hosts.txt ] && command -v ffuf &>/dev/null; then
        local wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        [ ! -f "$wordlist" ] && wordlist="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
        if [ -f "$wordlist" ]; then
            mkdir -p vhost_results
            print_info "VHost discovery with ffuf ($(wc -l < live_hosts.txt) hosts)..."
            local total_vhosts=0
            while IFS= read -r host; do
                local base; base=$(echo "$host" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
                local out="vhost_results/${base}_vhosts.json"
                ffuf -w "$wordlist" -u "$host" -H "Host: FUZZ.$base" \
                     -mc 200,201,301,302,403 -fc 404 \
                     -o "$out" -of json -silent 2>/dev/null
                if [ -s "$out" ]; then
                    local cnt; cnt=$(jq '.results | length' "$out" 2>/dev/null || echo 0)
                    [ "$cnt" -gt 0 ] && { print_success "vhosts on $base: $cnt"; total_vhosts=$((total_vhosts + cnt)); }
                fi
            done < live_hosts.txt
            print_success "Total vhosts discovered: $total_vhosts"
        else
            print_warning "SecLists not found — sudo apt install seclists"
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts" || print_warning "ffuf not installed — go install github.com/ffuf/ffuf/v2@latest"
    fi
}

step_grep_juicy() {
    if [ -s allurls.txt ]; then
        mkdir -p grep_results
        local F="allurls.txt"
        grep -iE "(\.config|\.conf|\.cfg|\.ini|\.env|\.properties|\.yaml|\.yml|\.toml|\.xml|settings|configuration)" "$F" 2>/dev/null | sort -u > grep_results/config.txt
        grep -iE "\.(bak|backup|old|orig|original|copy|tmp|temp|swp|swo|save|~|zip|tar|gz|rar|7z)(\?|$|&)" "$F" 2>/dev/null | sort -u > grep_results/backup.txt
        grep -iE "(\.sql|\.sqlite|\.sqlite3|\.db|\.mdb|\.dump|mysql|postgres|mongodb|database|phpmyadmin)" "$F" 2>/dev/null | sort -u > grep_results/database.txt
        grep -iE "(password|passwd|pwd|secret|token|api_key|apikey|api-key|auth_token|access_token|private_key|credential|htpasswd)" "$F" 2>/dev/null | sort -u > grep_results/secrets.txt
        grep -iE "(\.git|\.svn|\.hg|\.gitignore|\.gitconfig|\.gitattributes)" "$F" 2>/dev/null | sort -u > grep_results/sourcecode.txt
        grep -iE "(swagger|openapi|api-docs|graphql|graphiql|/api/|/v1/|/v2/|/v3/|rest/|wsdl|raml|__schema)" "$F" 2>/dev/null | sort -u > grep_results/api.txt
        grep -iE "(admin|administrator|dashboard|cpanel|webadmin|manager|console|portal|backend|wp-admin|phpmyadmin|adminer)" "$F" 2>/dev/null | sort -u > grep_results/admin.txt
        grep -iE "(debug|trace|test|phpinfo|server-status|server-info|\.dev\.|\.staging\.|\.uat\.|\.local\.|\.test\.)" "$F" 2>/dev/null | sort -u > grep_results/debug.txt
        grep -iE "(\.log|/logs/|/log/|error\.log|access\.log|debug\.log)" "$F" 2>/dev/null | sort -u > grep_results/logs.txt
        grep -iE "(upload|uploads|file|files|attachment|media|assets|/tmp/|/cache/)" "$F" 2>/dev/null | sort -u > grep_results/uploads.txt
        grep -iE "\.(pem|key|crt|cer|p12|pfx|jks|keystore|pub|ppk)(\?|$|&)" "$F" 2>/dev/null | sort -u > grep_results/keys.txt
        grep -iE "(\.csv|\.xls|\.xlsx|\.doc|\.docx|\.pdf|data\.json|users\.json|export|dump)" "$F" 2>/dev/null | sort -u > grep_results/datafiles.txt
        grep -iE "(internal|private|hidden|secret|confidential|restricted|/priv/|/private/)" "$F" 2>/dev/null | sort -u > grep_results/internal.txt
        grep -iE "(aws|s3\.|amazonaws|azure|blob\.core|gcp|googleusercontent|firebase|digitalocean|bucket)" "$F" 2>/dev/null | sort -u > grep_results/cloud.txt
        grep -iE "/(login|signin|sign-in|auth|oauth|authorize|sso|saml|oidc|openid|callback|logout|register|mfa|2fa|otp)" "$F" 2>/dev/null | sort -u > grep_results/auth.txt
        find grep_results/ -type f -name '*.txt' ! -name 'ALL_JUICY.txt' -exec cat {} + 2>/dev/null | sort -u > grep_results/ALL_JUICY.txt
        find grep_results/ -name '*.txt' ! -name 'ALL_JUICY.txt' -type f -empty -delete 2>/dev/null
        print_success "Juicy URLs: $(wc -l < grep_results/ALL_JUICY.txt 2>/dev/null || echo 0) total  →  grep_results/"
    else
        print_warning "allurls.txt empty"
    fi
}

step_gf_patterns() {
    if [ -s allurls.txt ] && command -v gf &>/dev/null; then
        mkdir -p gf
        for pat in xss sqli ssrf lfi redirect rce idor ssti cors s3-buckets interestingparams upload-fields; do
            gf "$pat" < allurls.txt > "gf/${pat}.txt" 2>/dev/null
        done
        find gf/ -type f -empty -delete 2>/dev/null
        print_success "GF patterns done:"
        echo -e "    ${GREEN}►${NC} XSS: $(wc -l < gf/xss.txt 2>/dev/null||echo 0)  SQLi: $(wc -l < gf/sqli.txt 2>/dev/null||echo 0)  SSRF: $(wc -l < gf/ssrf.txt 2>/dev/null||echo 0)  LFI: $(wc -l < gf/lfi.txt 2>/dev/null||echo 0)  IDOR: $(wc -l < gf/idor.txt 2>/dev/null||echo 0)  RCE: $(wc -l < gf/rce.txt 2>/dev/null||echo 0)"
    else
        [ ! -s allurls.txt ] && print_warning "No URLs for GF" || print_warning "gf not installed"
    fi
}

step_dirsearch() {
    if [ -s live_hosts.txt ] && command -v dirsearch &>/dev/null; then
        print_skip_hint
        local ext="conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,rb,php,bkp,cache,cgi,csv,html,inc,jar,js,json,jsp,lock,log,rar,sql.gz,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json"
        local cmd
        if [ -n "$CUSTOM_WORDLIST" ] && [ -f "$CUSTOM_WORDLIST" ]; then
            cmd="dirsearch -l live_hosts.txt -o tyrion_dirsearch.txt -w $CUSTOM_WORDLIST -i 200 -e $ext 2>/dev/null"
        elif [ -f ~/Desktop/WORDLIST/ULTRA_MEGA.txt ]; then
            cmd="dirsearch -l live_hosts.txt -o tyrion_dirsearch.txt -w ~/Desktop/WORDLIST/ULTRA_MEGA.txt -i 200 -e $ext 2>/dev/null"
        else
            cmd="dirsearch -l live_hosts.txt -o tyrion_dirsearch.txt -i 200 2>/dev/null"
        fi
        run_with_skip "dirsearch" "$cmd"
        local ex=$?
        if [ $ex -eq 0 ]; then
            dirsearch_count=$(grep -c "200" tyrion_dirsearch.txt 2>/dev/null || echo 0)
            print_success "Dirsearch done — 200s: $dirsearch_count  →  tyrion_dirsearch.txt"
        elif [ $ex -ne 2 ]; then
            print_error "Dirsearch failed"; failed_tools+=("dirsearch")
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts" || print_warning "Dirsearch not installed"
    fi
}

step_secretfinder() {
    if [ -s javascript.txt ] && command -v secretfinder &>/dev/null; then
        print_skip_hint
        run_with_skip "secretfinder" "secretfinder -i javascript.txt -o cli > secrets_found.txt 2>/dev/null"
        local ex=$?
        if [ $ex -eq 0 ] || [ $ex -eq 2 ]; then
            [ -s secrets_found.txt ] && { secret_count=$(wc -l < secrets_found.txt); print_success "SecretFinder: $secret_count potential secrets"; } || print_warning "SecretFinder: no secrets found"
        else
            print_error "SecretFinder failed"; failed_tools+=("secretfinder")
        fi
    else
        [ ! -s javascript.txt ] && print_warning "No JS files" || print_warning "SecretFinder not installed"
    fi
}

# ─────────────────────────────────────────────────────────────
# Always-on analysis (fast, no flags needed)
# ─────────────────────────────────────────────────────────────
step_auth_surface() {
    print_info "Auth surface detection..."
    mkdir -p auth_surface
    if [ -s allurls.txt ]; then
        grep -iE '/(login|signin|sign-in|logout|register|signup|sign-up|auth|oauth|authorize|callback|sso|saml|oidc|openid|token|mfa|2fa|otp|verify|forgot|reset-password|change-password)' allurls.txt | sort -u > auth_surface/auth_endpoints.txt
    fi
    # Auth provider fingerprinting from tech detect
    if [ -s tech_detect.txt ]; then
        grep -iE '(auth0|okta|azure-ad|keycloak|ping|onelogin|shibboleth|adfs|cognito|duo|jumpcloud)' tech_detect.txt > auth_surface/auth_providers.txt 2>/dev/null
    fi
    [ -s live_hosts_detailed.txt ] && grep -iE '(auth0|okta|keycloak|ping|cognito)' live_hosts_detailed.txt >> auth_surface/auth_providers.txt 2>/dev/null
    sort -u auth_surface/auth_providers.txt -o auth_surface/auth_providers.txt 2>/dev/null
    local ep; ep=$(wc -l < auth_surface/auth_endpoints.txt 2>/dev/null || echo 0)
    local pv; pv=$(wc -l < auth_surface/auth_providers.txt 2>/dev/null || echo 0)
    print_success "Auth endpoints: $ep  |  Providers detected: $pv"
}

step_bug_hunt_candidates() {
    print_info "Bug hunt candidate extraction..."
    mkdir -p bug_hunt
    if [ -s allurls.txt ]; then
        # IDOR
        grep -iE '/((user|profile|account|order|ticket|invoice|report|document|file|project|team|member|customer|admin)[s]?/[0-9a-fA-F-]{1,40})' allurls.txt | sort -u > bug_hunt/idor_candidates.txt
        # SSRF
        grep -iE '[?&](url|uri|dest|destination|redirect|return|callback|next|host|server|endpoint|proxy|target|resource|fetch|load|remote|forward|source|to|from|path|location|site|page|feed|redir|ref|image_url|img_url|link|href|src)=' allurls.txt | sort -u > bug_hunt/ssrf_candidates.txt
        # XSS
        grep -iE '[?&](search|q|query|term|keyword|name|value|input|text|content|message|comment|title|desc|description|s|p|v|k|lang|locale|type|cat|tag|label|subject|body|note|summary)=' allurls.txt | sort -u > bug_hunt/xss_candidates.txt
        # Open Redirect
        grep -iE '[?&](return|redirect|next|url|goto|forward|target|redir|ref|return_to|returnUrl|returnUrl|callback|continue|go|out|exit|view|display)=' allurls.txt | sort -u > bug_hunt/open_redirect_candidates.txt
        # LFI / File Read
        grep -iE '[?&](file|path|template|page|dir|document|root|include|folder|pg|style|pdf|doc|conf|config|archive|lang|locale|module|plugin|theme|load|read|open)=' allurls.txt | sort -u > bug_hunt/lfi_candidates.txt
        # SQLi
        grep -iE '[?&](id|pid|sid|uid|cid|oid|nid|did|rid|tid|aid|gid|cat|category|product|item|post|page|article|news|sort|order|group|limit|offset|start|count|num|type|from|by)=' allurls.txt | sort -u > bug_hunt/sqli_candidates.txt
    fi
    find bug_hunt/ -type f -empty -delete 2>/dev/null
    print_success "Bug hunt candidates:"
    echo -e "    ${GREEN}►${NC} IDOR: $(wc -l < bug_hunt/idor_candidates.txt 2>/dev/null||echo 0)   SSRF: $(wc -l < bug_hunt/ssrf_candidates.txt 2>/dev/null||echo 0)   XSS: $(wc -l < bug_hunt/xss_candidates.txt 2>/dev/null||echo 0)"
    echo -e "    ${GREEN}►${NC} Open Redirect: $(wc -l < bug_hunt/open_redirect_candidates.txt 2>/dev/null||echo 0)   LFI: $(wc -l < bug_hunt/lfi_candidates.txt 2>/dev/null||echo 0)   SQLi: $(wc -l < bug_hunt/sqli_candidates.txt 2>/dev/null||echo 0)"
}

step_attack_surface_ranking() {
    print_info "Attack surface ranking..."
    mkdir -p attack_surface
    if [ -s allurls.txt ]; then
        # HIGH — direct bug targets
        grep -iE '/(api|graphql|graphiql|__schema|swagger|swagger-ui|openapi|admin|oauth|saml|token|upload|import|export|webhook|rpc|exec|eval|render|proxy|ssrf|redirect|callback|auth|login|reset|register|signup|invite|payment|billing|transfer|withdraw|grant|impersonate|sudo|shell|cmd|command|execute)' allurls.txt | sort -u > attack_surface/HIGH_VALUE.txt
        # MEDIUM — interesting but lower priority
        grep -iE '/(profile|user|account|order|ticket|invoice|payment|setting|config|manage|dashboard|report|search|comment|post|article|product|download|view|show|get|fetch|read|edit|update|delete|create|add|remove)' allurls.txt | grep -v -f attack_surface/HIGH_VALUE.txt 2>/dev/null | sort -u > attack_surface/MEDIUM_VALUE.txt
        # LOW — static / uninteresting
        grep -iE '/(image|img|css|font|icon|static|public|asset|media|thumb|favicon)' allurls.txt | sort -u > attack_surface/LOW_VALUE.txt

        find attack_surface/ -type f -empty -delete 2>/dev/null
        print_success "Attack surface ranked:"
        echo -e "    ${RED}►${NC}    HIGH: $(wc -l < attack_surface/HIGH_VALUE.txt 2>/dev/null||echo 0)"
        echo -e "    ${YELLOW}►${NC}  MEDIUM: $(wc -l < attack_surface/MEDIUM_VALUE.txt 2>/dev/null||echo 0)"
        echo -e "    ${DIM}►${NC}     LOW: $(wc -l < attack_surface/LOW_VALUE.txt 2>/dev/null||echo 0)"

        # Parameter mining from all sources
        print_info "Mining all parameters..."
        {
            [ -s allurls.txt ]                           && grep -hoE '[?&][a-zA-Z0-9_-]{2,}=' allurls.txt 2>/dev/null
            [ -s params.txt ]                            && grep -hoE '[?&][a-zA-Z0-9_-]{2,}=' params.txt 2>/dev/null
            [ -s js_analysis/params_from_js.txt ]        && cat js_analysis/params_from_js.txt 2>/dev/null
            [ -s url_param_keys.txt ]                    && cat url_param_keys.txt 2>/dev/null
            [ -s arjun_params.txt ]                      && grep -hoE '[a-zA-Z0-9_-]{2,}' arjun_params.txt 2>/dev/null
        } | sed 's/^[?&]//' | sed 's/=$//' | sort | uniq -c | sort -rn | awk '{print $2, $1}' > all_parameters.txt 2>/dev/null
        [ -s all_parameters.txt ] && print_success "All parameters (ranked by freq): $(wc -l < all_parameters.txt)"
    else
        print_warning "No URLs to rank"
    fi
}

# ═════════════════════════════════════════════════════════════
# INTELLIGENCE LAYER — always-on (pure file analysis, no network)
# ═════════════════════════════════════════════════════════════

# ─── 1. Response Clustering + Login Panel Detection ──────────
step_response_intelligence() {
    # Response clustering
    if [ -s live_hosts_detailed.txt ]; then
        print_info "Clustering responses..."
        awk '{
            status="?"; server="?"
            for(i=1;i<=NF;i++){
                if($i~/^\[[0-9]+\]$/) status=$i
                if($i~/^\[/ && $i!~/^\[[0-9]+\]$/ && $i!~/^\[title/) server=$i
            }
            key=status" "server; count[key]++
            if(count[key]==1) ex[key]=$1
        } END { for(k in count) printf "%4d  %s  → %s\n",count[k],k,ex[k] }' \
        live_hosts_detailed.txt | sort -rn > response_clusters.txt
        print_success "Response clusters: $(wc -l < response_clusters.txt) unique groups"
        head -5 response_clusters.txt | while IFS= read -r line; do echo -e "    ${CYAN}►${NC} $line"; done
    fi

    # Login panel detection
    local panel_pat="jenkins|grafana|kibana|gitlab|sonarqube|jira|confluence|argocd|harbor|vault|rancher|portainer|splunk|elastic|prometheus|nexus|artifactory|teamcity|bamboo|zabbix|nagios|phpmyadmin|adminer|pgadmin|redisinsight|rabbitmq|sonar|airflow|superset|metabase|redash|retool"
    {
        [ -s live_hosts_detailed.txt ] && grep -iE "$panel_pat" live_hosts_detailed.txt
        [ -s allurls.txt ]             && grep -iE "$panel_pat" allurls.txt
        [ -s tech_detect.txt ]         && grep -iE "$panel_pat" tech_detect.txt
    } | sort -u > high_value_panels.txt 2>/dev/null
    find . -maxdepth 1 -name "high_value_panels.txt" -empty -delete 2>/dev/null
    [ -s high_value_panels.txt ] && print_success "High-value panels detected: $(wc -l < high_value_panels.txt)" || print_info "No known panels detected"
}

# ─── 2. Target Scoring + Auto Request Builder ────────────────
step_target_scoring() {
    if [ ! -s allurls.txt ]; then print_warning "No URLs to score"; return; fi
    print_info "Scoring $(wc -l < allurls.txt) URLs..."

    python3 - allurls.txt > url_scores_raw.txt 2>/dev/null <<'PYEOF'
import sys, re
def score(u):
    s=0; l=u.lower()
    if re.search(r'/(swagger|openapi|api-docs|graphql|graphiql|__schema)',l): s+=50
    if re.search(r'/(admin|administrator|console|dashboard|panel|manager)',l): s+=50
    if re.search(r'/(auth|oauth|saml|sso|oidc|openid|token|login|signin)',l): s+=40
    if re.search(r'/(upload|import|export|file|attachment|multipart)',l): s+=35
    if re.search(r'[?&](id|uid|user_?id|order_?id|ticket_?id|account_?id|cid|pid)=',l): s+=35
    if re.search(r'/(user|account|order|ticket|invoice|profile|payment|billing)',l): s+=30
    if re.search(r'[?&](token|access_token|api_?key|secret|callback|redirect|url|return|next)=',l): s+=25
    if re.search(r'/(api/|/v[0-9]+/)',l): s+=20
    if re.search(r'/(reset|forgot|verify|confirm|invite|register|signup|recover)',l): s+=20
    if re.search(r'\.(bak|sql|zip|tar|gz|old|backup|dump)(\?|$)',l): s+=45
    if re.search(r'/(debug|trace|test|phpinfo|server-status|\.env|config|backup)',l): s+=40
    if re.search(r'[?&](file|path|template|dir|include|page|load|read|module)=',l): s+=30
    if re.search(r'\.(png|jpg|gif|svg|ico|woff|css|ttf|eot|mp4|mp3)(\?|$)',l): s-=30
    if re.search(r'/(static|assets|media|images|fonts|vendor|dist|build)/',l): s-=20
    return max(0,s)
with open(sys.argv[1]) as f:
    rows=[(score(l.strip()),l.strip()) for l in f if l.strip()]
rows.sort(reverse=True)
for sc,url in rows:
    if sc>0: print(f"{sc:3d}  {url}")
PYEOF

    if [ -s url_scores_raw.txt ]; then
        awk '{print $2}' url_scores_raw.txt | head -100 > TOP_100_TARGETS.txt
        cp url_scores_raw.txt url_scores.txt
        print_success "TOP 100 targets → TOP_100_TARGETS.txt"
        echo -e "    ${BOLD}${RED}Top 10 targets by score:${NC}"
        head -10 url_scores_raw.txt | while IFS= read -r line; do
            echo -e "    ${RED}[$(echo "$line"|awk '{print $1}')]${NC} $(echo "$line"|awk '{$1="";print}')"
        done
        rm -f url_scores_raw.txt
    else
        # awk fallback if python3 absent
        awk '{
            s=0
            if($0~/swagger|graphql|admin|oauth/) s+=50
            if($0~/upload|auth|token|login/) s+=35
            if($0~/[?&](id|uid|url|file|path)=/) s+=30
            if($0~/\.(png|jpg|css|gif|woff)/) s-=30
            if(s>0) printf "%3d  %s\n",s,$0
        }' allurls.txt | sort -rn | head -500 > url_scores.txt
        awk '{$1="";print}' url_scores.txt | head -100 > TOP_100_TARGETS.txt
        print_success "Scored (awk fallback) — TOP 100 → TOP_100_TARGETS.txt"
    fi

    # Auto Request Builder
    print_info "Building curl commands..."
    > curl_commands.txt
    {
        [ -s TOP_100_TARGETS.txt ] && cat TOP_100_TARGETS.txt
        [ -s BIGRAC.txt ]          && cat BIGRAC.txt
    } | sort -u | head -300 | while IFS= read -r url; do
        echo "curl -i -k -s \"$url\""
    done > curl_commands.txt
    # Burp-ready target list (just URLs)
    cp TOP_100_TARGETS.txt burp_targets.txt 2>/dev/null
    [ -s BIGRAC.txt ] && cat BIGRAC.txt >> burp_targets.txt && sort -u burp_targets.txt -o burp_targets.txt
    print_success "curl_commands.txt: $(wc -l < curl_commands.txt)   burp_targets.txt: $(wc -l < burp_targets.txt 2>/dev/null||echo 0)"
}

# ─── 3. JS Route Mapper + GraphQL Extractor ──────────────────
step_js_intelligence() {
    if [ ! -d js_files ] || [ -z "$(find js_files -type f -size +0c 2>/dev/null | head -1)" ]; then
        print_info "No JS files downloaded (use -jsdeep to enable)"
        return
    fi

    print_info "Mapping frontend routes..."
    # Path strings: "/api/..." patterns
    grep -RhoE '"(/[a-zA-Z0-9_/:.@-]{2,})"' js_files/ 2>/dev/null | tr -d '"' | grep -E '^/' | grep -v '^//' | sort -u > frontend_routes.txt
    grep -RhoE "path:\s*['\"]([^'\"]+)['\"]" js_files/ 2>/dev/null | sed "s/path:\s*['\"]//; s/['\"]$//" | grep -E '^/' | sort -u >> frontend_routes.txt
    sort -u frontend_routes.txt -o frontend_routes.txt 2>/dev/null

    # API base URLs
    grep -RhoE "baseURL\s*[:=]\s*['\"]([^'\"]{5,})['\"]" js_files/ 2>/dev/null | grep -oE "https?://[^'\"]*" | sort -u > api_base_urls.txt

    # axios / fetch endpoints
    grep -RhoE "axios\.(get|post|put|patch|delete)\(['\"]([^'\"]+)" js_files/ 2>/dev/null | grep -oE "['\"][^'\"]{2,}['\"]" | tr -d "'\"" | sort -u > axios_endpoints.txt
    grep -RhoE "fetch\(['\"]([^'\"]{5,})['\"]" js_files/ 2>/dev/null | grep -oE "['\"][^'\"]+['\"]" | tr -d "'\"" | sort -u >> axios_endpoints.txt
    sort -u axios_endpoints.txt -o axios_endpoints.txt 2>/dev/null

    print_success "Routes: $(wc -l < frontend_routes.txt 2>/dev/null||echo 0)  API bases: $(wc -l < api_base_urls.txt 2>/dev/null||echo 0)  axios/fetch: $(wc -l < axios_endpoints.txt 2>/dev/null||echo 0)"

    # GraphQL operations
    print_info "Extracting GraphQL operations..."
    grep -RhoE '(query|mutation|subscription)\s+[A-Za-z][A-Za-z0-9_]+\s*[({]' js_files/ 2>/dev/null | sort -u > graphql_operations.txt
    grep -iE '^query'        graphql_operations.txt > graphql_queries.txt    2>/dev/null
    grep -iE '^mutation'     graphql_operations.txt > graphql_mutations.txt  2>/dev/null
    grep -iE '^subscription' graphql_operations.txt > graphql_subscriptions.txt 2>/dev/null
    grep -iE '(delete|remove|update|admin|role|permission|payment|user|impersonate|upload|grant|revoke|disable|reset|change|create)' \
        graphql_mutations.txt 2>/dev/null | sort -u > graphql_high_risk.txt
    # Introspection command stubs
    [ -s BIGRAC.txt ] && grep -iE '/(graphql|graphiql|__schema)' BIGRAC.txt | head -10 | while IFS= read -r u; do
        echo "curl -i -k -X POST \"$u\" -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}"
    done > graphql_introspection_cmds.txt 2>/dev/null
    print_success "GraphQL — queries: $(wc -l < graphql_queries.txt 2>/dev/null||echo 0)  mutations: $(wc -l < graphql_mutations.txt 2>/dev/null||echo 0)  high-risk: $(wc -l < graphql_high_risk.txt 2>/dev/null||echo 0)"
    [ -s graphql_high_risk.txt ] && { echo -e "    ${RED}HIGH-RISK mutations:${NC}"; cat graphql_high_risk.txt | while IFS= read -r l; do echo -e "    ${RED}►${NC} $l"; done; }
}

# ─── 4. Secret Classification + Cloud Buckets + Mobile Configs ─
step_secret_cloud_intelligence() {
    # Secret classification
    local src_args=()
    [ -s js_analysis/jsluice_secrets.txt ]   && src_args+=("js_analysis/jsluice_secrets.txt")
    [ -s js_analysis/js_secrets_regex.txt ]  && src_args+=("js_analysis/js_secrets_regex.txt")
    [ -s secrets_found.txt ]                 && src_args+=("secrets_found.txt")
    if [ ${#src_args[@]} -gt 0 ]; then
        mkdir -p secret_classification
        grep -hiE 'sk_(live|test)_[a-zA-Z0-9]{20,}'                              "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/stripe_keys.txt
        grep -hiE 'AIza[0-9A-Za-z_-]{35}'                                         "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/google_api_keys.txt
        grep -hiE '"(apiKey|authDomain|databaseURL|storageBucket|appId)"\s*:'     "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/firebase_configs.txt
        grep -hiE '(AKIA|ASIA|AROA)[A-Z0-9]{16}'                                  "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/aws_access_keys.txt
        grep -hiE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.'                       "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/jwt_tokens.txt
        grep -hiE 'Bearer [a-zA-Z0-9_.\-]{20,}'                                   "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/bearer_tokens.txt
        grep -hiE 'gh[a-z]_[A-Za-z0-9_]{36,}'                                     "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/github_tokens.txt
        grep -hiE 'xox[baprs]-[0-9A-Za-z-]{20,}'                                  "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/slack_tokens.txt
        grep -hiE '-----BEGIN (RSA|EC|PRIVATE|OPENSSH) PRIVATE KEY'               "${src_args[@]}" 2>/dev/null | sort -u > secret_classification/private_keys.txt
        find secret_classification/ -type f -empty -delete 2>/dev/null
        local sc_count=0
        for f in secret_classification/*.txt; do [ -s "$f" ] && sc_count=$((sc_count+$(wc -l <"$f"))); done
        [ $sc_count -gt 0 ] && { print_success "Secrets classified: $sc_count  →  secret_classification/"; for f in secret_classification/*.txt; do [ -s "$f" ] && echo -e "    ${RED}►${NC} $(basename "$f"): $(wc -l <"$f")"; done; } || print_info "No known secret patterns matched"
    else
        print_info "No secret files to classify (run -secret or -jsdeep)"
    fi

    # Cloud bucket extraction
    local all_src=()
    [ -s allurls.txt ]  && all_src+=("allurls.txt")
    [ -s BIGRAC.txt ]   && all_src+=("BIGRAC.txt")
    [ -d js_files ]     && mapfile -t js_f < <(find js_files -type f 2>/dev/null) && all_src+=("${js_f[@]}")
    if [ ${#all_src[@]} -gt 0 ]; then
        {
            grep -hoE '[a-zA-Z0-9._-]+\.s3\.amazonaws\.com'              "${all_src[@]}" 2>/dev/null | sed 's/^/https:\/\//'
            grep -hoE '[a-zA-Z0-9._-]+\.s3-[a-z0-9-]+\.amazonaws\.com'  "${all_src[@]}" 2>/dev/null | sed 's/^/https:\/\//'
            grep -hoE 's3://[a-zA-Z0-9._-]+'                             "${all_src[@]}" 2>/dev/null
            grep -hoE '[a-zA-Z0-9._-]+\.blob\.core\.windows\.net'        "${all_src[@]}" 2>/dev/null | sed 's/^/https:\/\//'
            grep -hoE 'storage\.googleapis\.com/[a-zA-Z0-9._-]+'         "${all_src[@]}" 2>/dev/null | sed 's/^/https:\/\//'
            grep -hoE '[a-zA-Z0-9._-]+\.firebaseio\.com'                 "${all_src[@]}" 2>/dev/null | sed 's/^/https:\/\//'
            grep -hoE '[a-zA-Z0-9._-]+\.firebasestorage\.app'            "${all_src[@]}" 2>/dev/null | sed 's/^/https:\/\//'
        } | sort -u > cloud_buckets.txt 2>/dev/null
        [ -s cloud_buckets.txt ] && print_success "Cloud buckets: $(wc -l < cloud_buckets.txt)" || print_info "No cloud buckets found"
    fi

    # Mobile / SDK config hunter
    mkdir -p mobile_configs
    local msrc_args=("${all_src[@]}")
    [ ${#msrc_args[@]} -gt 0 ] && {
        grep -hiE '"apiKey"\s*:\s*"[^"]+".*"authDomain"'                   "${msrc_args[@]}" 2>/dev/null | sort -u > mobile_configs/firebase.txt
        grep -hiE '(DSN|dsn).*sentry\.io'                                  "${msrc_args[@]}" 2>/dev/null | sort -u > mobile_configs/sentry_dsn.txt
        grep -hiE 'mixpanel\.(init|track)|mixpanel\.token'                 "${msrc_args[@]}" 2>/dev/null | sort -u > mobile_configs/mixpanel.txt
        grep -hiE 'analytics\.load\("[^"]+"\)'                             "${msrc_args[@]}" 2>/dev/null | sort -u > mobile_configs/segment.txt
        grep -hiE '(OneSignal\.init|onesignal.*appId)'                     "${msrc_args[@]}" 2>/dev/null | sort -u > mobile_configs/onesignal.txt
        grep -hiE '(AppCenter|appcenter).*secret'                          "${msrc_args[@]}" 2>/dev/null | sort -u > mobile_configs/appcenter.txt
        find mobile_configs/ -type f -empty -delete 2>/dev/null
        local mc_count; mc_count=$(find mobile_configs/ -type f | wc -l 2>/dev/null || echo 0)
        [ "$mc_count" -gt 0 ] && print_success "Mobile SDK configs found: $mc_count types  →  mobile_configs/" || print_info "No mobile SDK configs detected"
    }
}

# ─── 5. IDOR Clusters + Backup Mutations + Tech Playbooks ────
step_pattern_intelligence() {
    # IDOR cluster builder
    if [ -s allurls.txt ]; then
        print_info "Building IDOR clusters..."
        sed -E 's|/[0-9]{1,12}(/|$)|/{id}\1|g; s|=[0-9]{1,12}(&|$)|={id}\1|g' allurls.txt | sort | uniq -c | sort -rn | awk '$1>1{print $1,$2}' > idor_patterns.txt
        grep -oE '/(user|order|ticket|account|invoice|product|document|report|project|message|thread|comment|payment|transfer|member|customer|admin)[s]?/[0-9a-fA-F_-]{1,40}' allurls.txt | sort -u > object_id_endpoints.txt
        print_success "IDOR patterns: $(wc -l < idor_patterns.txt 2>/dev/null||echo 0)  object+id: $(wc -l < object_id_endpoints.txt 2>/dev/null||echo 0)"
        [ -s idor_patterns.txt ] && head -5 idor_patterns.txt | while IFS= read -r l; do echo -e "    ${YELLOW}►${NC} $l"; done
    fi

    # Backup URL mutations (generate candidates only)
    print_info "Generating backup URL mutations..."
    {
        [ -s BIGRAC.txt ]   && cat BIGRAC.txt
        [ -s allurls.txt ]  && grep -E '\.(php|asp|aspx|jsp|py|rb|xml|json|conf|config|yaml|yml|sql|db|bak)' allurls.txt | head -200
    } | sort -u | head -300 | while IFS= read -r url; do
        echo "${url}.bak"
        echo "${url}.old"
        echo "${url}.backup"
        echo "${url}~"
        echo "${url}.orig"
        echo "${url}.zip"
        echo "${url}.tar.gz"
        local b; b=$(echo "$url" | sed 's/\.[^.?#]*$//')
        echo "${b}.bak"
        echo "${b}.old"
    done | sort -u > backup_url_candidates.txt 2>/dev/null
    print_success "Backup URL candidates: $(wc -l < backup_url_candidates.txt 2>/dev/null||echo 0)"

    # Tech-specific playbooks
    if [ -s tech_detect.txt ]; then
        print_info "Generating tech-specific playbooks..."
        mkdir -p playbooks
        local tech; tech=$(tr '[]' '\n' < tech_detect.txt | sort -u | tr '[:upper:]' '[:lower:]')
        echo "$tech" | grep -qiE 'asp\.net|aspnet' && printf '/elmah.axd\n/trace.axd\n/swagger\n/api\n/.well-known/openid-configuration\n/api/values\n/api/info\n/api/swagger\n/api/version\n/_framework/blazor.server.js\n' > playbooks/aspnet.txt
        echo "$tech" | grep -qi 'spring'           && printf '/actuator\n/actuator/env\n/actuator/health\n/actuator/metrics\n/actuator/mappings\n/actuator/logfile\n/actuator/heapdump\n/swagger-ui.html\n/v2/api-docs\n/actuator/beans\n/actuator/httptrace\n' > playbooks/spring.txt
        echo "$tech" | grep -qi 'laravel'          && printf '/.env\n/storage/logs/laravel.log\n/api/user\n/telescope\n/horizon\n/api/documentation\n/_ignition/health-check\n/phpinfo.php\n' > playbooks/laravel.txt
        echo "$tech" | grep -qiE 'wordpress|wp-'  && printf '/wp-admin\n/wp-login.php\n/wp-json/wp/v2/users\n/xmlrpc.php\n/wp-content/debug.log\n/?author=1\n/wp-json/\n/wp-config.php.bak\n/wp-admin/admin-ajax.php\n' > playbooks/wordpress.txt
        echo "$tech" | grep -qi 'jenkins'          && printf '/script\n/scriptText\n/computer/api/json\n/credentials/api/json\n/queue/api/json\n/asynchPeople/api/json\n/people/api/json\n/api/json\n/systemInfo\n/manage\n' > playbooks/jenkins.txt
        echo "$tech" | grep -qi 'grafana'          && printf '/api/users\n/api/datasources\n/api/admin/users\n/api/snapshots\n/api/org\n/api/org/users\n/api/dashboards/home\n/login\n/metrics\n' > playbooks/grafana.txt
        echo "$tech" | grep -qi 'kibana'           && printf '/.kibana\n/api/status\n/_cat/indices\n/_cluster/health\n/_cat/nodes\n/app/kibana\n/_nodes\n/_security/user\n' > playbooks/kibana.txt
        echo "$tech" | grep -qi 'django'           && printf '/admin\n/admin/login\n/api\n/api/v1\n/__debug__\n/static/admin\n/api-auth/login\n' > playbooks/django.txt
        echo "$tech" | grep -qi 'rails|ruby'       && printf '/rails/info\n/rails/mailers\n/rails/info/properties\n/rails/info/routes\n/admin\n/sidekiq\n' > playbooks/rails.txt
        find playbooks/ -type f -empty -delete 2>/dev/null

        # Build live URLs from playbooks × live hosts
        if [ -d playbooks ] && [ -s live_hosts.txt ]; then
            > playbook_targets.txt
            for pb in playbooks/*.txt; do
                [ -s "$pb" ] || continue
                while IFS= read -r host; do
                    while IFS= read -r path; do
                        echo "${host%/}${path}"
                    done < "$pb"
                done < live_hosts.txt
            done | sort -u >> playbook_targets.txt
            print_success "Tech playbook targets: $(wc -l < playbook_targets.txt)  →  playbook_targets.txt"
        fi
        local pb_count; pb_count=$(find playbooks/ -type f | wc -l 2>/dev/null || echo 0)
        print_success "Playbooks generated: $pb_count  →  playbooks/"
    else
        print_info "No tech_detect.txt — playbooks skipped"
    fi
}

# ─── 6. Historical Diff + Wordlist Learning ──────────────────
step_diff_and_learning() {
    local snap_dir=".tyrion_snapshots"
    local snap_file="$snap_dir/last.tar.gz"

    # Historical diff
    if [ -f "$snap_file" ]; then
        print_info "Running historical diff..."
        local tmp_prev; tmp_prev=$(mktemp -d)
        tar -xzf "$snap_file" -C "$tmp_prev" 2>/dev/null
        local total_new=0
        for f in all_subs.txt live_hosts.txt allurls.txt javascript.txt BIGRAC.txt; do
            [ -f "$f" ] || continue
            local prev="$tmp_prev/$f"
            [ -f "$prev" ] || continue
            comm -23 <(sort "$f") <(sort "$prev") > "diff_new_${f}" 2>/dev/null
            comm -23 <(sort "$prev") <(sort "$f")  > "diff_removed_${f}" 2>/dev/null
            local nc; nc=$(wc -l < "diff_new_${f}" 2>/dev/null || echo 0)
            [ "$nc" -gt 0 ] && { print_success "NEW in $f: $nc items"; total_new=$((total_new+nc)); head -5 "diff_new_${f}" | while IFS= read -r l; do echo -e "    ${GREEN}+${NC} $l"; done; }
            [ -s "diff_removed_${f}" ] && print_info "REMOVED from $f: $(wc -l < "diff_removed_${f}")"
            find . -maxdepth 1 -name "diff_new_${f}" -empty -delete 2>/dev/null
            find . -maxdepth 1 -name "diff_removed_${f}" -empty -delete 2>/dev/null
        done
        rm -rf "$tmp_prev"
        [ $total_new -gt 0 ] && print_success "Total new items since last scan: $total_new" || print_info "No new items since last scan"
    else
        print_info "No previous snapshot — this run is the baseline"
    fi
    # Save snapshot
    mkdir -p "$snap_dir"
    tar -czf "$snap_file" all_subs.txt live_hosts.txt allurls.txt javascript.txt BIGRAC.txt 2>/dev/null
    print_success "Snapshot saved → $snap_file"

    # Wordlist self-learning
    local tyrion_db="$HOME/.tyrion404"
    mkdir -p "$tyrion_db"
    [ -s all_subs.txt ] && sed "s/\.$DOMAIN$//" all_subs.txt | tr '-.' '\n\n' | grep -E '^[a-z][a-z0-9]{1,}$' >> "$tyrion_db/words.txt"
    [ -s allurls.txt ]  && grep -oE '/[a-zA-Z][a-zA-Z0-9_-]{2,}' allurls.txt | tr -d '/' | tr '[:upper:]' '[:lower:]' >> "$tyrion_db/words.txt"
    sort -u "$tyrion_db/words.txt" 2>/dev/null | grep -E '^[a-z][a-z0-9-]{2,25}$' | sort | uniq -c | sort -rn | awk '$1>=2{print $2}' > "$tyrion_db/tyrion_wordlist.txt"
    print_success "Self-learning wordlist: $(wc -l < "$tyrion_db/tyrion_wordlist.txt" 2>/dev/null||echo 0) words  →  $tyrion_db/tyrion_wordlist.txt"
}

# ─── 7. Report Pack Generator + Recon Summary ────────────────
step_report_pack() {
    mkdir -p REPORT_PACK
    local ts; ts=$(get_timestamp)

    # scope_summary.md
    cat > REPORT_PACK/scope_summary.md <<EOF
# Scope Summary: $DOMAIN
**Date:** $ts
| Metric | Count |
|--------|-------|
| Subdomains | $(wc -l < all_subs.txt 2>/dev/null||echo 0) |
| Live Hosts | $(wc -l < live_hosts.txt 2>/dev/null||echo 0) |
| Total URLs | $(wc -l < allurls.txt 2>/dev/null||echo 0) |
| JS Files | $(wc -l < javascript.txt 2>/dev/null||echo 0) |
| BIGRAC/API | $(wc -l < BIGRAC.txt 2>/dev/null||echo 0) |
| Parameters | $(wc -l < all_parameters.txt 2>/dev/null||echo 0) |
EOF

    # top_targets.md
    {
        echo "# Top Targets: $DOMAIN"
        echo ""
        echo "## HIGH Priority"
        [ -s attack_surface/HIGH_VALUE.txt ]   && head -30 attack_surface/HIGH_VALUE.txt | while IFS= read -r u; do echo "- $u"; done
        echo ""
        echo "## Top 50 Scored URLs"
        [ -s url_scores.txt ] && head -50 url_scores.txt | awk '{$1=""; print "- ["$0"]()"}'
    } > REPORT_PACK/top_targets.md

    # api_surface.md
    {
        echo "# API Surface: $DOMAIN"
        echo ""
        echo "## BIGRAC / Sensitive Endpoints"
        [ -s BIGRAC.txt ] && cat BIGRAC.txt | while IFS= read -r u; do echo "- $u"; done
        echo ""
        echo "## Swagger / OpenAPI Endpoints"
        [ -s swagger_endpoints.txt ] && cat swagger_endpoints.txt | while IFS= read -r u; do echo "- $u"; done
        echo ""
        echo "## GraphQL"
        [ -s graphql_queries.txt ]   && { echo "### Queries"; cat graphql_queries.txt | while IFS= read -r l; do echo "- $l"; done; }
        [ -s graphql_mutations.txt ] && { echo "### Mutations"; cat graphql_mutations.txt | while IFS= read -r l; do echo "- $l"; done; }
        [ -s graphql_high_risk.txt ] && { echo "### HIGH RISK Mutations"; cat graphql_high_risk.txt | while IFS= read -r l; do echo "- **$l**"; done; }
    } > REPORT_PACK/api_surface.md

    # auth_surface.md
    {
        echo "# Auth Surface: $DOMAIN"
        echo ""
        echo "## Auth Endpoints"
        [ -s auth_surface/auth_endpoints.txt ] && cat auth_surface/auth_endpoints.txt | while IFS= read -r u; do echo "- $u"; done
        echo ""
        echo "## Auth Providers Detected"
        [ -s auth_surface/auth_providers.txt ] && cat auth_surface/auth_providers.txt | while IFS= read -r l; do echo "- $l"; done
    } > REPORT_PACK/auth_surface.md

    # js_findings.md
    {
        echo "# JS Intelligence: $DOMAIN"
        echo ""
        echo "## Routes Found"
        [ -s frontend_routes.txt ] && head -50 frontend_routes.txt | while IFS= read -r r; do echo "- $r"; done
        echo ""
        echo "## API Base URLs"
        [ -s api_base_urls.txt ] && cat api_base_urls.txt | while IFS= read -r u; do echo "- $u"; done
        echo ""
        echo "## Secret Classification"
        if [ -d secret_classification ]; then
            for f in secret_classification/*.txt; do
                [ -s "$f" ] && echo "### $(basename "$f")" && head -5 "$f" | while IFS= read -r l; do echo "- \`$l\`"; done
            done
        fi
        echo ""
        echo "## Cloud Buckets"
        [ -s cloud_buckets.txt ] && cat cloud_buckets.txt | while IFS= read -r u; do echo "- $u"; done
    } > REPORT_PACK/js_findings.md

    # bug_candidates.md
    {
        echo "# Bug Hunt Candidates: $DOMAIN"
        echo ""
        for class in idor ssrf xss open_redirect lfi sqli; do
            local f="bug_hunt/${class}_candidates.txt"
            [ -s "$f" ] && { echo "## ${class^^}"; head -20 "$f" | while IFS= read -r u; do echo "- $u"; done; echo ""; }
        done
        echo "## IDOR Patterns (top clusters)"
        [ -s idor_patterns.txt ] && head -20 idor_patterns.txt | while IFS= read -r l; do echo "- $l"; done
        echo ""
        echo "## Object+ID Endpoints"
        [ -s object_id_endpoints.txt ] && head -20 object_id_endpoints.txt | while IFS= read -r l; do echo "- $l"; done
    } > REPORT_PACK/bug_candidates.md

    # commands_to_test.md
    {
        echo "# Commands to Test: $DOMAIN"
        echo ""
        echo "## Curl Commands (TOP targets)"
        echo '```bash'
        [ -s curl_commands.txt ] && head -30 curl_commands.txt
        echo '```'
        echo ""
        echo "## 403/401 Bypass Candidates"
        [ -s bypass_403_candidates.txt ] && head -20 bypass_403_candidates.txt | while IFS= read -r u; do echo "- $u"; done
        echo ""
        echo "## Tech Playbook Targets"
        [ -s playbook_targets.txt ] && head -30 playbook_targets.txt | while IFS= read -r u; do echo "- $u"; done
        echo ""
        echo "## GraphQL Introspection"
        [ -s graphql_introspection_cmds.txt ] && cat graphql_introspection_cmds.txt | while IFS= read -r l; do echo '```bash'; echo "$l"; echo '```'; done
        echo ""
        echo "## Backup URL Candidates (sample)"
        [ -s backup_url_candidates.txt ] && head -20 backup_url_candidates.txt | while IFS= read -r u; do echo "- $u"; done
    } > REPORT_PACK/commands_to_test.md

    print_success "Report pack generated  →  REPORT_PACK/"
    for f in REPORT_PACK/*.md; do echo -e "    ${CYAN}►${NC} $(basename "$f")"; done

    # Smart terminal summary
    echo ""
    echo -e "${BOLD}${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${RED}║             TYRION404 — SMART RECON SUMMARY              ║${NC}"
    echo -e "${BOLD}${RED}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}${CYAN}Target:${NC} ${BOLD}$DOMAIN${NC}  |  ${BOLD}${CYAN}Date:${NC} $ts"
    echo ""
    echo -e "  ${BOLD}${BLUE}── Surface ──────────────────────────────────────────${NC}"
    [ -s all_subs.txt ]     && echo -e "  ${GREEN}►${NC} Subdomains:      ${BOLD}$(wc -l < all_subs.txt)${NC}"
    [ -s live_hosts.txt ]   && echo -e "  ${GREEN}►${NC} Live Hosts:      ${BOLD}$(wc -l < live_hosts.txt)${NC}"
    [ -s allurls.txt ]      && echo -e "  ${GREEN}►${NC} URLs:            ${BOLD}$(wc -l < allurls.txt)${NC}"
    [ -s BIGRAC.txt ]       && echo -e "  ${GREEN}►${NC} BIGRAC/API:      ${BOLD}$(wc -l < BIGRAC.txt)${NC}"
    [ -s all_parameters.txt ] && echo -e "  ${GREEN}►${NC} Parameters:     ${BOLD}$(wc -l < all_parameters.txt)${NC}"
    echo ""
    echo -e "  ${BOLD}${BLUE}── Intelligence ─────────────────────────────────────${NC}"
    [ -s TOP_100_TARGETS.txt ]           && echo -e "  ${RED}►${NC} TOP targets:     ${BOLD}$(wc -l < TOP_100_TARGETS.txt)${NC}"
    [ -s attack_surface/HIGH_VALUE.txt ] && echo -e "  ${RED}►${NC} HIGH-value URLs: ${BOLD}$(wc -l < attack_surface/HIGH_VALUE.txt)${NC}"
    [ -s high_value_panels.txt ]         && echo -e "  ${RED}►${NC} Panels detected: ${BOLD}$(wc -l < high_value_panels.txt)${NC}"
    [ -s graphql_high_risk.txt ]         && echo -e "  ${RED}►${NC} GraphQL high-risk mutations: ${BOLD}$(wc -l < graphql_high_risk.txt)${NC}"
    [ -s object_id_endpoints.txt ]       && echo -e "  ${YELLOW}►${NC} IDOR candidates: ${BOLD}$(wc -l < object_id_endpoints.txt)${NC}"
    [ -s bug_hunt/ssrf_candidates.txt ]  && echo -e "  ${YELLOW}►${NC} SSRF candidates: ${BOLD}$(wc -l < bug_hunt/ssrf_candidates.txt)${NC}"
    [ -s bug_hunt/xss_candidates.txt ]   && echo -e "  ${YELLOW}►${NC} XSS  candidates: ${BOLD}$(wc -l < bug_hunt/xss_candidates.txt)${NC}"
    [ -s cloud_buckets.txt ]             && echo -e "  ${YELLOW}►${NC} Cloud buckets:   ${BOLD}$(wc -l < cloud_buckets.txt)${NC}"
    [ -d secret_classification ]         && { local stot=0; for sf in secret_classification/*.txt; do [ -s "$sf" ] && stot=$((stot+$(wc -l <"$sf"))); done; [ $stot -gt 0 ] && echo -e "  ${RED}►${NC} Secrets found:  ${BOLD}$stot${NC}"; }
    echo ""
    echo -e "  ${BOLD}${BLUE}── Start Here ───────────────────────────────────────${NC}"
    [ -s BIGRAC.txt ]       && { echo -e "  ${BOLD}1.${NC} BIGRAC endpoints:"; head -3 BIGRAC.txt | while IFS= read -r u; do echo -e "     ${CYAN}→${NC} $u"; done; }
    [ -s TOP_100_TARGETS.txt ] && { echo -e "  ${BOLD}2.${NC} Top targets:"; head -3 TOP_100_TARGETS.txt | while IFS= read -r u; do echo -e "     ${CYAN}→${NC} $u"; done; }
    [ -s auth_surface/auth_endpoints.txt ] && { echo -e "  ${BOLD}3.${NC} Auth endpoints:"; head -3 auth_surface/auth_endpoints.txt | while IFS= read -r u; do echo -e "     ${CYAN}→${NC} $u"; done; }
    echo ""
    echo -e "  ${DIM}Full report → REPORT_PACK/   |   Curls → curl_commands.txt${NC}"
    echo ""
}

# ═════════════════════════════════════════════════════════════
# NETWORK INTELLIGENCE — flag-gated (makes HTTP requests)
# ═════════════════════════════════════════════════════════════

step_sitemap_robots() {
    if [ ! -s live_hosts.txt ]; then print_warning "No live hosts"; return; fi
    > robots_interesting.txt; > sitemaps_found.txt
    while IFS= read -r host; do
        local robots; robots=$(curl -sk --max-time 10 "${host%/}/robots.txt" 2>/dev/null)
        echo "$robots" | grep -qiE '^(Disallow|Sitemap|Allow):' || continue
        echo "$robots" | awk '/^Disallow:/{print $2}' | grep -v '^/$' | while IFS= read -r p; do echo "${host%/}${p}"; done >> robots_interesting.txt
        echo "$robots" | awk '/^Sitemap:/{print $2}' >> sitemaps_found.txt
    done < <(head -30 live_hosts.txt)
    [ -s sitemaps_found.txt ] && while IFS= read -r sm; do
        curl -sk --max-time 15 "$sm" 2>/dev/null | grep -oE '<loc>[^<]+</loc>' | sed 's/<.?loc>//g' >> robots_interesting.txt
    done < sitemaps_found.txt
    sort -u robots_interesting.txt -o robots_interesting.txt 2>/dev/null
    print_success "Robots/Sitemap: $(wc -l < robots_interesting.txt 2>/dev/null||echo 0) paths   sitemaps: $(wc -l < sitemaps_found.txt 2>/dev/null||echo 0)"
}

step_exposure_verifier() {
    if [ ! -s BIGRAC.txt ]; then print_warning "BIGRAC.txt empty"; return; fi
    print_info "Verifying $(wc -l < BIGRAC.txt) sensitive endpoints..."
    > verified_exposures.txt
    while IFS= read -r url; do
        local resp; resp=$(curl -sk --max-time 10 -I "$url" 2>/dev/null)
        local status; status=$(echo "$resp" | grep -oP 'HTTP/[^ ]+ \K[0-9]+' | tail -1)
        local ct; ct=$(echo "$resp" | grep -i 'content-type:' | head -1 | cut -d: -f2 | tr -d ' \r\n' | cut -d';' -f1)
        [ -n "$status" ] && echo "$status  $ct  $url" >> verified_exposures.txt
    done < <(head -150 BIGRAC.txt)
    # Sort 200s first
    { grep -E '^200' verified_exposures.txt; grep -E '^(401|403)' verified_exposures.txt; grep -E '^500' verified_exposures.txt; grep -vE '^(200|401|403|500)' verified_exposures.txt; } | sort -u > tmp_ve.txt && mv tmp_ve.txt verified_exposures.txt
    print_success "Verified: $(wc -l < verified_exposures.txt) results"
    grep -E '^200' verified_exposures.txt | head -10 | while IFS= read -r l; do echo -e "    ${RED}►${NC} $l"; done
}

step_swagger_parser() {
    if [ ! -s BIGRAC.txt ] || ! command -v jq &>/dev/null; then print_warning "BIGRAC.txt empty or jq missing"; return; fi
    mkdir -p swagger_parsed
    > swagger_endpoints.txt; > swagger_curls.txt; > unauth_possible_endpoints.txt
    local found=0
    while IFS= read -r url; do
        local tmp; tmp=$(mktemp)
        curl -sk --max-time 15 "$url" -o "$tmp" 2>/dev/null
        jq . "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; continue; }
        local fname; fname=$(echo "$url" | sed 's|[/:?=&]|_|g' | cut -c1-80)
        cp "$tmp" "swagger_parsed/${fname}.json"
        local base; base=$(jq -r '.servers[0].url // ""' "$tmp" 2>/dev/null)
        [ -z "$base" ] && base=$(echo "$url" | sed 's|/[^/]*$||')
        jq -r --arg b "$base" '.paths // {} | to_entries[] | .key as $p | .value | to_entries[] | select(.key|test("^(get|post|put|patch|delete)$")) | "\(.key|ascii_upcase) \($b)\($p)"' "$tmp" 2>/dev/null >> swagger_endpoints.txt
        jq -r --arg b "$base" '.paths // {} | to_entries[] | .key as $p | .value | to_entries[] | select(.key|test("^(get|post|put|patch|delete)$")) | "curl -i -k -X \(.key|ascii_upcase) \"\($b)\($p)\""' "$tmp" 2>/dev/null >> swagger_curls.txt
        # Unauthenticated — no security on operation
        jq -r --arg b "$base" '.paths // {} | to_entries[] | .key as $p | .value | to_entries[] | select((.key|test("^(get|post|put|patch|delete)$")) and (.value.security == [] or .value.security == null)) | "\(.key|ascii_upcase) \($b)\($p)"' "$tmp" 2>/dev/null >> unauth_possible_endpoints.txt
        rm -f "$tmp"
        found=$((found+1))
    done < <(grep -iE '(swagger|openapi|api-docs)(\.json|\.yaml|\.yml|$|\?)' BIGRAC.txt | head -20)
    sort -u swagger_endpoints.txt -o swagger_endpoints.txt 2>/dev/null
    sort -u unauth_possible_endpoints.txt -o unauth_possible_endpoints.txt 2>/dev/null
    print_success "Swagger specs: $found  endpoints: $(wc -l < swagger_endpoints.txt)  curls: $(wc -l < swagger_curls.txt)  possibly-unauth: $(wc -l < unauth_possible_endpoints.txt)"
    [ -s unauth_possible_endpoints.txt ] && { echo -e "    ${RED}Possibly unauthenticated:${NC}"; head -5 unauth_possible_endpoints.txt | while IFS= read -r l; do echo -e "    ${RED}►${NC} $l"; done; }
}

step_cors_checker() {
    if [ ! -s live_hosts.txt ]; then print_warning "No live hosts"; return; fi
    print_info "Checking CORS misconfigurations ($(wc -l < live_hosts.txt) hosts, sampling 50)..."
    > cors_misconfig_candidates.txt
    while IFS= read -r host; do
        for origin in "https://evil.com" "null" "https://${DOMAIN}.evil.com"; do
            local resp; resp=$(curl -sk --max-time 10 -H "Origin: $origin" -I "$host" 2>/dev/null)
            if echo "$resp" | grep -qi "access-control-allow-origin: $origin"; then
                echo "REFLECTS_ORIGIN  origin=$origin  $host" >> cors_misconfig_candidates.txt
            elif echo "$resp" | grep -qi "access-control-allow-origin: \*"; then
                echo "WILDCARD  $host" >> cors_misconfig_candidates.txt
            fi
            if echo "$resp" | grep -qi 'access-control-allow-credentials: true' && \
               echo "$resp" | grep -qi "access-control-allow-origin: $origin"; then
                echo "CRITICAL_CORS_WITH_CREDS  origin=$origin  $host" >> cors_misconfig_candidates.txt
            fi
        done
    done < <(head -50 live_hosts.txt)
    sort -u cors_misconfig_candidates.txt -o cors_misconfig_candidates.txt 2>/dev/null
    [ -s cors_misconfig_candidates.txt ] && { print_success "CORS issues: $(wc -l < cors_misconfig_candidates.txt)"; cat cors_misconfig_candidates.txt | while IFS= read -r l; do echo -e "    ${RED}►${NC} $l"; done; } || print_info "No CORS misconfigurations detected"
}

step_method_discovery() {
    local src="TOP_100_TARGETS.txt"; [ ! -s "$src" ] && src="BIGRAC.txt"
    [ ! -s "$src" ] && { print_warning "No targets for method discovery"; return; }
    print_info "Probing HTTP methods on $(wc -l < "$src") endpoints (sampling 40)..."
    > method_discovery.txt
    while IFS= read -r url; do
        local allowed; allowed=$(curl -sk --max-time 10 -X OPTIONS -I "$url" 2>/dev/null | grep -i '^Allow:' | head -1 | cut -d: -f2 | tr -d '\r\n' | xargs)
        [ -n "$allowed" ] && echo "$url  →  $allowed" >> method_discovery.txt
    done < <(head -40 "$src")
    [ -s method_discovery.txt ] && { print_success "Method discovery: $(wc -l < method_discovery.txt)"; cat method_discovery.txt | grep -iE 'DELETE|PUT|PATCH' | while IFS= read -r l; do echo -e "    ${RED}►${NC} $l"; done; } || print_info "No interesting methods discovered"
}

step_bypass_generator() {
    # Collect 401/403 URLs from httpx detailed output
    > tyrion_403_401.txt
    [ -s live_hosts_detailed.txt ] && grep -E '\[(401|403)\]' live_hosts_detailed.txt | awk '{print $1}' >> tyrion_403_401.txt
    [ -s verified_exposures.txt ]  && grep -E '^(401|403)' verified_exposures.txt | awk '{print $NF}' >> tyrion_403_401.txt
    sort -u tyrion_403_401.txt -o tyrion_403_401.txt 2>/dev/null

    if [ ! -s tyrion_403_401.txt ]; then print_warning "No 401/403 responses found to bypass"; return; fi
    print_info "Generating bypass payloads for $(wc -l < tyrion_403_401.txt) endpoints..."
    > bypass_403_candidates.txt
    while IFS= read -r url; do
        local path; path=$(echo "$url" | sed 's|https\?://[^/]*||')
        local base; base=$(echo "$url" | grep -oE 'https?://[^/]+')
        # Path bypass mutations
        printf '%s\n%s/\n%s/.\n%s?.\n%s#.\n%s%%20\n%s%%09\n%s..;/\n%%2e%s\n%s%%2f\n' \
            "$url" "$url" "$url" "$url" "$url" "$url" "$url" "$url" "$path" "$url" >> bypass_403_candidates.txt
        # Header bypass curl commands
        {
            echo "curl -i -k -H 'X-Original-URL: $path' \"$base/\""
            echo "curl -i -k -H 'X-Rewrite-URL: $path' \"$base/\""
            echo "curl -i -k -H 'X-Custom-IP-Authorization: 127.0.0.1' \"$url\""
            echo "curl -i -k -H 'X-Forwarded-For: 127.0.0.1' \"$url\""
            echo "curl -i -k -H 'X-Real-IP: 127.0.0.1' \"$url\""
            echo "curl -i -k -H 'Referer: https://$DOMAIN/admin' \"$url\""
        } >> bypass_403_curls.txt
    done < tyrion_403_401.txt
    sort -u bypass_403_candidates.txt -o bypass_403_candidates.txt 2>/dev/null
    print_success "Bypass candidates: $(wc -l < bypass_403_candidates.txt)  →  bypass_403_candidates.txt"
    print_success "Bypass curls:      $(wc -l < bypass_403_curls.txt)        →  bypass_403_curls.txt"
}

step_js_endpoint_validation() {
    local ep_file="reconstructed_endpoints/full_endpoints.txt"
    [ ! -s "$ep_file" ] && ep_file="js_analysis/js_paths.txt"
    [ ! -s "$ep_file" ] && { print_warning "No JS endpoints to validate (run -jsdeep first)"; return; }
    [ ! -s live_hosts.txt ] && { print_warning "No live hosts"; return; }
    local first_host; first_host=$(head -1 live_hosts.txt)
    print_info "Validating JS endpoints (sampling 200)..."
    > js_endpoints_validated.txt
    local c=0
    while IFS= read -r ep; do
        local url; echo "$ep" | grep -qE '^https?://' && url="$ep" || url="${first_host%/}${ep}"
        local st; st=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
        echo "$st  $url" >> js_endpoints_validated.txt
        c=$((c+1)); [ $c -ge 200 ] && break
    done < "$ep_file"
    { grep -E '^200' js_endpoints_validated.txt; grep -E '^(401|403)' js_endpoints_validated.txt; grep -E '^500' js_endpoints_validated.txt; } | sort -u > tmp_jv.txt && mv tmp_jv.txt js_endpoints_validated.txt
    print_success "JS validation: $(wc -l < js_endpoints_validated.txt) results (200:$(grep -c '^200' js_endpoints_validated.txt 2>/dev/null||echo 0) 401/403:$(grep -cE '^(401|403)' js_endpoints_validated.txt 2>/dev/null||echo 0) 500:$(grep -c '^500' js_endpoints_validated.txt 2>/dev/null||echo 0))"
}

step_api_discovery() {
    [ ! -s live_hosts.txt ] && { print_warning "No live hosts"; return; }
    local paths=("/api/v1" "/api/v2" "/api/v3" "/api/v4" "/api/internal" "/api/admin" "/api/debug" "/api/graphql" "/api/docs" "/api/swagger" "/api/openapi.json" "/api/v1/swagger.json" "/rest" "/v1" "/v2" "/v3" "/internal/api" "/api/private")
    print_info "API version/variant discovery on $(wc -l < live_hosts.txt) hosts (sampling 20)..."
    > api_discovery.txt
    while IFS= read -r host; do
        for path in "${paths[@]}"; do
            local url="${host%/}${path}"
            local st; st=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
            [[ "$st" =~ ^(200|201|301|302|401|403|405) ]] && echo "$st  $url" >> api_discovery.txt
        done
    done < <(head -20 live_hosts.txt)
    sort -u api_discovery.txt -o api_discovery.txt 2>/dev/null
    [ -s api_discovery.txt ] && { print_success "API discovery: $(wc -l < api_discovery.txt) live endpoints"; grep -E '^200' api_discovery.txt | while IFS= read -r l; do echo -e "    ${RED}►${NC} $l"; done; } || print_info "No API variants found"
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
main() {
    DOMAIN=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            -parallel)    ENABLE_PARALLEL=true; shift ;;
            -moreurls)    ENABLE_MOREURLS=true; shift ;;
            -dir)
                ENABLE_DIRSEARCH=true; shift
                [[ $# -gt 0 && ("$1" == /* || "$1" == ~*) ]] && { CUSTOM_WORDLIST="$1"; shift; }
                ;;
            -secret)      ENABLE_SECRETFINDER=true; shift ;;
            -takeover)    ENABLE_TAKEOVER=true; shift ;;
            -gf)          ENABLE_GF=true; shift ;;
            -grep)        ENABLE_GREP=true; shift ;;
            -port)        ENABLE_PORT_SCAN=true; shift ;;
            -gowitness)   ENABLE_GOWITNESS=true; shift ;;
            -bruteforce)  ENABLE_BRUTEFORCE=true; shift ;;
            -jsdeep)      ENABLE_JSDEEP=true; shift ;;
            -asn)         ENABLE_ASN=true; shift ;;
            -vhost)       ENABLE_VHOST=true; shift ;;
            -arjun)       ENABLE_ARJUN=true; shift ;;
            -nuclei)      ENABLE_NUCLEI_FULL=true; shift ;;
            -waf)         ENABLE_WAF=true; shift ;;
            -verify)      ENABLE_VERIFY=true; shift ;;
            -cors)        ENABLE_CORS=true; shift ;;
            -methods)     ENABLE_METHODS=true; shift ;;
            -bypass)      ENABLE_BYPASS=true; shift ;;
            -swagger)     ENABLE_SWAGGER=true; shift ;;
            -validate)    ENABLE_VALIDATE=true; shift ;;
            -apidisc)     ENABLE_APIDISC=true; shift ;;
            -sitemap)     ENABLE_SITEMAP=true; shift ;;
            -h|--help)    show_banner; usage ;;
            *)
                [ -z "$DOMAIN" ] && DOMAIN="$1" || { echo -e "${RED}Unknown: $1${NC}"; usage; }
                shift ;;
        esac
    done

    clear
    show_banner

    [ -z "$DOMAIN" ] && { print_error "No domain provided!"; usage; }

    OUTPUT_DIR="$DOMAIN"
    START_TIME=$(date +%s)
    calculate_total_steps

    echo -e "  ${BOLD}${CYAN}Target  :${NC} ${BOLD}$DOMAIN${NC}"
    echo -e "  ${BOLD}${CYAN}Steps   :${NC} ${BOLD}$TOTAL_STEPS${NC}"
    echo -e "  ${BOLD}${CYAN}Started :${NC} ${BOLD}$(get_timestamp)${NC}"
    echo -e "  ${DIM}${CYAN}─────────────────────────────────────────────────────${NC}"
    echo ""

    check_dependencies

    print_section "Creating Output Directory"
    if [ -f "${OUTPUT_DIR}/.checkpoint" ]; then
        print_warning "Resuming previous scan for $DOMAIN"
    elif [ -d "$OUTPUT_DIR" ] && [ -f "${OUTPUT_DIR}/all_subs.txt" ]; then
        print_warning "$DOMAIN already scanned — overwrite?"
        read -p "  Continue? (y/n): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && { print_error "Exiting"; exit 1; }
    else
        mkdir -p "$OUTPUT_DIR"
        print_success "Fresh scan: $DOMAIN"
    fi

    cd "$OUTPUT_DIR" || exit 1
    trap 'handle_interrupt' INT TERM
    trap 'handle_exit' EXIT
    checkpoint_init
    start_heartbeat

    failed_tools=()
    gowitness_count=0 brute_count=0 total_subs=0 live_hosts=0
    total_urls=0 param_count=0 js_count=0 php_count=0
    json_count=0 bigrac_count=0 dirsearch_count=0
    secret_count=0 takeover_count=0 port_count=0
    technologies="N/A"

    # ── Steps ─────────────────────────────────────────────────
    run_step "Subdomain Enumeration"                    "SUBDOMAIN_ENUM"   step_subdomain_enum
    [ "$ENABLE_BRUTEFORCE" = true ]   && run_step "Bruteforce + Permutations"          "BRUTEFORCE"       step_bruteforce
    run_step "DNS Resolution"                           "DNS_RESOLUTION"   step_dns_resolution
    run_step "Live Host Check"                          "LIVE_HOST_CHECK"  step_live_host_check
    [ "$ENABLE_WAF" = true ]          && run_step "WAF Detection"                      "WAF_DETECTION"    step_waf_detection
    [ "$ENABLE_ASN" = true ]          && run_step "ASN & Infrastructure Mapping"       "ASN_MAPPING"      step_asn_mapping
    [ "$ENABLE_GOWITNESS" = true ]    && run_step "Screenshot Live Hosts"              "GOWITNESS"        step_gowitness
    [ "$ENABLE_PORT_SCAN" = true ]    && run_step "Port Scanning"                      "PORT_SCANNING"    step_port_scan
    [ "$ENABLE_TAKEOVER" = true ]     && run_step "Subdomain Takeover Check"           "TAKEOVER"         step_takeover
    [ "$ENABLE_NUCLEI_FULL" = true ]  && run_step "Full Nuclei Scan"                   "NUCLEI_FULL"      step_nuclei_full
    [ "$ENABLE_VHOST" = true ]        && run_step "Virtual Host Discovery"             "VHOST"            step_vhost
    run_step "URL Gathering"                            "URL_GATHERING"    step_url_gathering
    run_step "Parameter Discovery"                      "PARAM_DISCOVERY"  step_param_discovery
    [ "$ENABLE_ARJUN" = true ]        && run_step "Deep Parameter Mining (Arjun)"      "ARJUN"            step_arjun
    run_step "JS & File Extraction"                     "JS_EXTRACTION"    step_js_extraction
    [ "$ENABLE_JSDEEP" = true ]       && run_step "JS Deep Analysis"                   "JSDEEP"           step_jsdeep
    [ "$ENABLE_GREP" = true ]         && run_step "Grep Juicy URLs"                    "GREP_JUICY"       step_grep_juicy
    [ "$ENABLE_GF" = true ]           && run_step "GF Vulnerability Patterns"          "GF_PATTERNS"      step_gf_patterns
    [ "$ENABLE_DIRSEARCH" = true ]    && run_step "Directory Bruteforce"               "DIR_BRUTEFORCE"   step_dirsearch
    [ "$ENABLE_SECRETFINDER" = true ] && run_step "Secret Finding in JavaScript"       "SECRET_FINDING"   step_secretfinder
    run_step "Auth Surface Detection"                   "AUTH_SURFACE"     step_auth_surface
    run_step "Bug Hunt Candidates"                      "BUG_HUNT"         step_bug_hunt_candidates
    run_step "Attack Surface Ranking"                   "ATTACK_SURFACE"   step_attack_surface_ranking

    # ── Intelligence Layer (always-on) ────────────────────────
    run_step "Response Clustering & Panel Detection"    "RESP_INTEL"       step_response_intelligence
    run_step "Target Scoring & Request Builder"         "SCORING"          step_target_scoring
    run_step "JS Route Mapper & GraphQL Extractor"      "JS_INTEL"         step_js_intelligence
    run_step "Secrets & Cloud & Mobile Intelligence"    "SECRET_CLOUD"     step_secret_cloud_intelligence
    run_step "IDOR Clusters & Backup Mutations & Playbooks" "PATTERN_INTEL" step_pattern_intelligence
    run_step "Historical Diff & Wordlist Learning"      "DIFF_LEARN"       step_diff_and_learning

    # ── Network Intelligence (flag-gated) ─────────────────────
    [ "$ENABLE_SITEMAP" = true ]  && run_step "Sitemap & Robots Intelligence"      "SITEMAP"     step_sitemap_robots
    [ "$ENABLE_VERIFY" = true ]   && run_step "Exposure Verifier"                  "VERIFY"      step_exposure_verifier
    [ "$ENABLE_SWAGGER" = true ]  && run_step "Swagger / OpenAPI Parser"           "SWAGGER"     step_swagger_parser
    [ "$ENABLE_CORS" = true ]     && run_step "CORS Misconfiguration Check"        "CORS"        step_cors_checker
    [ "$ENABLE_METHODS" = true ]  && run_step "HTTP Method Discovery"              "METHODS"     step_method_discovery
    [ "$ENABLE_BYPASS" = true ]   && run_step "403/401 Bypass Generator"           "BYPASS"      step_bypass_generator
    [ "$ENABLE_VALIDATE" = true ] && run_step "JS Endpoint Validation"             "VALIDATE"    step_js_endpoint_validation
    [ "$ENABLE_APIDISC" = true ]  && run_step "API Version Discovery"              "APIDISC"     step_api_discovery

    # ── Report Pack (always last) ─────────────────────────────
    run_step "Report Pack Generation"                   "REPORT_PACK"      step_report_pack

    # ── Summary ───────────────────────────────────────────────
    print_section "FINAL SUMMARY"
    local END_TIME; END_TIME=$(date +%s)
    local DUR=$(( END_TIME - START_TIME ))
    echo ""
    echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║            TYRION404  —  RECON COMPLETE               ║${NC}"
    echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Target:${NC}  ${BOLD}$DOMAIN${NC}"
    echo -e "  ${CYAN}Output:${NC}  ${BOLD}$OUTPUT_DIR/${NC}"
    echo -e "  ${CYAN}Time:${NC}    ${BOLD}$((DUR/60))m $((DUR%60))s${NC}"
    echo ""
    echo -e "${BOLD}${BLUE}Statistics:${NC}"
    echo -e "  ${GREEN}►${NC} Subdomains:            ${BOLD}${total_subs:-0}${NC}"
    echo -e "  ${GREEN}►${NC} Live Hosts:            ${BOLD}${live_hosts:-0}${NC}"
    echo -e "  ${GREEN}►${NC} Total URLs:            ${BOLD}${total_urls:-0}${NC}"
    echo -e "  ${GREEN}►${NC} JavaScript files:      ${BOLD}${js_count:-0}${NC}"
    echo -e "  ${GREEN}►${NC} PHP files:             ${BOLD}${php_count:-0}${NC}"
    echo -e "  ${GREEN}►${NC} JSON files:            ${BOLD}${json_count:-0}${NC}"
    echo -e "  ${GREEN}►${NC} BIGRAC/API endpoints:  ${BOLD}${bigrac_count:-0}${NC}"
    echo -e "  ${GREEN}►${NC} Parameters:            ${BOLD}${param_count:-0}${NC}"
    [ "$ENABLE_TAKEOVER" = true ]     && echo -e "  ${GREEN}►${NC} Takeover findings:    ${BOLD}${takeover_count:-0}${NC}"
    [ "$ENABLE_SECRETFINDER" = true ] && echo -e "  ${GREEN}►${NC} Secrets found:        ${BOLD}${secret_count:-0}${NC}"
    [ "$ENABLE_DIRSEARCH" = true ]    && echo -e "  ${GREEN}►${NC} Dirsearch 200s:       ${BOLD}${dirsearch_count:-0}${NC}"
    [ "$ENABLE_PORT_SCAN" = true ]    && echo -e "  ${GREEN}►${NC} Open ports:           ${BOLD}${port_count:-0}${NC}"
    [ "$ENABLE_GOWITNESS" = true ]    && echo -e "  ${GREEN}►${NC} Screenshots:          ${BOLD}${gowitness_count:-0}${NC}"
    echo ""

    echo -e "${BOLD}${BLUE}Generated Files:${NC}"
    _sf() { [ -s "$1" ] && echo -e "  ${CYAN}►${NC} ${BOLD}${1}${NC} — ${2} ${DIM}($(wc -l < "$1" 2>/dev/null||echo ?) lines)${NC}"; }
    _sd() { [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ] && echo -e "  ${CYAN}►${NC} ${BOLD}${1}/${NC} — ${2}"; }
    _sf "all_subs.txt"              "All unique subdomains"
    _sf "live_hosts.txt"            "Live hosts"
    _sf "live_hosts_detailed.txt"   "Live hosts (status+title+server+size)"
    _sf "tech_detect.txt"           "Technology fingerprints"
    _sf "cdncheck_results.txt"      "CDN / origin detection"
    _sf "tyrion_waf.txt"            "WAF detection results"
    _sf "asn.txt"                   "ASN information"
    _sf "cidrs.txt"                 "IP CIDRs from ASN"
    _sf "cloud_assets.txt"          "Cloud assets detected"
    _sf "allurls.txt"               "All URLs (deduplicated)"
    _sf "url_paths.txt"             "Unique URL paths (unfurl)"
    _sf "url_param_keys.txt"        "Unique param keys (unfurl)"
    _sf "params.txt"                "Parameters (ParamSpider)"
    _sf "arjun_params.txt"          "Parameters (Arjun)"
    _sf "all_parameters.txt"        "All params ranked by frequency"
    _sf "javascript.txt"            "JavaScript URLs"
    _sf "php.txt"                   "PHP URLs"
    _sf "json.txt"                  "JSON URLs"
    _sf "BIGRAC.txt"                "Sensitive/API endpoints"
    _sd "js_files"                  "Downloaded JS files"
    _sd "js_analysis"               "JS deep analysis (endpoints/params/secrets)"
    _sd "reconstructed_endpoints"   "Full endpoints built from JS paths"
    _sd "vhost_results"             "Virtual host discovery results"
    _sd "attack_surface"            "HIGH/MEDIUM/LOW ranked URLs"
    _sd "bug_hunt"                  "Bug hunt candidates by class"
    _sd "auth_surface"              "Auth endpoints & providers"
    _sd "grep_results"              "Juicy URLs by category"
    _sd "gf"                        "GF pattern results"
    _sd "gowitness_output"          "Screenshots + HTML report"
    _sf "tyrion_dirsearch.txt"      "Dirsearch results"
    _sf "tyrion_nuclei.txt"         "Nuclei scan results"
    _sf "takeover_results.txt"      "Subdomain takeover findings"
    _sf "secrets_found.txt"         "Secrets (SecretFinder)"
    _sf "open_ports.txt"            "Open ports (Naabu)"
    _sf "ports_detailed.txt"        "Port details (Nmap)"
    echo ""
    echo -e "${BOLD}${BLUE}Intelligence Layer:${NC}"
    _sf "TOP_100_TARGETS.txt"            "Top 100 scored attack targets"
    _sf "url_scores.txt"                 "All URLs with priority score"
    _sf "curl_commands.txt"              "Ready-to-run curl commands"
    _sf "burp_targets.txt"               "Burp Suite target list"
    _sf "response_clusters.txt"          "Response cluster groups"
    _sf "high_value_panels.txt"          "Jenkins/Grafana/Kibana panels"
    _sf "frontend_routes.txt"            "React/Angular/Vue routes from JS"
    _sf "api_base_urls.txt"              "API base URLs from JS"
    _sf "axios_endpoints.txt"            "axios/fetch endpoints"
    _sf "graphql_queries.txt"            "GraphQL queries"
    _sf "graphql_mutations.txt"          "GraphQL mutations"
    _sf "graphql_high_risk.txt"          "HIGH-RISK GraphQL mutations"
    _sf "graphql_introspection_cmds.txt" "Introspection curl stubs"
    _sd "secret_classification"          "Secrets by type (Stripe/AWS/JWT...)"
    _sf "cloud_buckets.txt"              "S3/Azure/GCP/Firebase buckets"
    _sd "mobile_configs"                 "Firebase/Sentry/Mixpanel/Segment"
    _sf "idor_patterns.txt"              "IDOR URL patterns (clustered)"
    _sf "object_id_endpoints.txt"        "Object+ID endpoints"
    _sf "backup_url_candidates.txt"      "Backup file URL mutations"
    _sd "playbooks"                      "Tech-specific attack paths"
    _sf "playbook_targets.txt"           "Full URLs from tech playbooks"
    _sf "swagger_endpoints.txt"          "Parsed Swagger/OpenAPI endpoints"
    _sf "swagger_curls.txt"              "curl per Swagger endpoint"
    _sf "unauth_possible_endpoints.txt"  "Possibly unauthenticated endpoints"
    _sf "verified_exposures.txt"         "Verified BIGRAC status codes"
    _sf "cors_misconfig_candidates.txt"  "CORS misconfiguration findings"
    _sf "method_discovery.txt"           "Interesting HTTP methods"
    _sf "bypass_403_candidates.txt"      "403/401 bypass URL mutations"
    _sf "bypass_403_curls.txt"           "Header-based bypass curls"
    _sf "js_endpoints_validated.txt"     "Live JS endpoints (HTTP verified)"
    _sf "api_discovery.txt"              "API versions (v1/v2/internal)"
    _sf "robots_interesting.txt"         "Disallowed paths from robots.txt"
    _sf "all_parameters.txt"             "All params ranked by frequency"
    _sd "REPORT_PACK"                    "Markdown report pack"
    echo ""

    if [ ${#failed_tools[@]} -gt 0 ]; then
        echo -e "${BOLD}${RED}Failed Tools:${NC}"
        for t in "${failed_tools[@]}"; do echo -e "  ${RED}✗${NC} $t"; done
        echo ""
    fi

    stop_heartbeat
    print_success "Tyrion404 — Reconnaissance complete!"
    rm -f "$CHECKPOINT_FILE" 2>/dev/null
    echo -e "${CYAN}Output: ${BOLD}$OUTPUT_DIR/${NC}\n"
}

main "$@"
