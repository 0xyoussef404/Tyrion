#!/bin/bash

# ============================================
#  0xMarvul RECON FLOW - Reconnaissance Tool
#  Author: 0xMarvul
#  Description: Automated reconnaissance tool for bug bounty and security assessments
# ============================================

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Discord Webhook Configuration
DISCORD_WEBHOOK="https://discord.com/api/webhooks/1451940045475807315/-6ecZ9WRgnY5GS-5iJ_BC0Cdus9L35BpBbIjsYRldmeQvOWYouGbddeTXJvWYKPQz5tg"
NOTIFY_ENABLED=true
START_TIME_EPOCH=$(date +%s)

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
CUSTOM_WORDLIST=""

# Step counter
TOTAL_STEPS=0
CURRENT_STEP=0

# Skip/Pause variables
CURRENT_TOOL_PID=""
CURRENT_TOOL_NAME=""
SCAN_PAUSED=false

# Checkpoint variables
CHECKPOINT_FILE=""
LAST_COMPLETED_KEY=""
CURRENT_RUNNING_KEY=""

# ─────────────────────────────────────────────────────────────
# Checkpoint functions
# ─────────────────────────────────────────────────────────────
checkpoint_save() {
    local key="$1"
    if [ -n "$CHECKPOINT_FILE" ]; then
        grep -qxF "${key}=done" "$CHECKPOINT_FILE" 2>/dev/null || echo "${key}=done" >> "$CHECKPOINT_FILE"
    fi
}

checkpoint_done() {
    local result=1
    if [ -f "$CHECKPOINT_FILE" ]; then
        grep -qxF "$1=done" "$CHECKPOINT_FILE" 2>/dev/null && result=0
    fi
    return $result
}

checkpoint_init() {
    CHECKPOINT_FILE=".checkpoint"
}

# ─────────────────────────────────────────────────────────────
# Interrupt / Exit handlers
# ─────────────────────────────────────────────────────────────
handle_interrupt() {
    echo ""
    stop_heartbeat
    if [ -n "$CURRENT_TOOL_PID" ]; then
        kill -- -${CURRENT_TOOL_PID} 2>/dev/null
        wait "$CURRENT_TOOL_PID" 2>/dev/null
        CURRENT_TOOL_PID=""
    fi
    if [ -n "$LAST_COMPLETED_KEY" ]; then
        checkpoint_save "$LAST_COMPLETED_KEY"
        print_warning "Scan interrupted — checkpoint saved up to: $LAST_COMPLETED_KEY"
    else
        print_warning "Scan interrupted — no completed steps to save"
    fi
    print_info "Run the same command again to resume"
    stty sane 2>/dev/null
    exit 1
}

handle_exit() {
    stty sane 2>/dev/null
}

# ─────────────────────────────────────────────────────────────
# Heartbeat — saves last completed step every 2s
# Covers power cuts, kill -9, Ctrl+Z
# ─────────────────────────────────────────────────────────────
start_heartbeat() {
    : # heartbeat removed — handle_interrupt trap handles checkpoint saving
}

stop_heartbeat() {
    if [ -n "$HEARTBEAT_PID" ]; then
        kill "$HEARTBEAT_PID" 2>/dev/null
        wait "$HEARTBEAT_PID" 2>/dev/null
        HEARTBEAT_PID=""
    fi
}

# ─────────────────────────────────────────────────────────────
# Step helper — checks checkpoint, prints header, sets keys
# Usage: run_step "LABEL" "KEY" <function_name>
# ─────────────────────────────────────────────────────────────
run_step() {
    local label="$1"
    local key="$2"
    local func="$3"


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

# ─────────────────────────────────────────────────────────────
# Step counter
# ─────────────────────────────────────────────────────────────
calculate_total_steps() {
    TOTAL_STEPS=6
    [ "$ENABLE_BRUTEFORCE" = true ]   && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_GOWITNESS" = true ]    && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_PORT_SCAN" = true ]    && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_TAKEOVER" = true ]     && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_GF" = true ]           && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_GREP" = true ]         && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_DIRSEARCH" = true ]    && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_SECRETFINDER" = true ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    [ "$ENABLE_MOREURLS" = true ]     && TOTAL_STEPS=$((TOTAL_STEPS + 1))
}

# ─────────────────────────────────────────────────────────────
# Print functions
# ─────────────────────────────────────────────────────────────
show_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗  ███████╗██╗      ██████╗ ██╗    ██╗${NC}"
    echo -e "${CYAN}${BOLD}  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║  ██╔════╝██║     ██╔═══██╗██║    ██║${NC}"
    echo -e "${CYAN}${BOLD}  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║  █████╗  ██║     ██║   ██║██║ █╗ ██║${NC}"
    echo -e "${CYAN}${BOLD}  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  ██╔══╝  ██║     ██║   ██║██║███╗██║${NC}"
    echo -e "${CYAN}${BOLD}  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║  ██║     ███████╗╚██████╔╝╚███╔███╔╝${NC}"
    echo -e "${CYAN}${BOLD}  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝${NC}"
    echo ""
    echo -e "${DIM}${CYAN}                by 0xMarvul  ·  Bug Bounty Recon Automation${NC}"
    echo -e "${DIM}${CYAN}  ─────────────────────────────────────────────────────────────────────────────${NC}"
    echo ""
    if [ "$NOTIFY_ENABLED" = true ]; then
        echo -e "  ${GREEN}🔔 Discord Notifications: Enabled${NC}"
    else
        echo -e "  ${YELLOW}🔕 Discord Notifications: Disabled${NC}"
    fi
    echo ""
}

print_success() { echo -e "  ${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "  ${RED}[✗]${NC} $1"; }
print_warning() { echo -e "  ${YELLOW}[!]${NC} $1"; }
print_info()    { echo -e "  ${CYAN}[*]${NC} $1"; }

print_step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local start_ts=$(date '+%H:%M:%S')
    echo ""
    echo -e "  ${BOLD}${BLUE}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${BLUE}│${NC}  ${BOLD}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${BOLD}${1}${NC}"
    echo -e "  ${BOLD}${BLUE}│${NC}  ${DIM}Started: ${start_ts}${NC}"
    echo -e "  ${BOLD}${BLUE}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
}

print_section() {
    local ts=$(date '+%H:%M:%S')
    echo ""
    echo -e "  ${BOLD}${MAGENTA}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${MAGENTA}│${NC}  ${BOLD}${1}${NC}"
    echo -e "  ${BOLD}${MAGENTA}│${NC}  ${DIM}${ts}${NC}"
    echo -e "  ${BOLD}${MAGENTA}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
}

print_skip_hint() {
    echo -e "  ${DIM}${YELLOW}↵  ENTER to skip  |  P to pause${NC}"
}

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
        IFS= read -t 0.5 -r -n 1 _keystroke 2>/dev/null
        local read_exit=$?
        if [ $read_exit -eq 0 ]; then
            if [[ "$_keystroke" == "" || "$_keystroke" == $'\n' || "$_keystroke" == $'\r' ]]; then
                if [ "$SCAN_PAUSED" = true ]; then
                    kill -SIGCONT -- -${tool_pgid} 2>/dev/null
                    SCAN_PAUSED=false
                fi
                kill -- -${tool_pgid} 2>/dev/null
                wait "$CURRENT_TOOL_PID" 2>/dev/null
                print_warning "Skipped: $CURRENT_TOOL_NAME (user interrupted) - partial results saved"
                CURRENT_TOOL_PID=""; CURRENT_TOOL_NAME=""; SCAN_PAUSED=false
                return 2
            elif [[ "$_keystroke" == "p" || "$_keystroke" == "P" ]]; then
                if [ "$SCAN_PAUSED" = false ]; then
                    kill -SIGSTOP -- -${tool_pgid} 2>/dev/null
                    SCAN_PAUSED=true
                    echo ""
                    echo -e "  ${BOLD}${YELLOW}⏸  Scan PAUSED — press C to continue or ENTER to skip${NC}"
                fi
            elif [[ "$_keystroke" == "c" || "$_keystroke" == "C" ]]; then
                if [ "$SCAN_PAUSED" = true ]; then
                    kill -SIGCONT -- -${tool_pgid} 2>/dev/null
                    SCAN_PAUSED=false
                    echo -e "  ${GREEN}▶  Resumed — $CURRENT_TOOL_NAME continuing...${NC}"
                fi
            fi
        fi
    done

    wait "$CURRENT_TOOL_PID"
    local exit_code=$?
    CURRENT_TOOL_PID=""; CURRENT_TOOL_NAME=""; SCAN_PAUSED=false
    return $exit_code
}

# ─────────────────────────────────────────────────────────────
# Timestamp helpers
# ─────────────────────────────────────────────────────────────
get_timestamp()     { date '+%Y-%m-%d %H:%M:%S'; }
get_iso_timestamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# ─────────────────────────────────────────────────────────────
# Discord functions
# ─────────────────────────────────────────────────────────────
escape_json() {
    echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\r/\\r/g; s/\f/\\f/g'
}

send_discord() {
    [ "$NOTIFY_ENABLED" = false ] && return 0
    [ -z "$DISCORD_WEBHOOK" ] && return 0
    local title="$(escape_json "$1")"
    local description="$(escape_json "$2")"
    local color="$3" fields="$4"
    local footer="$(escape_json "$5")"
    local json_payload=$(cat <<EOF
{"embeds":[{"title":"$title","description":"$description","color":$color,"fields":$fields,"footer":{"text":"$footer"},"timestamp":"$(get_iso_timestamp)"}]}
EOF
)
    curl -s -H "Content-Type: application/json" -X POST -d "$json_payload" "$DISCORD_WEBHOOK" > /dev/null 2>&1
}

send_discord_start() {
    local domain="$(escape_json "$1")"
    local ts="$(escape_json "$2")"
    local fields='[{"name":"🎯 Target","value":"'"$domain"'","inline":true},{"name":"⏰ Started","value":"'"$ts"'","inline":true}]'
    send_discord "🚀 Scan Started" "Starting reconnaissance on **$domain**" 255 "$fields" "0xMarvul RECON FLOW"
}

send_discord_error() {
    local domain="$(escape_json "$1")"
    local tool="$(escape_json "$2")"
    local err="$(escape_json "$3")"
    local fields='[{"name":"🔧 Tool","value":"'"$tool"'","inline":true},{"name":"❌ Error","value":"'"$err"'","inline":true}]'
    send_discord "⚠️ Tool Error" "An error occurred during scan of **$domain**" 16711680 "$fields" "Scan will continue with other tools"
}

# ─────────────────────────────────────────────────────────────
# Dependency check
# ─────────────────────────────────────────────────────────────
check_dependencies() {
    print_section "Checking Dependencies"
    local tools=("subfinder" "assetfinder" "httpx" "gospider" "waybackurls" "katana" "paramspider" "jq" "curl")
    local missing_tools=() optional_tools=()
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then print_success "$tool is installed"
        else print_warning "$tool is NOT installed"; missing_tools+=("$tool"); fi
    done
    [ "$ENABLE_DIRSEARCH" = true ]    && { command -v dirsearch &>/dev/null && print_success "dirsearch is installed" || { print_warning "dirsearch NOT installed"; optional_tools+=("dirsearch"); }; }
    [ "$ENABLE_SECRETFINDER" = true ] && { command -v secretfinder &>/dev/null && print_success "secretfinder is installed" || { print_warning "secretfinder NOT installed"; optional_tools+=("secretfinder"); }; }
    [ "$ENABLE_TAKEOVER" = true ]     && { command -v nuclei &>/dev/null && print_success "nuclei is installed" || { print_warning "nuclei NOT installed"; optional_tools+=("nuclei"); }; }
    [ "$ENABLE_GF" = true ]           && { command -v gf &>/dev/null && print_success "gf is installed" || { print_warning "gf NOT installed"; optional_tools+=("gf"); }; }
    [ "$ENABLE_GOWITNESS" = true ]    && { command -v gowitness &>/dev/null && print_success "gowitness is installed" || { print_warning "gowitness NOT installed"; optional_tools+=("gowitness"); }; }
    if [ "$ENABLE_PORT_SCAN" = true ]; then
        for t in naabu nmap dnsx; do command -v $t &>/dev/null && print_success "$t is installed" || { print_warning "$t NOT installed"; optional_tools+=("$t"); }; done
    fi
    if [ "$ENABLE_MOREURLS" = true ]; then
        for t in gau hakrawler; do command -v $t &>/dev/null && print_success "$t is installed" || { print_warning "$t NOT installed"; optional_tools+=("$t"); }; done
    fi
    if [ "$ENABLE_BRUTEFORCE" = true ]; then
        command -v dnsx &>/dev/null && print_success "dnsx is installed" || { print_warning "dnsx NOT installed"; optional_tools+=("dnsx"); }
        [ -f "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt" ] && print_success "SecLists wordlist found" || { print_warning "SecLists not found — sudo apt install seclists"; optional_tools+=("seclists"); }
    fi
    [ ${#missing_tools[@]} -gt 0 ]  && print_warning "Missing required tools: ${missing_tools[*]}"
    [ ${#optional_tools[@]} -gt 0 ] && print_warning "Missing optional tools: ${optional_tools[*]}"
    [ ${#missing_tools[@]} -eq 0 ] && [ ${#optional_tools[@]} -eq 0 ] && print_success "All dependencies installed!"
    echo ""
}

# ─────────────────────────────────────────────────────────────
# Usage
# ─────────────────────────────────────────────────────────────
usage() {
    echo -e "  ${BOLD}Usage:${NC}  $0 ${CYAN}<domain>${NC} ${YELLOW}[flags]${NC}"
    echo ""
    echo -e "  ${DIM}${CYAN}─────────────────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}Subdomain:${NC}"
    echo -e "    ${CYAN}-parallel${NC}            Run enumeration tools in parallel (faster)"
    echo -e "    ${CYAN}-bruteforce${NC}          Active bruteforce with dnsx + SecLists (20k wordlist)"
    echo ""
    echo -e "  ${BOLD}URL Gathering:${NC}"
    echo -e "    ${CYAN}-moreurls${NC}            Extra URL gathering with GAU and Hakrawler"
    echo ""
    echo -e "  ${BOLD}Analysis:${NC}"
    echo -e "    ${CYAN}-gf${NC}                  GF patterns — filter URLs by vuln type"
    echo -e "    ${CYAN}-grep${NC}                Grep juicy URLs (configs, backups, secrets, etc.)"
    echo -e "    ${CYAN}-secret${NC}              Find secrets in JavaScript files"
    echo ""
    echo -e "  ${BOLD}Active:${NC}"
    echo -e "    ${CYAN}-dir${NC}                 Directory bruteforce with Dirsearch"
    echo -e "    ${CYAN}-dir /path/wordlist${NC}  Use custom wordlist for Dirsearch"
    echo -e "    ${CYAN}-port${NC}                Port scanning with Naabu + Nmap"
    echo -e "    ${CYAN}-takeover${NC}            Subdomain takeover check with Nuclei"
    echo -e "    ${CYAN}-gowitness${NC}           Screenshot all live hosts"
    echo ""
    echo -e "  ${BOLD}Misc:${NC}"
    echo -e "    ${CYAN}--webhook <url>${NC}      Custom Discord webhook URL"
    echo -e "    ${CYAN}--no-notify${NC}          Disable Discord notifications"
    echo ""
    echo -e "  ${DIM}${CYAN}─────────────────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}Examples:${NC}"
    echo -e "    ${CYAN}$0 target.com${NC}                                          # basic recon"
    echo -e "    ${CYAN}$0 target.com -parallel -bruteforce${NC}                    # fast + active subs"
    echo -e "    ${CYAN}$0 target.com -moreurls -gf -grep${NC}                      # deep URL analysis"
    echo -e "    ${CYAN}$0 target.com -gowitness -port${NC}                         # visual + ports"
    echo -e "    ${CYAN}$0 target.com -parallel -moreurls -dir -secret -gf -gowitness${NC}  # full"
    echo ""
    exit 1
}

# ═════════════════════════════════════════════════════════════
# STEP FUNCTIONS
# ═════════════════════════════════════════════════════════════

step_subdomain_enum() {
    if [ "$ENABLE_PARALLEL" = true ]; then
        print_info "Running subdomain enumeration in parallel mode..."
        command -v subfinder &>/dev/null && { subfinder -d "$DOMAIN" -o subs_subfinder.txt 2>/dev/null & pid_subfinder=$!; }
        command -v assetfinder &>/dev/null && { assetfinder --subs-only "$DOMAIN" > subs_assetfinder.txt 2>/dev/null & pid_assetfinder=$!; }
        { command -v curl &>/dev/null && command -v jq &>/dev/null; } && { (timeout 30 curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | jq -r '.[].name_value // empty' 2>/dev/null | sed 's/^\*\.//' | grep -v '@' | sort -u > subs_crtsh.txt) & pid_crtsh=$!; }
        command -v curl &>/dev/null && { (timeout 30 curl -s "https://shrewdeye.app/domains/$DOMAIN.txt" > subs_shrewdeye.txt 2>/dev/null) & pid_shrewdeye=$!; }
        command -v curl &>/dev/null && { (timeout 30 curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | cut -d',' -f1 | grep -v "error" > subs_hackertarget.txt) & pid_hackertarget=$!; }
        command -v curl &>/dev/null && { (timeout 30 curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1" 2>/dev/null | grep -oP '[\w.-]+\.'$DOMAIN'' | sort -u > subs_rapiddns.txt) & pid_rapiddns=$!; }
        { command -v curl &>/dev/null && command -v jq &>/dev/null; } && { (timeout 30 curl -s "https://anubisdb.com/anubis/subdomains/$DOMAIN" 2>/dev/null | jq -r '.[]' 2>/dev/null | sort -u > subs_anubis.txt) & pid_anubis=$!; }
        print_info "Waiting for all subdomain tools to complete..."
        [ -n "${pid_subfinder:-}" ]    && { wait $pid_subfinder 2>/dev/null && print_success "Subfinder completed" || print_warning "Subfinder failed"; }
        [ -n "${pid_assetfinder:-}" ]  && { wait $pid_assetfinder 2>/dev/null && print_success "Assetfinder completed" || print_warning "Assetfinder failed"; }
        [ -n "${pid_crtsh:-}" ]        && { wait $pid_crtsh 2>/dev/null && print_success "crt.sh completed" || print_warning "crt.sh failed"; }
        [ -n "${pid_shrewdeye:-}" ]    && { wait $pid_shrewdeye 2>/dev/null && print_success "Shrewdeye completed" || print_warning "Shrewdeye failed"; }
        [ -n "${pid_hackertarget:-}" ] && { wait $pid_hackertarget 2>/dev/null && [ -s subs_hackertarget.txt ] && print_success "HackerTarget completed - Found $(wc -l < subs_hackertarget.txt) subdomains" || print_warning "HackerTarget returned no results"; }
        [ -n "${pid_rapiddns:-}" ]     && { wait $pid_rapiddns 2>/dev/null && [ -s subs_rapiddns.txt ] && print_success "RapidDNS completed - Found $(wc -l < subs_rapiddns.txt) subdomains" || print_warning "RapidDNS returned no results"; }
        [ -n "${pid_anubis:-}" ]       && { wait $pid_anubis 2>/dev/null && [ -s subs_anubis.txt ] && print_success "Anubis-DB completed - Found $(wc -l < subs_anubis.txt) subdomains" || print_warning "Anubis-DB returned no results"; }
        print_success "Parallel subdomain enumeration completed!"
    else
        if command -v subfinder &>/dev/null; then
            print_info "Running Subfinder..."
            subfinder -d "$DOMAIN" -o subs_subfinder.txt 2>/dev/null && print_success "Subfinder completed" || { print_error "Subfinder failed"; failed_tools+=("subfinder"); send_discord_error "$DOMAIN" "subfinder" "Command execution failed"; }
        else print_warning "Subfinder not installed, skipping..."; fi

        if command -v assetfinder &>/dev/null; then
            print_info "Running Assetfinder..."
            assetfinder --subs-only "$DOMAIN" > subs_assetfinder.txt 2>/dev/null && print_success "Assetfinder completed" || { print_error "Assetfinder failed"; failed_tools+=("assetfinder"); send_discord_error "$DOMAIN" "assetfinder" "Command execution failed"; }
        else print_warning "Assetfinder not installed, skipping..."; fi

        if command -v curl &>/dev/null && command -v jq &>/dev/null; then
            print_info "Running crt.sh..."
            crt_response=$(timeout 30 curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null)
            if echo "$crt_response" | jq -e . >/dev/null 2>&1; then
                echo "$crt_response" | jq -r '.[].name_value // empty' | sed 's/^\*\.//' | grep -v '@' | sort -u > subs_crtsh.txt
                [ -s subs_crtsh.txt ] && print_success "crt.sh completed" || print_warning "crt.sh returned no results"
            else
                local domain_escaped=$(printf '%s\n' "$DOMAIN" | sed 's/[][\\.*^$()+?{|}]/\\&/g')
                timeout 30 curl -s "https://crt.sh/?q=%25.$DOMAIN" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\\.$domain_escaped" | grep -v '@' | sort -u > subs_crtsh.txt
                [ -s subs_crtsh.txt ] && print_success "crt.sh completed (HTML fallback)" || { print_error "crt.sh failed"; failed_tools+=("crt.sh"); }
            fi
        else print_warning "curl or jq not installed, skipping crt.sh..."; fi

        if command -v curl &>/dev/null; then
            print_info "Running Shrewdeye..."
            timeout 30 curl -s "https://shrewdeye.app/domains/$DOMAIN.txt" > subs_shrewdeye.txt 2>/dev/null
            [ -s subs_shrewdeye.txt ] && print_success "Shrewdeye completed" || print_warning "Shrewdeye returned no results"

            print_info "Running HackerTarget..."
            curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | cut -d',' -f1 | grep -v "error" > subs_hackertarget.txt
            [ -s subs_hackertarget.txt ] && print_success "HackerTarget completed - Found $(wc -l < subs_hackertarget.txt) subdomains" || print_warning "HackerTarget returned no results"

            print_info "Running RapidDNS..."
            curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1" 2>/dev/null | grep -oP '[\w.-]+\.'$DOMAIN'' | sort -u > subs_rapiddns.txt
            [ -s subs_rapiddns.txt ] && print_success "RapidDNS completed - Found $(wc -l < subs_rapiddns.txt) subdomains" || print_warning "RapidDNS returned no results"
        else print_warning "curl not installed, skipping API sources..."; fi

        if command -v curl &>/dev/null && command -v jq &>/dev/null; then
            print_info "Running Anubis-DB..."
            curl -s "https://anubisdb.com/anubis/subdomains/$DOMAIN" 2>/dev/null | jq -r '.[]' 2>/dev/null | sort -u > subs_anubis.txt
            [ -s subs_anubis.txt ] && print_success "Anubis-DB completed - Found $(wc -l < subs_anubis.txt) subdomains" || print_warning "Anubis-DB returned no results"
        else print_warning "curl or jq not installed, skipping Anubis-DB..."; fi
    fi
}

step_bruteforce() {
    local wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
    if command -v dnsx &>/dev/null && [ -f "$wordlist" ]; then
        print_info "Checking for wildcard DNS on $DOMAIN..."
        local wildcard_result=$(dig "randomxyz99notreal99abc.${DOMAIN}" +short 2>/dev/null | head -1)
        if [ -n "$wildcard_result" ]; then
            print_warning "Wildcard DNS detected — bruteforce skipped (results would be garbage)"
            failed_tools+=("dnsx-bruteforce-wildcard")
        else
            print_success "No wildcard DNS — safe to bruteforce"
            print_info "Wordlist: $wordlist (20,000 entries)"
            print_skip_hint
            run_with_skip "dnsx-bruteforce" "dnsx -d \"$DOMAIN\" -w \"$wordlist\" -a -silent -o subs_bruteforce.txt 2>/dev/null"
            local exit_code=$?
            if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
                [ -s subs_bruteforce.txt ] && brute_count=$(wc -l < subs_bruteforce.txt) && print_success "dnsx bruteforce completed - Found $brute_count subdomains" || print_warning "dnsx bruteforce - No new subdomains found"
            else
                print_error "dnsx bruteforce failed"
                failed_tools+=("dnsx-bruteforce")
                send_discord_error "$DOMAIN" "dnsx-bruteforce" "Command execution failed"
            fi
        fi
    else
        ! command -v dnsx &>/dev/null && print_warning "dnsx not installed, skipping bruteforce..." || print_warning "SecLists wordlist not found — sudo apt install seclists"
    fi
}

step_dns_resolution() {
    if ls subs_*.txt 1>/dev/null 2>&1; then
        cat subs_*.txt 2>/dev/null | grep -v '@' | sort -u > all_subs.txt
        total_subs=$(wc -l < all_subs.txt)
        print_success "Total unique subdomains: $total_subs (deduplicated, @ filtered)"
    else
        print_error "No subdomain files found"
        total_subs=0
    fi
}

step_live_host_check() {
    if [ -s all_subs.txt ] && command -v httpx &>/dev/null; then
        print_info "Running httpx (single pass — clean URLs + detailed info)..."
        setsid bash -c "cat all_subs.txt | httpx -silent -status-code -title -web-server -content-length -o live_hosts_detailed.txt 2>/dev/null" &
        CURRENT_TOOL_PID=$!
        wait $CURRENT_TOOL_PID
        local httpx_exit=$?
        CURRENT_TOOL_PID=""
        if [ $httpx_exit -eq 0 ]; then
            awk '{print $1}' live_hosts_detailed.txt > live_hosts.txt 2>/dev/null
            live_hosts=$(wc -l < live_hosts.txt 2>/dev/null || echo 0)
            print_success "httpx completed - Live hosts: $live_hosts"
            print_success "Detailed info saved to live_hosts_detailed.txt"
        else
            print_error "httpx failed"
            failed_tools+=("httpx")
            send_discord_error "$DOMAIN" "httpx" "Command execution failed"
            live_hosts=0
        fi
    else
        print_warning "httpx not installed or no subdomains, skipping..."
        live_hosts=0
    fi

    # Tech Detection (no checkpoint needed — runs fast)
    technologies="N/A"
    if [ -s live_hosts.txt ] && command -v httpx &>/dev/null; then
        print_info "Running Tech Detection..."
        if cat live_hosts.txt | httpx -tech-detect -silent -o tech_detect.txt 2>/dev/null; then
            if [ -s tech_detect.txt ]; then
                technologies=$(grep -oP '\[.*?\]' tech_detect.txt 2>/dev/null | tr -d '[]' | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g' | head -c 200)
                [ -z "$technologies" ] && technologies="N/A"
                print_success "Tech Detection completed"
                print_info "Technologies: $technologies"
            else
                print_success "Tech Detection completed"
            fi
        else
            print_warning "Tech Detection failed"
        fi
    fi
}

step_gowitness() {
    if [ -s live_hosts.txt ] && command -v gowitness &>/dev/null; then
        mkdir -p gowitness_output
        print_info "Running Gowitness on live hosts..."
        print_skip_hint
        run_with_skip "gowitness" "gowitness scan file -f live_hosts.txt --screenshot-path gowitness_output --write-db --write-db-uri sqlite://gowitness_output/gowitness.sqlite3 2>/dev/null"
        local exit_code=$?
        if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
            gowitness_count=$(ls gowitness_output/*.jpeg gowitness_output/*.png 2>/dev/null | wc -l)
            [ $exit_code -eq 0 ] && print_success "Gowitness completed - $gowitness_count screenshots" || print_info "Gowitness skipped - $gowitness_count screenshots saved"
            if [ "$gowitness_count" -gt 0 ]; then
                print_info "Generating HTML report..."
                if gowitness report generate --db-uri sqlite://gowitness_output/gowitness.sqlite3 --screenshot-path gowitness_output --zip-name gowitness_output/report.zip 2>/dev/null; then
                    command -v unzip &>/dev/null && { unzip -o gowitness_output/report.zip -d gowitness_output/report/ 2>/dev/null; rm -f gowitness_output/report.zip; print_success "HTML report: gowitness_output/report/report.html"; } || print_success "Report saved as gowitness_output/report.zip"
                else
                    print_warning "Report generation failed (screenshots still saved)"
                fi
            fi
        else
            print_error "Gowitness failed"
            failed_tools+=("gowitness")
            send_discord_error "$DOMAIN" "gowitness" "Command execution failed"
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts to screenshot" || print_warning "gowitness not installed — go install github.com/sensepost/gowitness/v3@latest"
    fi
}

step_port_scan() {
    if [ -s live_hosts.txt ] && command -v dnsx &>/dev/null && command -v naabu &>/dev/null; then
        print_info "Extracting domains and resolving to IPs..."
        sed 's|https\?://||' live_hosts.txt | cut -d'/' -f1 | sort -u > domains_for_port.txt
        if dnsx -a -resp-only -silent < domains_for_port.txt | sort -u > ips.txt 2>/dev/null; then
            ip_count=$(wc -l < ips.txt 2>/dev/null || echo 0)
            print_success "Resolved $ip_count unique IPs"
            if [ "$ip_count" -gt 0 ]; then
                print_info "Running Naabu..."
                print_skip_hint
                run_with_skip "naabu" "naabu -l ips.txt -o open_ports.txt 2>/dev/null"
                local exit_code=$?
                if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
                    if [ -s open_ports.txt ]; then
                        port_count=$(wc -l < open_ports.txt 2>/dev/null || echo 0)
                        print_success "Naabu completed - Found $port_count open ports"
                        if command -v nmap &>/dev/null; then
                            print_info "Running Nmap service detection..."
                            print_skip_hint
                            port_list=$(cut -d':' -f2 open_ports.txt | grep -E '^[0-9]+$' | awk '$1 >= 1 && $1 <= 65535' | sort -u | tr '\n' ',' | sed 's/,$//')
                            [ -n "$port_list" ] && { run_with_skip "nmap" "nmap -iL ips.txt -p \"$port_list\" -sV -oN ports_detailed.txt 2>/dev/null"; [ $? -eq 0 ] && print_success "Nmap completed — ports_detailed.txt"; } || print_warning "No ports to scan with Nmap"
                        else print_warning "Nmap not installed, skipping service detection"; fi
                    else print_warning "Naabu - No open ports found"; fi
                else
                    print_error "Naabu failed"
                    failed_tools+=("naabu")
                    send_discord_error "$DOMAIN" "naabu" "Command execution failed"
                fi
            else print_warning "No IPs resolved, skipping port scan"; fi
        else
            print_error "DNS resolution failed"
            failed_tools+=("dnsx")
            send_discord_error "$DOMAIN" "dnsx" "Command execution failed"
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts to scan for ports" || print_warning "dnsx or naabu not installed, skipping..."
    fi
}

step_takeover() {
    if [ -s live_hosts.txt ] && command -v nuclei &>/dev/null; then
        print_info "Running Nuclei takeover templates..."
        print_skip_hint
        if [ -d "$HOME/nuclei-templates/http/takeovers" ]; then
            run_with_skip "nuclei-takeover" "nuclei -l live_hosts.txt -t ~/nuclei-templates/http/takeovers -o takeover_results.txt 2>/dev/null"
            local exit_code=$?
            if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
                if [ -s takeover_results.txt ]; then
                    takeover_count=$(grep -c . takeover_results.txt 2>/dev/null || echo 0)
                    if [ "$takeover_count" -gt 0 ]; then
                        print_success "Found $takeover_count potential takeovers!"
                        echo ""
                        echo -e "    ${RED}⚠️  TAKEOVER VULNERABILITIES FOUND:${NC}"
                        while read line; do echo -e "    ${YELLOW}►${NC} $line"; done < takeover_results.txt
                        echo ""
                        send_discord "🚨 Subdomain Takeover Found!" "Found $takeover_count vulnerable subdomains on $DOMAIN" 16711680 '[{"name":"Target","value":"'"$DOMAIN"'","inline":true},{"name":"Vulnerabilities","value":"'"$takeover_count"'","inline":true}]' "0xMarvul RECON FLOW - CRITICAL"
                    else
                        print_success "Nuclei takeover scan completed - No takeovers found"
                    fi
                else
                    print_success "Nuclei takeover scan completed - No takeovers found"
                fi
            else
                print_error "Nuclei takeover scan failed"
                failed_tools+=("nuclei-takeover")
                send_discord_error "$DOMAIN" "nuclei-takeover" "Command execution failed"
            fi
        else
            print_error "Nuclei takeover templates not found — run: nuclei -update-templates"
            failed_tools+=("nuclei-templates")
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts to check for takeover" || print_warning "Nuclei not installed, skipping..."
    fi
}

step_url_gathering() {
    if [ -s live_hosts.txt ]; then
        if command -v gospider &>/dev/null; then
            print_info "Running Gospider..."
            print_skip_hint
            run_with_skip "gospider" "gospider -S live_hosts.txt -o gospider_output -t 5 -c 10 -d 3 --sitemap --robots -a -w 2>/dev/null"
            local exit_code=$?
            if [ $exit_code -ne 2 ]; then
                if [ -d gospider_output ] && [ -n "$(find gospider_output -maxdepth 1 -type f -print -quit 2>/dev/null)" ]; then
                    gospider_url_count=$(find gospider_output -type f -exec cat {} + 2>/dev/null | grep -oE "https?://[^ \"']+" | wc -l)
                    print_success "Gospider completed - Found ~$gospider_url_count URLs"
                else
                    print_warning "Gospider finished with no output"
                fi
            fi
        else print_warning "Gospider not installed, skipping..."; fi

        if command -v waybackurls &>/dev/null; then
            print_info "Running Waybackurls..."
            print_skip_hint
            run_with_skip "waybackurls" "cat live_hosts.txt | waybackurls > wayback.txt 2>/dev/null"
            local exit_code=$?
            [ $exit_code -eq 0 ] && print_success "Waybackurls completed" || [ $exit_code -eq 2 ] || { print_error "Waybackurls failed"; failed_tools+=("waybackurls"); send_discord_error "$DOMAIN" "waybackurls" "Command execution failed"; }
        else print_warning "Waybackurls not installed, skipping..."; fi

        if command -v katana &>/dev/null; then
            print_info "Running Katana..."
            print_skip_hint
            run_with_skip "katana" "katana -list live_hosts.txt -o katana.txt -silent -d 3 -jc -kf all -aff -ef png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css,mp4,mp3 2>/dev/null"
            local exit_code=$?
            [ $exit_code -eq 0 ] && print_success "Katana completed" || [ $exit_code -eq 2 ] || { print_error "Katana failed"; failed_tools+=("katana"); send_discord_error "$DOMAIN" "katana" "Command execution failed"; }
        else print_warning "Katana not installed, skipping..."; fi

        if [ "$ENABLE_MOREURLS" = true ]; then
            if command -v gau &>/dev/null; then
                print_info "Running GAU..."
                print_skip_hint
                run_with_skip "gau" "echo \"$DOMAIN\" | gau > gau.txt 2>/dev/null"
                local exit_code=$?
                [ $exit_code -eq 0 ] && print_success "GAU completed - $(wc -l < gau.txt 2>/dev/null || echo 0) URLs" || [ $exit_code -eq 2 ] || { print_error "GAU failed"; failed_tools+=("gau"); send_discord_error "$DOMAIN" "gau" "Command execution failed"; }
            else print_warning "GAU not installed, skipping..."; fi

            if command -v hakrawler &>/dev/null; then
                print_info "Running Hakrawler..."
                print_skip_hint
                run_with_skip "hakrawler" "cat live_hosts.txt | hakrawler > hakrawler.txt 2>/dev/null"
                local exit_code=$?
                [ $exit_code -eq 0 ] && print_success "Hakrawler completed - $(wc -l < hakrawler.txt 2>/dev/null || echo 0) URLs" || [ $exit_code -eq 2 ] || { print_error "Hakrawler failed"; failed_tools+=("hakrawler"); send_discord_error "$DOMAIN" "hakrawler" "Command execution failed"; }
            else print_warning "Hakrawler not installed, skipping..."; fi
        fi
    else
        print_warning "No live hosts found, skipping URL gathering..."
    fi

    # Extract and merge all URLs
    if [ -d gospider_output ] && [ -n "$(find gospider_output -maxdepth 1 -type f -print -quit 2>/dev/null)" ]; then
        print_info "Extracting Gospider URLs for merge..."
        find gospider_output -type f -exec cat {} + 2>/dev/null | grep -oE 'https?://[^ "'"'"']+' | sort -u > gospider_urls.txt
        print_success "Extracted $(wc -l < gospider_urls.txt 2>/dev/null || echo 0) unique URLs from Gospider"
    fi

    local junk_ext='\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|mp4|mp3|mp2|avi|mov|wmv|flv|webm|ogg|wav|aac|bmp|tiff|tif|psd|ai|eps|raw|cr2|nef|webp|apng|avif|jfif|cur|ani|xbm|pbm|pgm|ppm|pnm|hdr|exr|dds|pcx|tga|wbmp|otf|sfnt|ttc|dfont|fon|fnt|pfb|pfm)(\?|#|$)'

    if [ "$ENABLE_MOREURLS" = true ]; then
        if [ -f wayback.txt ] || [ -f katana.txt ] || [ -f gau.txt ] || [ -f hakrawler.txt ] || [ -f gospider_urls.txt ]; then
            cat wayback.txt katana.txt gau.txt hakrawler.txt gospider_urls.txt 2>/dev/null | sort -u > allurls_raw.txt
            grep -viE "$junk_ext" allurls_raw.txt > allurls.txt; rm -f allurls_raw.txt
            total_urls=$(wc -l < allurls.txt 2>/dev/null || echo 0)
            print_success "Total unique URLs: $total_urls (all sources merged + cleaned)"
        else
            print_warning "No URL files to merge"; total_urls=0
        fi
    else
        if [ -f wayback.txt ] || [ -f katana.txt ] || [ -f gospider_urls.txt ]; then
            cat wayback.txt katana.txt gospider_urls.txt 2>/dev/null | sort -u > allurls_raw.txt
            grep -viE "$junk_ext" allurls_raw.txt > allurls.txt; rm -f allurls_raw.txt
            total_urls=$(wc -l < allurls.txt 2>/dev/null || echo 0)
            print_success "Total unique URLs: $total_urls (merged + cleaned)"
        else
            print_warning "No URL files to merge"; total_urls=0
        fi
    fi
}

step_param_discovery() {
    if command -v paramspider &>/dev/null; then
        print_info "Running ParamSpider..."
        print_skip_hint
        run_with_skip "paramspider" "paramspider -d \"$DOMAIN\" 2>/dev/null"
        local exit_code=$?
        if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
            local param_file=""
            [ -f "results/${DOMAIN}.txt" ] && param_file="results/${DOMAIN}.txt"
            [ -z "$param_file" ] && [ -f "output/${DOMAIN}.txt" ] && param_file="output/${DOMAIN}.txt"
            [ -z "$param_file" ] && [ -f "${DOMAIN}.txt" ] && param_file="${DOMAIN}.txt"
            [ -z "$param_file" ] && param_file=$(find . -maxdepth 3 -name "${DOMAIN}.txt" 2>/dev/null | head -1)
            if [ -n "$param_file" ] && [ -f "$param_file" ]; then
                cp "$param_file" params.txt 2>/dev/null
                param_count=$(wc -l < params.txt 2>/dev/null || echo 0)
                [ $exit_code -eq 0 ] && print_success "ParamSpider completed - Parameters: $param_count" || print_info "ParamSpider - Parameters (partial): $param_count"
            else
                print_warning "ParamSpider output not found (check paramspider version)"
            fi
        else
            print_error "ParamSpider failed"
            failed_tools+=("paramspider")
            send_discord_error "$DOMAIN" "paramspider" "Command execution failed"
        fi
    else print_warning "ParamSpider not installed, skipping..."; fi
}

step_js_extraction() {
    if [ -s allurls.txt ]; then
        print_info "Filtering JavaScript files..."
        grep -E "\.js" allurls.txt > javascript.txt 2>/dev/null
        js_count=$(wc -l < javascript.txt 2>/dev/null || echo 0)
        print_success "JavaScript files: $js_count"

        print_info "Filtering PHP files..."
        grep -E "\.php" allurls.txt > php.txt 2>/dev/null
        php_count=$(wc -l < php.txt 2>/dev/null || echo 0)
        print_success "PHP files: $php_count"

        print_info "Filtering JSON files..."
        grep -Ei '\.json($|\?|&)' allurls.txt > json.txt 2>/dev/null
        json_count=$(wc -l < json.txt 2>/dev/null || echo 0)
        print_success "JSON files: $json_count"

        print_info "Filtering BIGRAC (sensitive files)..."
        grep -Ei '/(swagger|openapi|api-docs|v2\/api-docs|swagger-resources)(\.json|/|$|\?)|\b(json|config|metadata|schema|manifest|openapi|swagger)(\.json|\.yaml|\.yml)?(\?|$/)|\.(yaml|yml)($|\?|&)|(/|^)(package|config|composer|manifest)\.json($|\?|&)|/(\.env|env|config\.php|db\.sql|dump\.sql|backup|\.htpasswd|credentials|robots\.txt)$' allurls.txt | sort -u > BIGRAC.txt 2>/dev/null
        bigrac_count=$(wc -l < BIGRAC.txt 2>/dev/null || echo 0)
        print_success "BIGRAC sensitive files: $bigrac_count"
    else
        print_warning "No URLs to filter"
    fi
}

step_grep_juicy() {
    if [ -s allurls.txt ]; then
        mkdir -p grep_results
        local INPUT_FILE="allurls.txt"
        print_info "Grepping for juicy URLs..."
        grep -iE "(\.config|\.conf|\.cfg|\.ini|\.env|\.properties|\.yaml|\.yml|\.toml|\.xml|settings|configuration)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/config.txt
        grep -iE "\.(bak|backup|old|orig|original|copy|tmp|temp|swp|swo|save|~|zip|tar|gz|rar|7z)(\?|$|&)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/backup.txt
        grep -iE "(\.sql|\.sqlite|\.sqlite3|\.db|\.mdb|\.dump|mysql|postgres|mongodb|database|phpmyadmin)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/database.txt
        grep -iE "(password|passwd|pwd|secret|token|api_key|apikey|api-key|auth_token|access_token|private_key|credential|htpasswd|htaccess)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/secrets.txt
        grep -iE "(\.git|\.svn|\.hg|\.bzr|\.gitignore|\.gitconfig|\.gitattributes)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/sourcecode.txt
        grep -iE "(swagger|openapi|api-docs|graphql|graphiql|/api/|/v1/|/v2/|/v3/|rest/|wsdl|raml)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/api.txt
        grep -iE "(admin|administrator|dashboard|cpanel|webadmin|manager|console|portal|backend|wp-admin|wp-login|wp-content|phpmyadmin|adminer)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/admin.txt
        grep -iE "(debug|trace|test|phpinfo|server-status|server-info|\.dev\.|\.staging\.|\.uat\.|\.local\.|\.test\.)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/debug.txt
        grep -iE "(\.log|/logs/|/log/|error\.log|access\.log|debug\.log|audit\.log)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/logs.txt
        grep -iE "(upload|uploads|file|files|attachment|attachments|media|assets|/tmp/|/temp/|/cache/)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/uploads.txt
        grep -iE "\.(pem|key|crt|cer|p12|pfx|jks|keystore|pub|ppk)(\?|$|&)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/keys.txt
        grep -iE "(\.csv|\.xls|\.xlsx|\.doc|\.docx|\.pdf|data\.json|users\.json|export|dump)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/datafiles.txt
        grep -iE "(internal|private|hidden|secret|confidential|restricted|/priv/|/private/)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/internal.txt
        grep -iE "(aws|s3\.|amazonaws|azure|blob\.core|gcp|googleusercontent|firebase|digitalocean|bucket)" "$INPUT_FILE" 2>/dev/null | sort -u > grep_results/cloud.txt
        find grep_results/ -type f -name '*.txt' ! -name 'ALL_JUICY.txt' -exec cat {} + 2>/dev/null | sort -u > grep_results/ALL_JUICY.txt
        find grep_results/ -name '*.txt' ! -name 'ALL_JUICY.txt' -type f -empty -delete 2>/dev/null
        local total_juicy=$(wc -l < grep_results/ALL_JUICY.txt 2>/dev/null || echo 0)
        print_success "Grep Juicy URLs completed — TOTAL: $total_juicy juicy URLs"
        echo -e "    ${GREEN}►${NC} Results saved in: ${BOLD}grep_results/${NC}"
    else
        print_warning "No URLs to grep (allurls.txt is empty)"
    fi
}

step_gf_patterns() {
    if [ -s allurls.txt ] && command -v gf &>/dev/null; then
        print_info "Running GF patterns..."
        mkdir -p gf
        gf xss      < allurls.txt > gf/xss.txt 2>/dev/null
        gf sqli     < allurls.txt > gf/sqli.txt 2>/dev/null
        gf ssrf     < allurls.txt > gf/ssrf.txt 2>/dev/null
        gf lfi      < allurls.txt > gf/lfi.txt 2>/dev/null
        gf redirect < allurls.txt > gf/redirect.txt 2>/dev/null
        gf rce      < allurls.txt > gf/rce.txt 2>/dev/null
        gf idor     < allurls.txt > gf/idor.txt 2>/dev/null
        gf ssti     < allurls.txt > gf/ssti.txt 2>/dev/null
        find gf/ -type f -empty -delete 2>/dev/null
        print_success "GF Patterns completed:"
        echo -e "    ${GREEN}►${NC} XSS: $(wc -l < gf/xss.txt 2>/dev/null || echo 0)    SQLi: $(wc -l < gf/sqli.txt 2>/dev/null || echo 0)    SSRF: $(wc -l < gf/ssrf.txt 2>/dev/null || echo 0)    LFI: $(wc -l < gf/lfi.txt 2>/dev/null || echo 0)"
        echo -e "    ${GREEN}►${NC} Redirect: $(wc -l < gf/redirect.txt 2>/dev/null || echo 0)    RCE: $(wc -l < gf/rce.txt 2>/dev/null || echo 0)    IDOR: $(wc -l < gf/idor.txt 2>/dev/null || echo 0)    SSTI: $(wc -l < gf/ssti.txt 2>/dev/null || echo 0)"
    else
        [ ! -s allurls.txt ] && print_warning "No URLs to filter with GF patterns" || print_warning "GF not installed, skipping..."
    fi
}

step_dirsearch() {
    if [ -s live_hosts.txt ] && command -v dirsearch &>/dev/null; then
        print_info "Running Dirsearch..."
        print_skip_hint
        local default_wordlist=~/Desktop/WORDLIST/ULTRA_MEGA.txt
        local extensions="conf,config,bak,backup,swp,old,db,sql,asp,aspx,asp~,py,py~,rb,rb~,php,php~,bkp,cache,cgi,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql.gz,sql.tar.gz,sql~,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json"
        local dirsearch_cmd
        if [ -n "$CUSTOM_WORDLIST" ] && [ -f "$CUSTOM_WORDLIST" ]; then
            print_info "Using custom wordlist: $CUSTOM_WORDLIST"
            dirsearch_cmd="dirsearch -l live_hosts.txt -o mar0xwan.txt -w $CUSTOM_WORDLIST -i 200 -e $extensions 2>/dev/null"
        elif [ -f "$default_wordlist" ]; then
            print_info "Using default wordlist: $default_wordlist"
            dirsearch_cmd="dirsearch -l live_hosts.txt -o mar0xwan.txt -w $default_wordlist -i 200 -e $extensions 2>/dev/null"
        else
            print_warning "Default wordlist not found, using dirsearch built-in"
            dirsearch_cmd="dirsearch -l live_hosts.txt -o mar0xwan.txt -i 200 2>/dev/null"
        fi
        run_with_skip "dirsearch" "$dirsearch_cmd"
        local exit_code=$?
        if [ $exit_code -eq 0 ]; then
            print_success "Dirsearch completed"
            [ -f mar0xwan.txt ] && { dirsearch_count=$(grep -c "200" mar0xwan.txt 2>/dev/null || echo 0); print_info "Findings (200 status): $dirsearch_count"; }
        elif [ $exit_code -eq 2 ]; then :
        else
            print_error "Dirsearch failed"
            failed_tools+=("dirsearch")
            send_discord_error "$DOMAIN" "dirsearch" "Command execution failed"
        fi
    else
        [ ! -s live_hosts.txt ] && print_warning "No live hosts to scan with Dirsearch" || print_warning "Dirsearch not installed, skipping..."
    fi
}

step_secretfinder() {
    if [ -s javascript.txt ] && command -v secretfinder &>/dev/null; then
        print_info "Running SecretFinder on JavaScript files..."
        print_skip_hint
        run_with_skip "secretfinder" "secretfinder -i javascript.txt -o cli > secrets_found.txt 2>/dev/null"
        local exit_code=$?
        if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
            if [ -s secrets_found.txt ]; then
                secret_count=$(wc -l < secrets_found.txt 2>/dev/null || echo 0)
                [ $exit_code -eq 0 ] && print_success "SecretFinder completed - Found $secret_count potential secrets" || print_info "SecretFinder - Found $secret_count secrets (partial)"
            else
                print_warning "SecretFinder completed - No secrets found"
            fi
        else
            print_error "SecretFinder failed"
            failed_tools+=("secretfinder")
            send_discord_error "$DOMAIN" "secretfinder" "Command execution failed"
        fi
    else
        [ ! -s javascript.txt ] && print_warning "No JavaScript files to scan for secrets" || print_warning "SecretFinder not installed, skipping..."
    fi
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
            --webhook)    DISCORD_WEBHOOK="$2"; shift 2 ;;
            --no-notify)  NOTIFY_ENABLED=false; shift ;;
            -h|--help)    show_banner; usage ;;
            *)
                if [ -z "$DOMAIN" ]; then DOMAIN="$1"
                else echo -e "${RED}Error: Unknown argument '$1'${NC}"; usage; fi
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
    echo -e "  ${BOLD}${CYAN}Steps   :${NC} ${BOLD}$TOTAL_STEPS${NC} steps queued"
    echo -e "  ${BOLD}${CYAN}Started :${NC} ${BOLD}$(get_timestamp)${NC}"
    echo -e "  ${DIM}${CYAN}─────────────────────────────────────────────────────${NC}"
    echo ""

    send_discord_start "$DOMAIN" "$(get_timestamp)"
    check_dependencies

    # ── Directory / Checkpoint logic ──────────────────────────
    print_section "Creating Output Directory"
    if [ -f "${OUTPUT_DIR}/.checkpoint" ]; then
        print_warning "Previous scan found for $DOMAIN — resuming automatically"
        print_info "Completed steps will be skipped"
        echo ""
    elif [ -d "$OUTPUT_DIR" ] && [ -f "${OUTPUT_DIR}/all_subs.txt" ]; then
        print_warning "$DOMAIN was already scanned and completed"
        print_info "Running again will overwrite previous results"
        read -p "  Continue? (y/n): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && { print_error "Exiting..."; exit 1; }
        echo ""
    else
        mkdir -p "$OUTPUT_DIR"
        print_success "Starting fresh scan for: $DOMAIN"
    fi

    cd "$OUTPUT_DIR" || exit 1
    trap 'handle_interrupt' INT TERM
    trap 'handle_exit' EXIT

    checkpoint_init
    start_heartbeat

    # ── Initialize all counters ───────────────────────────────
    failed_tools=()
    gowitness_count=0 brute_count=0 total_subs=0 live_hosts=0
    total_urls=0 param_count=0 js_count=0 php_count=0
    json_count=0 bigrac_count=0 dirsearch_count=0
    secret_count=0 takeover_count=0 port_count=0
    technologies="N/A"

    # ── Run all steps ─────────────────────────────────────────
    run_step "Subdomain Enumeration"                  "SUBDOMAIN_ENUM"   step_subdomain_enum
    [ "$ENABLE_BRUTEFORCE" = true ] && run_step "Active Subdomain Bruteforce" "BRUTEFORCE"  step_bruteforce
    run_step "DNS Resolution"                         "DNS_RESOLUTION"   step_dns_resolution
    run_step "Live Host Check"                        "LIVE_HOST_CHECK"  step_live_host_check
    [ "$ENABLE_GOWITNESS" = true ]  && run_step "Screenshot Live Hosts (Gowitness)" "GOWITNESS"    step_gowitness
    [ "$ENABLE_PORT_SCAN" = true ]  && run_step "Port Scanning"                     "PORT_SCANNING" step_port_scan
    [ "$ENABLE_TAKEOVER" = true ]   && run_step "Subdomain Takeover Check"          "TAKEOVER"     step_takeover
    run_step "URL Gathering"                          "URL_GATHERING"    step_url_gathering
    run_step "Parameter Discovery"                    "PARAM_DISCOVERY"  step_param_discovery
    run_step "JavaScript Extraction & File Filtering" "JS_EXTRACTION"    step_js_extraction
    [ "$ENABLE_GREP" = true ]       && run_step "Grep Juicy URLs"                   "GREP_JUICY"   step_grep_juicy
    [ "$ENABLE_GF" = true ]         && run_step "GF Vulnerability Patterns"         "GF_PATTERNS"  step_gf_patterns
    [ "$ENABLE_DIRSEARCH" = true ]  && run_step "Directory Bruteforce"              "DIR_BRUTEFORCE" step_dirsearch
    [ "$ENABLE_SECRETFINDER" = true ] && run_step "Secret Finding in JavaScript"   "SECRET_FINDING" step_secretfinder

    # ── Final Summary ─────────────────────────────────────────
    print_section "FINAL SUMMARY"
    print_info "End Time: $(get_timestamp)"
    echo ""
    echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║               RECONNAISSANCE SUMMARY                      ║${NC}"
    echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Target Domain:${NC} ${BOLD}$DOMAIN${NC}"
    echo -e "${CYAN}Output Directory:${NC} ${BOLD}$OUTPUT_DIR${NC}"
    echo ""
    echo -e "${BOLD}${BLUE}Statistics:${NC}"
    echo -e "  ${GREEN}►${NC} Total Subdomains:       ${BOLD}${total_subs:-0}${NC}"
    echo -e "  ${GREEN}►${NC} Live Hosts:             ${BOLD}${live_hosts:-0}${NC}"
    echo -e "  ${GREEN}►${NC} Total URLs:             ${BOLD}${total_urls:-0}${NC}"
    echo -e "  ${GREEN}►${NC} JavaScript files:       ${BOLD}${js_count:-0}${NC}"
    echo -e "  ${GREEN}►${NC} PHP files:              ${BOLD}${php_count:-0}${NC}"
    echo -e "  ${GREEN}►${NC} JSON files:             ${BOLD}${json_count:-0}${NC}"
    echo -e "  ${GREEN}►${NC} BIGRAC sensitive files: ${BOLD}${bigrac_count:-0}${NC}"
    echo -e "  ${GREEN}►${NC} Parameters discovered:  ${BOLD}${param_count:-0}${NC}"
    [ "$ENABLE_TAKEOVER" = true ]     && echo -e "  ${GREEN}►${NC} Subdomain Takeovers:    ${BOLD}${takeover_count:-0}${NC}"
    [ "$ENABLE_SECRETFINDER" = true ] && echo -e "  ${GREEN}►${NC} Secrets found:          ${BOLD}${secret_count:-0}${NC}"
    [ "$ENABLE_DIRSEARCH" = true ]    && echo -e "  ${GREEN}►${NC} Dirsearch findings:     ${BOLD}${dirsearch_count:-0}${NC}"
    [ "$ENABLE_PORT_SCAN" = true ]    && echo -e "  ${GREEN}►${NC} Open ports found:       ${BOLD}${port_count:-0}${NC}"
    [ "$ENABLE_GOWITNESS" = true ]    && echo -e "  ${GREEN}►${NC} Screenshots taken:      ${BOLD}${gowitness_count:-0}${NC}"
    echo ""

    echo -e "${BOLD}${BLUE}Generated Files (non-empty only):${NC}"
    _show_file() { [ -s "$1" ] && echo -e "  ${CYAN}►${NC} ${BOLD}${1}${NC} — ${2} ${DIM}($(wc -l < "$1" 2>/dev/null || echo ?) lines)${NC}"; }
    _show_dir()  { [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ] && echo -e "  ${CYAN}►${NC} ${BOLD}${1}/${NC} — ${2}"; }
    _show_file "subs_subfinder.txt"      "Subfinder"
    _show_file "subs_assetfinder.txt"    "Assetfinder"
    _show_file "subs_crtsh.txt"          "crt.sh Certificate Transparency"
    _show_file "subs_shrewdeye.txt"      "Shrewdeye"
    _show_file "subs_hackertarget.txt"   "HackerTarget"
    _show_file "subs_rapiddns.txt"       "RapidDNS"
    _show_file "subs_anubis.txt"         "Anubis-DB"
    _show_file "subs_bruteforce.txt"     "Active dnsx bruteforce"
    _show_file "all_subs.txt"            "All unique subdomains (deduplicated)"
    _show_file "live_hosts.txt"          "Live hosts — clean URLs"
    _show_file "live_hosts_detailed.txt" "Live hosts — status, title, server, size"
    _show_file "tech_detect.txt"         "Detected technologies"
    _show_dir  "gospider_output"         "Gospider crawl results"
    _show_file "gospider_urls.txt"       "Gospider URLs (extracted + merged)"
    _show_file "wayback.txt"             "Wayback Machine URLs"
    _show_file "katana.txt"              "Katana crawler URLs"
    _show_file "gau.txt"                 "GAU URLs"
    _show_file "hakrawler.txt"           "Hakrawler URLs"
    _show_file "allurls.txt"             "All URLs combined (deduplicated + cleaned)"
    _show_file "params.txt"              "Discovered parameters (ParamSpider)"
    _show_file "javascript.txt"          "JavaScript files"
    _show_file "php.txt"                 "PHP files"
    _show_file "json.txt"                "JSON files"
    _show_file "BIGRAC.txt"              "Sensitive files (swagger, .env, configs, credentials)"
    _show_dir  "gowitness_output"        "Screenshots + HTML report"
    _show_file "takeover_results.txt"    "Subdomain takeover vulnerabilities"
    _show_file "secrets_found.txt"       "Secrets found in JavaScript"
    _show_file "mar0xwan.txt"            "Dirsearch results"
    _show_file "open_ports.txt"          "Open ports (Naabu)"
    _show_file "ports_detailed.txt"      "Detailed port scan (Nmap)"
    _show_dir  "gf"                      "GF vulnerability pattern results"
    _show_dir  "grep_results"            "Juicy URLs by category"
    echo ""

    if [ ${#failed_tools[@]} -gt 0 ]; then
        echo -e "${BOLD}${RED}Failed/Skipped Tools:${NC}"
        for tool in "${failed_tools[@]}"; do echo -e "  ${RED}✗${NC} $tool"; done
        echo ""
    fi

    # Discord End Notification
    if [ -n "$DISCORD_WEBHOOK" ] && [ "$NOTIFY_ENABLED" = true ]; then
        local END_TIME=$(date +%s)
        local DURATION_SEC=$((END_TIME - START_TIME))
        local DURATION_MIN=$((DURATION_SEC / 60))
        local DURATION_REMAIN=$((DURATION_SEC % 60))
        local discord_msg="Finished scanning $DOMAIN
📍 Subdomains: $(wc -l < all_subs.txt 2>/dev/null || echo 0)
🌐 Live Hosts: $(wc -l < live_hosts.txt 2>/dev/null || echo 0)
🔗 Total URLs: $(wc -l < allurls.txt 2>/dev/null || echo 0)
📜 JavaScript: $(wc -l < javascript.txt 2>/dev/null || echo 0)
🔴 BIGRAC: ${bigrac_count:-0}
🔍 Parameters: $(wc -l < params.txt 2>/dev/null || echo 0)"
        [ "$ENABLE_DIRSEARCH" = true ]    && { local dc=$(grep -c "200" mar0xwan.txt 2>/dev/null || echo 0); [ "$dc" -gt 0 ] && discord_msg="${discord_msg}
📁 Dirsearch: ${dc} found"; }
        [ "$ENABLE_PORT_SCAN" = true ]    && { local pc=$(wc -l < open_ports.txt 2>/dev/null || echo 0); [ "$pc" -gt 0 ] && discord_msg="${discord_msg}
🔌 Open Ports: ${pc}"; }
        [ "$ENABLE_SECRETFINDER" = true ] && { local sc=$(wc -l < secrets_found.txt 2>/dev/null || echo 0); [ "$sc" -gt 0 ] && discord_msg="${discord_msg}
🔑 Secrets: ${sc}"; }
        [ "$ENABLE_GOWITNESS" = true ] && [ "${gowitness_count:-0}" -gt 0 ] && discord_msg="${discord_msg}
📸 Screenshots: ${gowitness_count}"
        discord_msg="${discord_msg}
⏱️ Duration: ${DURATION_MIN}m ${DURATION_REMAIN}s"
        send_discord "✅ Recon Complete" "$discord_msg" 65280 "[]" "0xMarvul RECON FLOW"
    fi

    stop_heartbeat
    print_success "Reconnaissance completed!"
    rm -f "$CHECKPOINT_FILE" 2>/dev/null
    echo -e "${CYAN}All output files saved in: ${BOLD}$OUTPUT_DIR/${NC}\n"
}

main "$@"
