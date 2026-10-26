#!/usr/bin/env bash
# ==============================================================================
# Linux Security Audit & Integrity Check Script
# ==============================================================================

set -uo pipefail

# ---------------------------------------------------------
# Concurrency Protection & Timeout Handling
# ---------------------------------------------------------
LOCK_FILE="/var/run/security_audit.lock"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "[-] Another instance of this audit script is already running. Exiting."
    exit 1
fi

# Set a 30-minute hard execution timeout
TIMEOUT_SECONDS=1800
(
    sleep "$TIMEOUT_SECONDS"
    echo -e "\n[-] Audit execution timed out after 30 minutes. Terminating."
    kill -TERM "$$" 2>/dev/null
) &
TIMEOUT_PID=$!

TMP_FILES=()

cleanup() {
    kill "$TIMEOUT_PID" 2>/dev/null || true
    flock -u 200 2>/dev/null || true
    if [ "${#TMP_FILES[@]}" -gt 0 ]; then
        rm -f "${TMP_FILES[@]}"
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------
# Report helpers
# ---------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
finding() { echo "[-] [$1] $2"; }
note() { echo "[*] $1"; }

section() {
    echo -e "\n=========================================================="
    echo " $1"
    echo "=========================================================="
}

# Read at most 4 MiB from each newline-separated log path (matches the Rust log-tail cap).
collect_log_tail() {
    local out=$1
    local file
    : > "$out"
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        sudo tail -c 4194304 "$file" >> "$out" 2>/dev/null || true
    done
}

# ---------------------------------------------------------
# STAGE 1: Precheck & Dependencies
# ---------------------------------------------------------
echo "=========================================================="
echo " Stage 1: Precheck & Dependencies"
echo "=========================================================="
echo "Checking required audit tools..."

REQUIRED_PKGS="clamav clamav-freshclam debsums rkhunter chkrootkit iproute2"
MISSING_PKGS=""

for pkg in $REQUIRED_PKGS; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "[-] Missing package: $pkg"
        MISSING_PKGS="$MISSING_PKGS $pkg"
    else
        echo "[+] Installed: $pkg"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo "Installing missing dependencies:$MISSING_PKGS"
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        $MISSING_PKGS
    echo "Dependencies successfully installed."
else
    echo "All required audit utilities are already present."
fi

# ---------------------------------------------------------
# STAGE 2: Docker Security Audit
# ---------------------------------------------------------
echo -e "\n=========================================================="
echo " Stage 2: Docker Security Audit"
echo "=========================================================="
echo "Checking container privilege levels and socket mounts..."

if ! have docker; then
    {
        echo "=== DOCKER SOCKET MOUNT CHECK ==="
        echo "Skipped: docker command not found."
        echo "=== PRIVILEGED CONTAINER CHECK ==="
        echo "Skipped: docker command not found."
    } > docker-audit-report.txt
elif ! sudo docker ps -q >/dev/null 2>&1; then
    {
        echo "=== DOCKER SOCKET MOUNT CHECK ==="
        echo "Skipped: docker daemon unavailable."
        echo "=== PRIVILEGED CONTAINER CHECK ==="
        echo "Skipped: docker daemon unavailable."
    } > docker-audit-report.txt
else
    {
        echo "=== DOCKER SOCKET MOUNT CHECK ==="
        sudo docker ps -q 2>/dev/null | xargs -r sudo docker inspect \
            --format '{{.Name}}: {{range .Mounts}}{{if or (eq .Source "/var/run/docker.sock") (eq .Source "/run/docker.sock")}}MOUNTED_DOCKER_SOCK({{.Source}}){{end}}{{end}}' 2>/dev/null \
            | grep 'MOUNTED_DOCKER_SOCK' || echo "No containers mount docker.sock."

        echo "=== PRIVILEGED CONTAINER CHECK ==="
        sudo docker ps -q 2>/dev/null | xargs -r sudo docker inspect \
            --format '{{.Name}}: Privileged={{.HostConfig.Privileged}}' 2>/dev/null \
            | grep 'Privileged=true' || echo "No privileged containers running."
    } > docker-audit-report.txt
fi

cat docker-audit-report.txt

# ---------------------------------------------------------
# STAGE 3: ClamAV Scan
# ---------------------------------------------------------
echo -e "\n=========================================================="
echo " Stage 3: ClamAV Scan"
echo "=========================================================="
echo "Starting ClamAV signature update and targeted scan..."

if ! have clamscan; then
    echo "Skipped: clamscan command not found." > clamav-report.txt
else
    sudo freshclam --quiet || true
    sudo clamscan -r --infected --suppress-ok-results \
        /var/lib/docker/volumes /tmp /var/tmp /dev/shm > clamav-report.txt 2>&1 || true
fi

cat clamav-report.txt

# ---------------------------------------------------------
# STAGE 4: Debsums Integrity
# ---------------------------------------------------------
echo -e "\n=========================================================="
echo " Stage 4: Debsums Integrity"
echo "=========================================================="
echo "Checking package file checksums..."

if have debsums; then
    sudo debsums -cs > debsums-report.txt 2>&1 || true
else
    echo "Skipped: debsums command not found." > debsums-report.txt
fi

cat debsums-report.txt

# ---------------------------------------------------------
# STAGE 5: Rootkit Audits
# ---------------------------------------------------------
echo -e "\n=========================================================="
echo " Stage 5: Rootkit Audits"
echo "=========================================================="
echo "Running chkrootkit and rkhunter..."

{
    echo "--- CHKROOTKIT ---"
    sudo chkrootkit -q 2>&1 \
        | grep -vE '(/usr/lib/python3/|/usr/lib/jvm/|/usr/lib/ruby/|/usr/lib/node_modules/|/usr/lib/libreoffice/)' \
        | grep -v 'PACKET SNIFFER(/usr/sbin/NetworkManager' \
        | grep -v 'infected ports: 4000 45454' \
        | grep -v 'defmt-[0-9.]*/src/impls/core_' \
        | grep -vE '/tmp/yarn--[0-9]+-[0-9.]+' \
        || true

    echo "--- RKHUNTER ---"
    sudo rkhunter --cronjob --report-warnings-only --skip-keypress || true
} > rootkit-report.txt

cat rootkit-report.txt

# ---------------------------------------------------------
# STAGE 6: Persistence & Account Audit
# ---------------------------------------------------------
echo -e "\n=========================================================="
echo " Stage 6: Persistence & Account Audit"
echo "=========================================================="
echo "Auditing accounts, keys, cron, and systemd units..."

{
    echo "=== UID 0 ACCOUNTS ==="
    awk -F: '($3 == 0) {print $1}' /etc/passwd

    echo "=== SYSTEM & USER CRONTABS ==="
    sudo tail -n +1 /var/spool/cron/crontabs/* 2>/dev/null || echo "No spool crontabs."

    echo "=== ALL AUTHORIZED KEYS ==="
    sudo find /root /home /var/lib -maxdepth 4 -name "authorized_keys" -exec ls -la {} + 2>/dev/null || echo "No authorized_keys found."

    echo "=== SUSPICIOUS SYSTEMD UNITS ==="
    systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | grep -iE 'local|custom|run|tmp' || echo "No suspicious units."
} > persistence-report.txt

cat persistence-report.txt

# ---------------------------------------------------------
# STAGE 7: Network Sockets & Pending Patches
# ---------------------------------------------------------
echo -e "\n=========================================================="
echo " Stage 7: Network Sockets & Pending Patches"
echo "=========================================================="
echo "Auditing open sockets and pending updates..."

{
    echo "=== PUBLIC LISTENING PORTS (0.0.0.0 or [::]) ==="
    sudo ss -tulpn | grep -E '0\.0\.0\.0|:::' || echo "No wildcard listening ports."

    echo "=== ESTABLISHED OUTBOUND CONNECTIONS ==="
    sudo ss -tpn state established || true

    echo "=== PENDING DEBIAN SECURITY PATCHES ==="
    sudo apt-get update -qq
    apt-get --just-print upgrade \
        | grep -iE 'security|esm(apps)?[:/]|ubuntu pro' \
        || echo "All security patches up to date."
} > network-updates-report.txt

cat network-updates-report.txt

# ---------------------------------------------------------
# STAGE 8: Web Server Log Analysis
# ---------------------------------------------------------
section "Stage 8: Web Server Log Analysis"
echo "Scanning nginx, Apache, httpd and Caddy logs for attack patterns..."

WEB_LOG_FILES=$(
    sudo find /var/log/nginx /var/log/apache2 /var/log/httpd /var/log/caddy \
        -maxdepth 2 -type f 2>/dev/null || true
    sudo find /var/log -maxdepth 1 -type f \
        \( -name 'caddy.log' -o -name 'nginx.log' \) 2>/dev/null || true
)
WEB_LOG_FILES=$(printf '%s\n' "$WEB_LOG_FILES" \
    | grep -Ev '\.(gz|bz2|xz|zst|zip)$' \
    | grep -Ei '(access|error|caddy|\.log$)' \
    | head -n 32 || true)

if [ -z "$WEB_LOG_FILES" ]; then
    {
        echo "=== WEB SERVER LOGS ==="
        echo "Skipped: no nginx, Apache or Caddy access/error logs found."
    } > web-logs-report.txt
    cat web-logs-report.txt
else
    WEB_TMP=$(mktemp)
    TMP_FILES+=("$WEB_TMP")
    printf '%s\n' "$WEB_LOG_FILES" | collect_log_tail "$WEB_TMP"

    WEB_REQUESTS=$(grep -Eci '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE) ' "$WEB_TMP" || true)
    WEB_STATUSES=$(
        { grep -Eo 'HTTP/[0-9.]+" [0-9]{3}' "$WEB_TMP" | awk '{print $2}' || true
          grep -Eo '"status":[0-9]{3}' "$WEB_TMP" | grep -Eo '[0-9]{3}$' || true
        }
    )
    WEB_CLIENT_ERRORS=$(printf '%s\n' "$WEB_STATUSES" | grep -c '^4' || true)
    WEB_SERVER_ERRORS=$(printf '%s\n' "$WEB_STATUSES" | grep -c '^5' || true)
    WEB_LOGIN_FAILURES=$(printf '%s\n' "$WEB_STATUSES" | grep -Ec '^(401|403)$' || true)
    WEB_TRACE=$(
        { grep -Ec '"TRACE ' "$WEB_TMP" || true
          grep -Ec '"method"[[:space:]]*:[[:space:]]*"TRACE"' "$WEB_TMP" || true
        } | awk '{total += $1} END {print total + 0}'
    )

    ATTACK_NAMES=(
        "SQL injection"
        "cross-site scripting"
        "path traversal"
        "command injection"
        "Log4Shell/JNDI lookup"
        "Shellshock"
        "web shell / upload"
        "sensitive file probe"
        "automated scanner agent"
        "XML external entity"
    )
    ATTACK_REGEX=(
        "union([[:space:]]|%20)+select|'[[:space:]]*or[[:space:]]*'?1|sleep[[:space:]]*\\(|benchmark[[:space:]]*\\(|information_schema|xp_cmdshell|into[[:space:]]+outfile|load_file[[:space:]]*\\("
        "<script|%3cscript|javascript[[:space:]]*:|onerror[[:space:]]*=|onload[[:space:]]*=|document\\.cookie|alert[[:space:]]*\\("
        "\\.\\./|%2e%2e(%2f|/)|%252e%252e|/etc/passwd|/proc/self/environ|win\\.ini|boot\\.ini"
        '(;|\||`|\$\(|%3b|%7c)[[:space:]]*(wget|curl|bash|sh|nc|netcat|python|perl|cat|id|whoami|uname|base64|powershell|certutil)|/bin/(ba)?sh|chmod[[:space:]]+\+x'
        '\$\{(jndi|env|sys|lower|date|java):'
        '\([[:space:]]*\)[[:space:]]*\{'
        '/shell\.php|/cmd\.php|/c99\.php|/r57\.php|/eval-stdin\.php|/vendor/phpunit|/wp-content/(uploads|plugins)/.*\.php|/uploads/.*\.(php|phtml|jsp|asp|aspx)|<\?php|%3c\?php'
        '/\.env([.]|/|[?[:space:]"]|$)|/\.git(/|[?[:space:]"]|$)|/\.svn(/|[?[:space:]"]|$)|/\.aws/credentials|/wp-login\.php|/wp-admin(/|[?[:space:]"]|$)|/phpmyadmin|/pma(/|[?[:space:]"]|$)|/adminer(\.php)?|/server-status|/actuator/(env|heapdump|health)|/\.DS_Store|/(backup|dump|db)\.(sql|tar|gz|zip)|/config\.(json|php|ya?ml)|/\.?htpasswd|/web\.config|/cgi-bin/'
        'sqlmap|nikto|nuclei|nmap|masscan|zgrab|gobuster|dirbuster|feroxbuster|wpscan|acunetix|nessus'
        '<!doctype|<!entity|%3c!doctype|%3c!entity'
    )

    ATTACK_FINDINGS=""
    for i in "${!ATTACK_NAMES[@]}"; do
        count=$(grep -Eci "${ATTACK_REGEX[$i]}" "$WEB_TMP" || true)
        if [ "${count:-0}" -gt 0 ]; then
            successful=$(grep -Ei "${ATTACK_REGEX[$i]}" "$WEB_TMP" \
                | grep -Ec 'HTTP/[0-9.]+" (2|3)[0-9]{2}|"status":(2|3)[0-9]{2}' || true)
            case "${ATTACK_NAMES[$i]}" in
                "automated scanner agent") severity=LOW ;;
                "sensitive file probe") [ "${successful:-0}" -gt 0 ] && severity=HIGH || severity=LOW ;;
                "web shell / upload") [ "${successful:-0}" -gt 0 ] && severity=HIGH || severity=MEDIUM ;;
                *) [ "${successful:-0}" -gt 0 ] && severity=HIGH || severity=MEDIUM ;;
            esac
            ATTACK_FINDINGS="${ATTACK_FINDINGS}$(finding "$severity" "${ATTACK_NAMES[$i]} pattern: ${count} request(s), ${successful} with a 2xx/3xx status")"$'\n'
            ATTACK_FINDINGS="${ATTACK_FINDINGS}$(grep -Ei "${ATTACK_REGEX[$i]}" "$WEB_TMP" | head -n 3 | sed 's/^/  /' || true)"$'\n'
        fi
    done

    {
        echo "=== WEB SERVER LOGS ==="
        echo "Scanned log files:"
        printf '%s\n' "$WEB_LOG_FILES" | sed 's/^/  /'
        echo
        echo "=== SUMMARY ==="
        echo "requests: $WEB_REQUESTS"
        echo "client errors (4xx): $WEB_CLIENT_ERRORS"
        echo "server errors (5xx): $WEB_SERVER_ERRORS"
        echo "TRACE requests: $WEB_TRACE"
        echo
        if [ -n "$ATTACK_FINDINGS" ]; then
            printf '%s' "$ATTACK_FINDINGS"
        else
            echo "No attack or probe patterns detected."
        fi
        if [ "$WEB_LOGIN_FAILURES" -ge 50 ]; then
            finding HIGH "web login brute-force pattern: $WEB_LOGIN_FAILURES 401/403 response(s)"
        elif [ "$WEB_LOGIN_FAILURES" -ge 10 ]; then
            finding MEDIUM "web login brute-force pattern: $WEB_LOGIN_FAILURES 401/403 response(s)"
        fi
        if [ "$WEB_SERVER_ERRORS" -ge 25 ]; then
            finding MEDIUM "web server produced $WEB_SERVER_ERRORS 5xx response(s); investigate application or proxy failures"
        fi
        if [ "$WEB_CLIENT_ERRORS" -ge 500 ]; then
            finding LOW "web server produced $WEB_CLIENT_ERRORS 4xx response(s); possible scanning or broken clients"
        fi
        if [ "$WEB_TRACE" -gt 0 ]; then
            finding LOW "$WEB_TRACE HTTP TRACE request(s) reached the web server; disable the method if unused"
        fi
    } > web-logs-report.txt
    cat web-logs-report.txt
    rm -f "$WEB_TMP"
fi

# ---------------------------------------------------------
# STAGE 9: Authentication Log Analysis
# ---------------------------------------------------------
section "Stage 9: Authentication Log Analysis"
echo "Scanning auth.log/secure logs for brute force, break-ins and sudo denials..."

AUTH_LOG_FILES=$(
    sudo find /var/log -maxdepth 2 -type f \
        \( -name 'auth.log*' -o -name 'secure*' -o -name 'sshd*' -o -name 'sudo' \) \
        2>/dev/null || true
)
AUTH_LOG_FILES=$(printf '%s\n' "$AUTH_LOG_FILES" \
    | grep -Ev '\.(gz|bz2|xz|zst|zip)$' \
    | head -n 16 || true)

if [ -z "$AUTH_LOG_FILES" ]; then
    {
        echo "=== AUTHENTICATION LOGS ==="
        echo "Skipped: no auth.log/secure logs found."
    } > auth-logs-report.txt
    cat auth-logs-report.txt
else
    AUTH_TMP=$(mktemp)
    TMP_FILES+=("$AUTH_TMP")
    printf '%s\n' "$AUTH_LOG_FILES" | collect_log_tail "$AUTH_TMP"

    AUTH_LINES=$(wc -l < "$AUTH_TMP" | tr -d ' ')
    AUTH_FAILURES=$(grep -Ec 'Failed [^ ]+ for (invalid user )?[^ ]+ from ' "$AUTH_TMP" || true)
    AUTH_PAM_FAILURES=$(grep -Ec 'pam_unix\([^)]*\): authentication failure.*rhost=' "$AUTH_TMP" || true)
    AUTH_TOTAL_FAILURES=$((AUTH_FAILURES + AUTH_PAM_FAILURES))
    AUTH_INVALID=$(grep -Eci 'Invalid user ' "$AUTH_TMP" || true)
    AUTH_ACCEPTED=$(grep -Ec 'Accepted [^ ]+ for ' "$AUTH_TMP" || true)
    AUTH_ROOT=$(grep -Ec 'Accepted [^ ]+ for root from ' "$AUTH_TMP" || true)
    AUTH_BREAKINS=$(grep -Eci 'BREAK-IN ATTEMPT|Possible break-in attempt|reverse mapping checking getaddrinfo .* failed' "$AUTH_TMP" || true)
    AUTH_SUDO_DENIALS=$(grep -Ec 'sudo:.*NOT in sudoers' "$AUTH_TMP" || true)

    AUTH_TOP_IPS=$(grep -Eo 'Failed [^ ]+ for (invalid user )?[^ ]+ from [^ ]+' "$AUTH_TMP" \
        | awk '{print $NF}' | sort | uniq -c | sort -rn | head -n 5 \
        | awk '{print $2" ("$1")"}' | paste -sd, - | sed 's/,/, /g' || true)
    AUTH_TOP_USERS=$(grep -Eo 'Failed [^ ]+ for (invalid user )?[^ ]+ from ' "$AUTH_TMP" \
        | awk '{print $(NF-1)}' | sort | uniq -c | sort -rn | head -n 5 \
        | awk '{print $2" ("$1")"}' | paste -sd, - | sed 's/,/, /g' || true)

    AUTH_ACCEPTED_AFTER=$(awk '
        /Failed [^ ]+ for / {
            for (i = 1; i <= NF; i++) {
                if ($i == "from") { pending[$(i + 1)]++; break }
            }
        }
        /Accepted [^ ]+ for / {
            user = ""; ip = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "for") user = $(i + 1)
                if ($i == "from") { ip = $(i + 1); break }
            }
            if (ip != "" && pending[ip] >= 5) {
                print user " from " ip " after " pending[ip] " failure(s)"
                pending[ip] = 0
            }
        }
    ' "$AUTH_TMP" || true)

    {
        echo "=== AUTHENTICATION LOGS ==="
        echo "Scanned log files:"
        printf '%s\n' "$AUTH_LOG_FILES" | sed 's/^/  /'
        echo
        echo "=== SUMMARY ==="
        echo "lines: $AUTH_LINES"
        echo "failed authentications: $AUTH_TOTAL_FAILURES"
        echo "invalid users: $AUTH_INVALID"
        echo "successful logins: $AUTH_ACCEPTED"
        echo "root logins: $AUTH_ROOT"
        echo "break-in markers: $AUTH_BREAKINS"
        echo "sudo denials: $AUTH_SUDO_DENIALS"
        echo
        if [ "$AUTH_TOTAL_FAILURES" -ge 100 ]; then
            finding HIGH "SSH authentication failures: $AUTH_TOTAL_FAILURES; top source IPs: ${AUTH_TOP_IPS:-none}"
        elif [ "$AUTH_TOTAL_FAILURES" -ge 10 ]; then
            finding MEDIUM "SSH authentication failures: $AUTH_TOTAL_FAILURES; top source IPs: ${AUTH_TOP_IPS:-none}"
        fi
        if [ "$AUTH_TOTAL_FAILURES" -ge 10 ]; then
            echo "top targeted users: ${AUTH_TOP_USERS:-none}"
        fi
        if [ "$AUTH_INVALID" -ge 50 ]; then
            finding MEDIUM "SSH invalid-user probes: $AUTH_INVALID"
        elif [ "$AUTH_INVALID" -ge 5 ]; then
            finding LOW "SSH invalid-user probes: $AUTH_INVALID"
        fi
        if [ -n "$AUTH_ACCEPTED_AFTER" ]; then
            finding HIGH "successful login after repeated failures: $AUTH_ACCEPTED_AFTER"
        fi
        if [ "$AUTH_BREAKINS" -gt 0 ]; then
            finding HIGH "$AUTH_BREAKINS authentication break-in marker(s) in the logs"
        fi
        if [ "$AUTH_SUDO_DENIALS" -gt 0 ]; then
            finding LOW "$AUTH_SUDO_DENIALS sudo denial(s); a user attempted commands outside sudoers"
        fi
        if [ "$AUTH_ROOT" -gt 0 ]; then
            finding INFO "$AUTH_ROOT successful root login(s) recorded"
        fi
        if [ "$AUTH_TOTAL_FAILURES" -eq 0 ] && [ "$AUTH_BREAKINS" -eq 0 ]; then
            note "no authentication failures or break-in markers were found"
        fi
    } > auth-logs-report.txt
    cat auth-logs-report.txt
    rm -f "$AUTH_TMP"
fi

# ---------------------------------------------------------
# STAGE 10: Host Hardening
# ---------------------------------------------------------
section "Stage 10: Host Hardening"
echo "Auditing SSH, sysctl, firewall, sudoers, file modes and account hygiene..."

SSHD_DUMP=""
if have sshd; then
    SSHD_DUMP=$(sudo sshd -T 2>/dev/null || true)
fi
if [ -z "$SSHD_DUMP" ]; then
    SSHD_DUMP=$(
        { sudo cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
          sudo cat /etc/ssh/sshd_config 2>/dev/null || true
        } | sed '/^[[:space:]]*#/d' | awk 'tolower($1) == "match" {exit} {print}'
    )
fi

ssh_value() {
    printf '%s\n' "$SSHD_DUMP" \
        | awk -v key="$1" 'tolower($1) == key {gsub(/"/, "", $2); print tolower($2); exit}'
}

SSH_ROOT_LOGIN=$(ssh_value permitrootlogin)
SSH_PASSWORD_AUTH=$(ssh_value passwordauthentication)
SSH_EMPTY_PASSWORDS=$(ssh_value permitemptypasswords)
SSH_USER_ENV=$(ssh_value permituserenvironment)
SSH_USE_PAM=$(ssh_value usepam)
SSH_X11=$(ssh_value x11forwarding)
SSH_MAX_AUTH=$(ssh_value maxauthtries)
SSH_GRACE=$(ssh_value logingracetime)
SSH_ALIVE=$(ssh_value clientaliveinterval)

SYSCTL_VALUES=$(
    { sudo cat /etc/sysctl.conf 2>/dev/null || true
      sudo cat /etc/sysctl.d/*.conf 2>/dev/null || true
      sudo sysctl -a 2>/dev/null || true
    } | sed 's/#.*//' | awk -F= '
        NF >= 2 {
            gsub(/^[ \t]+|[ \t]+$/, "", $1)
            gsub(/^[ \t]+|[ \t]+$/, "", $2)
            if ($1 != "" && $2 != "") print $1 "=" $2
        }'
)

check_sysctl() {
    local key=$1 expected=$2 severity=$3 description=$4 value
    value=$(printf '%s\n' "$SYSCTL_VALUES" | awk -F= -v key="$key" '$1 == key {print $2; exit}')
    [ -n "$value" ] || return 0
    case " $expected " in
        *" $value "*) ;;
        *) finding "$severity" "sysctl $key = $value; expected ${expected// /\/} ($description)" ;;
    esac
}

FIREWALL=""
FIREWALL_TOOLING=0
if have ufw; then
    FIREWALL_TOOLING=1
    UFW_STATUS=$(sudo ufw status 2>/dev/null || true)
    if printf '%s' "$UFW_STATUS" | grep -qi 'status: active'; then
        FIREWALL=ufw
    else
        note "ufw is installed but not active"
    fi
fi
if [ -z "$FIREWALL" ] && have nft; then
    FIREWALL_TOOLING=1
    NFT_RULES=$(sudo nft list ruleset 2>/dev/null || true)
    if printf '%s\n' "$NFT_RULES" | grep -qvE '^[[:space:]]*(#|$)'; then
        FIREWALL=nftables
    else
        note "nftables has no rules"
    fi
fi
if [ -z "$FIREWALL" ] && have iptables; then
    FIREWALL_TOOLING=1
    IPT_RULES=$(sudo iptables -S 2>/dev/null || true)
    IPT_COUNT=$(printf '%s\n' "$IPT_RULES" | grep -vcE '^[[:space:]]*(-P|-N|$)' || true)
    if [ "${IPT_COUNT:-0}" -gt 0 ]; then
        FIREWALL=iptables
    else
        note "iptables has no rules"
    fi
fi

SUDO_NOPASSWD=$(sudo grep -rEh '^[^#]*\bNOPASSWD[[:space:]]*:' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 5 || true)
SUDO_NOAUTH=$(sudo grep -rEh '^[[:space:]]*Defaults(@[^[:space:]]+|[[:space:]]+[^#]*)?[[:space:]]+!authenticate\b' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 5 || true)

SCAN_ROOTS="/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /tmp /var/tmp /home /srv /var/www"
KNOWN_PRIVILEGED="Xorg at beep bsd-write chage chfn chsh crontab dbus-daemon-launch-helper dotlockfile expiry fusermount fusermount3 gpasswd krb5_child locate lppasswd mlocate mount newgrp ntfs-3g passwd ping ping6 pkexec polkit-agent-helper-1 postdrop postqueue pppd procmail qemu-bridge-helper sendmail sg snap-confine ssh-agent ssh-keysign su sudo suexec umount"

SUID_SGID=$(sudo timeout 120 find $SCAN_ROOTS -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -n 500 || true)
UNEXPECTED_PRIV=$(printf '%s\n' "$SUID_SGID" | awk -v known="$KNOWN_PRIVILEGED" '
    BEGIN { n = split(known, a, " "); for (i = 1; i <= n; i++) k[a[i]] = 1 }
    $0 != "" { n = split($0, p, "/"); if (!(p[n] in k)) print }
')
EXPOSED_PRIV=$(printf '%s\n' "$UNEXPECTED_PRIV" | grep -E '^/(home|srv|var/www|tmp|var/tmp)/' || true)
WW_FILES=$(sudo timeout 120 find $SCAN_ROOTS -xdev -type f -perm -0002 \
    ! -path '*/tmp/*' ! -path '*/shm/*' 2>/dev/null | head -n 200 || true)
WW_DIRS=$(sudo timeout 120 find $SCAN_ROOTS -xdev -type d -perm -0002 ! -perm -1000 \
    ! -path '*/tmp/*' ! -path '*/shm/*' ! -name tmp ! -name shm 2>/dev/null | head -n 200 || true)

UID0_EXTRA=$(awk -F: 'NF >= 7 && $0 !~ /^#/ && $3 == 0 && $1 != "root" {print $1}' /etc/passwd)
PASSWD_EMPTY=$(awk -F: 'NF >= 7 && $0 !~ /^#/ && $2 == "" {print $1}' /etc/passwd)
SHADOW_EMPTY=$(sudo awk -F: 'NF >= 2 && $0 !~ /^#/ && $2 == "" {print $1}' /etc/shadow 2>/dev/null || true)
SHADOW_WEAK=$(sudo awk -F: 'NF >= 2 && $0 !~ /^#/ && $2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null || true)
SHADOW_LOCKED=$(sudo awk -F: 'NF >= 2 && $0 !~ /^#/ && $2 ~ /^[!*]/ {c++} END {print c + 0}' /etc/shadow 2>/dev/null || true)

{
    echo "=== SSH DAEMON CONFIGURATION ==="
    if [ -z "$SSHD_DUMP" ]; then
        finding LOW "SSH daemon configuration could not be read; SSH hardening was not audited"
    else
        echo "permitrootlogin: ${SSH_ROOT_LOGIN:--}"
        echo "passwordauthentication: ${SSH_PASSWORD_AUTH:--}"
        echo "maxauthtries: ${SSH_MAX_AUTH:--}"
        echo "x11forwarding: ${SSH_X11:--}"
        echo "clientaliveinterval: ${SSH_ALIVE:--}"
        case "$SSH_ROOT_LOGIN" in
            yes) finding HIGH "SSH root login is enabled (PermitRootLogin yes)" ;;
            without-password | prohibit-password) finding INFO "SSH root login is limited to key-based authentication" ;;
            forced-commands-only) finding LOW "SSH root login is allowed only for forced commands" ;;
        esac
        if [ "$SSH_PASSWORD_AUTH" = "yes" ]; then
            finding MEDIUM "SSH password authentication is enabled; prefer keys only"
        fi
        if [ "$SSH_EMPTY_PASSWORDS" = "yes" ]; then
            finding HIGH "SSH permits empty passwords (PermitEmptyPasswords yes)"
        fi
        if [ "$SSH_USER_ENV" = "yes" ]; then
            finding MEDIUM "SSH accepts user environment files (PermitUserEnvironment yes)"
        fi
        if [ "$SSH_USE_PAM" = "no" ]; then
            finding MEDIUM "SSH has PAM disabled (UsePAM no)"
        fi
        if [ "$SSH_X11" = "yes" ]; then
            finding LOW "SSH X11 forwarding is enabled"
        fi
        case "$SSH_MAX_AUTH" in
            '' | *[!0-9]*) ;;
            *) [ "$SSH_MAX_AUTH" -gt 6 ] && finding LOW "SSH allows $SSH_MAX_AUTH authentication attempts; expected 6 or fewer" ;;
        esac
        case "$SSH_GRACE" in
            '' | *[!0-9]*) ;;
            *) [ "$SSH_GRACE" -gt 60 ] && finding LOW "SSH LoginGraceTime is ${SSH_GRACE}s; expected 60s or less" ;;
        esac
        if [ "$SSH_ALIVE" = "0" ]; then
            finding LOW "SSH idle sessions never expire (ClientAliveInterval 0)"
        fi
    fi

    echo
    echo "=== SYSCTL / KERNEL HARDENING ==="
    check_sysctl kernel.randomize_va_space "2" MEDIUM "full address-space layout randomisation"
    check_sysctl net.ipv4.tcp_syncookies "1" MEDIUM "SYN-cookie protection"
    check_sysctl net.ipv4.conf.all.accept_redirects "0" MEDIUM "ICMP redirect acceptance"
    check_sysctl net.ipv4.conf.default.accept_redirects "0" MEDIUM "ICMP redirect acceptance on new interfaces"
    check_sysctl net.ipv4.conf.all.send_redirects "0" LOW "ICMP redirect emission"
    check_sysctl net.ipv4.conf.all.accept_source_route "0" MEDIUM "source-routed packets"
    check_sysctl net.ipv4.conf.all.log_martians "1" LOW "logging of martian packets"
    check_sysctl net.ipv4.conf.all.rp_filter "1 2" LOW "reverse-path filtering"
    check_sysctl net.ipv6.conf.all.accept_redirects "0" MEDIUM "IPv6 redirect acceptance"
    check_sysctl kernel.dmesg_restrict "1" LOW "kernel log restriction"
    check_sysctl kernel.kptr_restrict "1 2" LOW "kernel pointer restriction"
    check_sysctl kernel.yama.ptrace_scope "1 2 3" LOW "ptrace restriction"
    check_sysctl fs.protected_hardlinks "1" LOW "hardlink protection"
    check_sysctl fs.protected_symlinks "1" LOW "symlink protection"
    check_sysctl net.ipv4.ip_forward "0" LOW "IP forwarding on a non-router host"
    if [ -z "$SYSCTL_VALUES" ]; then
        finding LOW "no sysctl configuration was found; kernel hardening was not audited"
    fi

    echo
    echo "=== FIREWALL ==="
    if [ -n "$FIREWALL" ]; then
        echo "active firewall: $FIREWALL"
    elif [ "$FIREWALL_TOOLING" -eq 0 ]; then
        finding LOW "no firewall tooling (ufw, nft or iptables) was found"
    else
        finding MEDIUM "no active firewall rules detected (ufw/nft/iptables)"
    fi

    echo
    echo "=== SUDOERS ==="
    if [ -n "$SUDO_NOPASSWD" ]; then
        finding MEDIUM "sudo rules use NOPASSWD:"
        printf '%s\n' "$SUDO_NOPASSWD" | sed 's/^/  /'
    fi
    if [ -n "$SUDO_NOAUTH" ]; then
        finding HIGH "sudo authentication is disabled by !authenticate:"
        printf '%s\n' "$SUDO_NOAUTH" | sed 's/^/  /'
    fi
    if [ -z "$SUDO_NOPASSWD" ] && [ -z "$SUDO_NOAUTH" ]; then
        echo "no NOPASSWD or !authenticate rules found"
    fi

    echo
    echo "=== FILE PERMISSIONS (SUID/SGID & WORLD-WRITABLE) ==="
    echo "SUID/SGID files: $(printf '%s\n' "$SUID_SGID" | grep -c . || true)"
    if [ -n "$EXPOSED_PRIV" ]; then
        finding HIGH "$(printf '%s\n' "$EXPOSED_PRIV" | grep -c .) SUID/SGID file(s) in a user-writable or shared location"
        printf '%s\n' "$EXPOSED_PRIV" | head -n 20 | sed 's/^/  /'
    fi
    OTHER_PRIV=$(printf '%s\n' "$UNEXPECTED_PRIV" | grep -vxF -f <(printf '%s\n' "$EXPOSED_PRIV") 2>/dev/null || true)
    if [ -n "$OTHER_PRIV" ]; then
        finding LOW "$(printf '%s\n' "$OTHER_PRIV" | grep -c .) unexpected SUID/SGID file(s); review the list"
        printf '%s\n' "$OTHER_PRIV" | head -n 20 | sed 's/^/  /'
    fi
    if [ -n "$WW_FILES" ]; then
        finding MEDIUM "$(printf '%s\n' "$WW_FILES" | grep -c .) world-writable file(s) outside temporary directories"
        printf '%s\n' "$WW_FILES" | head -n 20 | sed 's/^/  /'
    fi
    if [ -n "$WW_DIRS" ]; then
        finding MEDIUM "$(printf '%s\n' "$WW_DIRS" | grep -c .) world-writable directories without the sticky bit"
        printf '%s\n' "$WW_DIRS" | head -n 20 | sed 's/^/  /'
    fi
    if [ -z "$WW_FILES" ] && [ -z "$WW_DIRS" ]; then
        echo "no world-writable files or directories found"
    fi

    echo
    echo "=== ACCOUNT & PASSWORD HYGIENE ==="
    if [ -n "$UID0_EXTRA" ]; then
        finding HIGH "additional UID 0 account(s) in /etc/passwd: $(printf '%s' "$UID0_EXTRA" | paste -sd, - | sed 's/,/, /g')"
    fi
    if [ -n "$PASSWD_EMPTY" ]; then
        finding HIGH "account(s) with an empty password field in /etc/passwd: $(printf '%s' "$PASSWD_EMPTY" | paste -sd, - | sed 's/,/, /g')"
    fi
    if [ -n "$SHADOW_EMPTY" ]; then
        finding HIGH "account(s) with an empty password hash in /etc/shadow: $(printf '%s' "$SHADOW_EMPTY" | paste -sd, - | sed 's/,/, /g')"
    fi
    if [ -n "$SHADOW_WEAK" ]; then
        finding MEDIUM "account(s) using a legacy MD5 password hash: $(printf '%s' "$SHADOW_WEAK" | paste -sd, - | sed 's/,/, /g')"
    fi
    echo "locked password entries: ${SHADOW_LOCKED:-0}"
} > hardening-report.txt

cat hardening-report.txt

# ---------------------------------------------------------
# STAGE 11: AWS Host Audit
# ---------------------------------------------------------
section "Stage 11: AWS Host Audit"
echo "Checking AWS metadata, credential exposure, agents and time sync..."

IMDS_ROOT="http://169.254.169.254/latest"
IMDS_CURL=(curl -sS -f --noproxy '*' --connect-timeout 1 --max-time 2)

IMDS_INSTANCE_ID=$("${IMDS_CURL[@]}" "$IMDS_ROOT/meta-data/instance-id" 2>/dev/null || true)
IMDS_TOKEN=$("${IMDS_CURL[@]}" -X PUT \
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
    "$IMDS_ROOT/api/token" 2>/dev/null || true)

AWS_CRED_FILES=$(
    sudo find /root /home -maxdepth 3 -type f \
        \( -path '*/.aws/credentials' -o -path '*/.aws/config' \) \
        2>/dev/null | head -n 64 || true
)
AWS_ENV_FILES=$(sudo find /etc/profile.d -maxdepth 1 -type f -name '*.sh' 2>/dev/null | head -n 32 || true)

AWS_EXPOSED=0
AWS_SCANNED=0
for file in /etc/environment /etc/ecs/ecs.config /var/lib/cloud/instance/user-data.txt $AWS_CRED_FILES $AWS_ENV_FILES; do
    [ -n "$file" ] || continue
    [ -e "$file" ] || continue
    AWS_SCANNED=$((AWS_SCANNED + 1))
    if sudo grep -Eqi 'aws_(access_key_id|secret_access_key|session_token)[[:space:]]*[=:]|(AKIA|ASIA)[0-9A-Z]{16}' "$file" 2>/dev/null; then
        AWS_EXPOSED=$((AWS_EXPOSED + 1))
    fi
done

{
    echo "=== OPERATING SYSTEM ==="
    if [ -r /etc/os-release ]; then
        OS_PRETTY=$(awk -F= '$1 == "PRETTY_NAME" {sub(/^[^=]*=/, ""); gsub(/"/, ""); print; exit}' /etc/os-release)
        OS_ID=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2; exit}' /etc/os-release)
        OS_VERSION=$(awk -F= '$1 == "VERSION_ID" {gsub(/"/, "", $2); print $2; exit}' /etc/os-release)
        echo "${OS_PRETTY:-unknown}"
        echo "ID: ${OS_ID:-unknown}"
        echo "VERSION_ID: ${OS_VERSION:-unknown}"
        if [ "$OS_ID" != "ubuntu" ] && [ "$OS_ID" != "debian" ]; then
            finding LOW "host OS \`${OS_ID:-unknown}\` is not Debian/Ubuntu; dpkg/apt and package-file checks may not apply"
        fi
    else
        finding LOW "could not read /etc/os-release; Debian/Ubuntu compatibility was not verified"
    fi

    echo
    echo "=== EC2 INSTANCE METADATA (IMDS) ==="
    if ! have curl; then
        echo "Skipped: curl command not found."
        finding LOW "curl is unavailable; EC2 IMDSv1/IMDSv2 state could not be audited"
    elif [ -z "$IMDS_INSTANCE_ID" ] && [ -z "$IMDS_TOKEN" ]; then
        echo "IMDSv1: unreachable"
        echo "IMDSv2: token endpoint unreachable"
        note "EC2 instance metadata service is not reachable; AWS metadata checks were skipped"
    else
        if [ -n "$IMDS_INSTANCE_ID" ]; then
            echo "IMDSv1: reachable without a session token"
            finding HIGH "EC2 IMDSv1 is enabled; require IMDSv2 (HttpTokens=required) to prevent SSRF credential theft"
        else
            echo "IMDSv1: blocked (session token required)"
            note "IMDSv1 is blocked; IMDSv2 appears to be required"
        fi
        if [ -n "$IMDS_TOKEN" ]; then
            echo "IMDSv2: token issued"
            IMDS_DOC=$("${IMDS_CURL[@]}" \
                -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
                "$IMDS_ROOT/dynamic/instance-identity/document" 2>/dev/null || true)
            if [ -n "$IMDS_DOC" ]; then
                for field in instanceId region availabilityZone instanceType imageId; do
                    value=$(printf '%s' "$IMDS_DOC" \
                        | grep -o "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
                        | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/')
                    echo "$field: ${value:--}"
                done
            else
                note "EC2 instance identity document was not available"
            fi
            IMDS_ROLES=$("${IMDS_CURL[@]}" \
                -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
                "$IMDS_ROOT/meta-data/iam/security-credentials/" 2>/dev/null || true)
            if [ -n "$IMDS_ROLES" ]; then
                echo "instance profile role: $(printf '%s\n' "$IMDS_ROLES" | head -n 1)"
            fi
        else
            echo "IMDSv2: token endpoint unavailable"
            finding LOW "EC2 IMDSv2 token could not be obtained; metadata hardening could not be verified"
        fi
    fi

    echo
    echo "=== AWS CREDENTIAL EXPOSURE ==="
    echo "scanned $AWS_SCANNED AWS-related file(s); $AWS_EXPOSED contained credential material"
    for file in /etc/environment /etc/ecs/ecs.config /var/lib/cloud/instance/user-data.txt $AWS_CRED_FILES $AWS_ENV_FILES; do
        [ -n "$file" ] || continue
        [ -e "$file" ] || continue
        if sudo grep -Eqi 'aws_(access_key_id|secret_access_key|session_token)[[:space:]]*[=:]|(AKIA|ASIA)[0-9A-Z]{16}' "$file" 2>/dev/null; then
            finding HIGH "long-term AWS credential material is stored in $file"
        fi
        if sudo grep -Eq -- '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----' "$file" 2>/dev/null; then
            finding HIGH "private key material is stored in $file"
        fi
        mode=$(sudo stat -c '%a' "$file" 2>/dev/null || true)
        if [ -n "$mode" ] && [ $((8#$mode & 8#077)) -ne 0 ]; then
            finding MEDIUM "$file is readable by group/others (mode $mode); expected 0600"
        fi
    done
    if [ "$AWS_SCANNED" -eq 0 ]; then
        echo "No AWS-related files were found to scan."
        note "no static AWS credentials were found in the scanned locations"
    fi

    echo
    echo "=== AWS AGENTS & TIME SYNC ==="
    if have systemctl; then
        for unit in amazon-ssm-agent.service amazon-cloudwatch-agent.service ecs.service; do
            state=$(systemctl show "$unit" --property=LoadState,ActiveState --no-pager 2>/dev/null || true)
            load=$(printf '%s\n' "$state" | awk -F= '$1 == "LoadState" {print $2; exit}')
            active=$(printf '%s\n' "$state" | awk -F= '$1 == "ActiveState" {print $2; exit}')
            case "$load:$active" in
                not-found:*)
                    echo "$unit: not installed"
                    if [ "$unit" = "ecs.service" ] && [ -e /etc/ecs/ecs.config ]; then
                        finding MEDIUM "/etc/ecs/ecs.config exists but the ECS agent unit is not installed"
                    fi
                    ;;
                *:active) echo "$unit: active" ;;
                *)
                    echo "$unit: inactive"
                    case "$unit" in
                        amazon-ssm-agent.service) finding LOW "AWS SSM agent is installed but not running" ;;
                        amazon-cloudwatch-agent.service) finding INFO "CloudWatch agent is installed but not running" ;;
                        ecs.service) finding MEDIUM "ECS agent is installed but not running on an ECS host" ;;
                    esac
                    ;;
            esac
        done
    else
        echo "Skipped: systemctl command not found."
        note "\`systemctl\` was not found; AWS agent checks skipped"
    fi

    if have timedatectl; then
        NTP_SYNC=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || true)
        echo "clock synchronized: ${NTP_SYNC:-unknown}"
        if [ "$NTP_SYNC" = "no" ]; then
            finding LOW "system clock is not NTP-synchronized; AWS SigV4 signatures may fail"
        fi
    else
        echo "Skipped: timedatectl command not found."
        note "\`timedatectl\` was not found; clock synchronization was not checked"
    fi
} > aws-report.txt

cat aws-report.txt

echo -e "\n[+] Audit run completed. Generated reports:"
ls -lh *-report.txt