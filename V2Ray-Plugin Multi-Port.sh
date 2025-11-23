#!/bin/bash
# V2Ray-Plugin Multi-Port Auto-Rotator Installer for Ubuntu 22.04
# Implements advanced security, dynamic port rotation, and WebSocket obfuscation

set -euo pipefail

# Configuration
readonly SCRIPT_NAME="v2ray-plugin-installer"
readonly LOCKFILE="/var/lock/${SCRIPT_NAME}.lock"
readonly LOG_FILE="/var/log/v2ray-plugin-install.log"
readonly GITHUB_API_URL="https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest"
readonly V2RAY_PLUGIN_VERSION="v1.3.2"
readonly NUM_PORTS=7
readonly ARCH="linux-amd64"
readonly NUM_OBFUSCATION_PORTS=7 # Количество портов для обфускации

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

# Logging function
logit() {
    local level="${1:-info}"
    local msg="${2:-}"
    echo "$(date -u '+%Y-%m-%d %H:%M:%S') [${level^^}]: $msg" | tee -a "$LOG_FILE"
    logger -p "user.$level" -t "$SCRIPT_NAME" "$msg"
}

# Acquire installation lock
acquire_lock() {
    exec 200>"$LOCKFILE"
    if ! flock -w 10 200; then
        logit error "Installation already running or lock file exists"
        exit 98
    fi
    trap 'rm -f "$LOCKFILE"' EXIT
}

# Rollback function for errors
rollback() {
    logit error "INSTALLATION ROLLBACK triggered at line $LINENO"
    # Cleanup on failure
    local temp_files=(
        "/tmp/v2ray-plugin.tar.gz"
        "/tmp/v2ray-plugin_linux_amd64"
    )
    for file in "${temp_files[@]}"; do
        [[ -f "$file" ]] && rm -f "$file"
    done
    exit 1
}

# --- ПРОВЕРКА Read-Only файловой системы и снятие атрибута immutable ---

# Ensure filesystem is writable and remove immutable attributes from known paths
ensure_writable_and_clean() {
    logit info "Ensuring filesystem writability and cleaning immutable attributes..."

    # Check critical paths for writability
    local critical_paths=("/" "/etc" "/usr" "/var")
    for path in "${critical_paths[@]}"; do
        if [[ ! -w "$path" ]]; then
            logit error "Critical path '$path' is not writable (Read-only filesystem detected). Cannot proceed."
            exit 100
        fi
    done

    # Paths that might be created or modified by this installer or its generated scripts
    local potential_immutable_paths=(
        "/etc/v2ray_ports.list"
        "/etc/v2ray_passwd"
        "/etc/shadowsocks-libev"
        "/etc/systemd/system/ss-server-v2ray@.service"
        "/etc/systemd/system/v2ray-multi.service"
        "/etc/systemd/system/v2ray-multi.timer"
        "/usr/local/bin/start-v2ray-multi.sh"
        "/usr/local/bin/send-nonstandard-frame.sh"
        "/etc/systemd/system/send-nonstandard-frame.service"
        "/etc/systemd/system/send-nonstandard-frame.timer"
        "/var/log/v2ray-multi.log"
        "/var/log/send-nonstandard-frame.log"
        "/tmp/current_obf_ports.list"
        # Add any other paths that scripts might create/modify
    )

    for path in "${potential_immutable_paths[@]}"; do
        if [[ -e "$path" ]]; then
            logit info "Checking $path for immutable attribute..."
            if lsattr "$path" 2>/dev/null | grep -q 'i'; then
                logit info "Removing immutable attribute from $path"
                chattr -i "$path" 2>/dev/null || logit warning "Could not remove immutable attribute from $path, continuing..."
            fi
        else
            logit info "Path $path does not exist, skipping immutable check."
        fi
    done
    logit info "Filesystem check and cleanup passed."
}

# --- ВАЛИДАЦИЯ И УСТАНОВКА ЗАВИСИМОСТЕЙ ---

# Validate system requirements
validate_system() {
    logit info "Validating system requirements..."

    # Check OS
    if [[ ! -f /etc/os-release ]] || ! grep -q "Ubuntu 22.04" /etc/os-release; then
        logit error "This script requires Ubuntu 22.04"
        exit 1
    fi

    # Check architecture
    if [[ "$(uname -m)" != "x86_64" ]]; then
        logit error "This script requires x86_64 architecture"
        exit 1
    fi

    # Check disk space (at least 100MB free)
    local free_space
    free_space=$(df / | awk 'NR==2 {print int($4/1024)}')  # in MB
    if (( free_space < 100 )); then
        logit error "Insufficient disk space. Required: 100MB, Available: ${free_space}MB"
        exit 1
    fi

    # Check for systemd
    if ! command -v systemctl >/dev/null 2>&1; then
        logit error "systemd is required but not found"
        exit 1
    fi

    # Ensure writability and clean attributes before proceeding
    ensure_writable_and_clean
}

# Check required utilities
check_dependencies() {
    logit info "Checking required dependencies..."
    local deps=("curl" "tar" "awk" "grep" "systemctl" "flock" "sha256sum" "socat")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            logit error "Required dependency '$dep' is not installed"
            exit 1
        fi
    done
    # Ensure writability and clean attributes before installing packages
    ensure_writable_and_clean
}

# Install required packages
install_packages() {
    logit info "Updating package lists..."
    # Ensure writability and clean attributes before apt operations
    ensure_writable_and_clean
    apt-get update

    logit info "Installing required packages..."
    # Ensure writability and clean attributes before installing packages
    ensure_writable_and_clean
    apt-get install -y shadowsocks-libev pwgen systemd curl wget tar gzip socat
}

# --- УСТАНОВКА КОМПОНЕНТОВ ---

# Download and install v2ray-plugin
install_v2ray_plugin() {
    logit info "Downloading v2ray-plugin $V2RAY_PLUGIN_VERSION..."

    # Ensure writability and clean attributes before download
    ensure_writable_and_clean
    local download_url
    download_url=$(curl -s "$GITHUB_API_URL" | grep -o "https://.*v2ray-plugin-${ARCH}-.*\.tar\.gz" | head -n1)

    if [[ -z "$download_url" ]]; then
        logit error "Could not fetch v2ray-plugin download URL"
        exit 1
    fi

    logit info "Downloading from: $download_url"

    # Download with verification
    curl -L -o "/tmp/v2ray-plugin.tar.gz" "$download_url" || {
        logit error "Failed to download v2ray-plugin"
        exit 1
    }

    # Ensure writability and clean attributes before extraction
    ensure_writable_and_clean
    # Extract and verify
    cd /tmp
    tar xzf v2ray-plugin.tar.gz || {
        logit error "Failed to extract v2ray-plugin archive"
        exit 1
    }

    # Find the extracted binary (filename may vary)
    local binary_path
    binary_path=$(find /tmp -name "v2ray-plugin_*" -type f -executable | head -n1)

    if [[ -z "$binary_path" ]]; then
        logit error "Could not find v2ray-plugin binary after extraction"
        exit 1
    fi

    # Ensure writability and clean attributes before copying
    ensure_writable_and_clean
    # Copy to system location
    cp "$binary_path" /usr/bin/v2ray-plugin || {
        logit error "Failed to copy v2ray-plugin to /usr/bin/"
        exit 1
    }

    chmod +x /usr/bin/v2ray-plugin

    # Verify installation
    if command -v v2ray-plugin >/dev/null 2>&1; then
        logit info "v2ray-plugin version: $(v2ray-plugin --version 2>/dev/null || echo "unknown")"
    else
        logit error "v2ray-plugin installation verification failed"
        exit 1
    fi
}

# Create directories
create_directories() {
    logit info "Creating required directories..."

    # Ensure writability and clean attributes before creating directories
    ensure_writable_and_clean
    mkdir -p /etc/shadowsocks-libev
    mkdir -p /usr/local/bin
    mkdir -p /etc/systemd/system
    mkdir -p /var/log

    # Set permissions
    chmod 755 /etc/shadowsocks-libev
}

# --- ФУНКЦИИ СОЗДАНИЯ ФАЙЛОВ (с использованием шаблонов и printf) ---

# Create main configuration script using a template string and printf
create_main_script() {
    logit info "Creating main configuration script..."

    # Ensure writability and clean attributes before creating the script file
    ensure_writable_and_clean

    # Check if the target file exists and remove immutable attribute if it does
    if [[ -f /usr/local/bin/start-v2ray-multi.sh ]]; then
        logit info "Checking /usr/local/bin/start-v2ray-multi.sh for immutable attribute..."
        if lsattr /usr/local/bin/start-v2ray-multi.sh 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from /usr/local/bin/start-v2ray-multi.sh"
            chattr -i /usr/local/bin/start-v2ray-multi.sh 2>/dev/null || logit warning "Could not remove immutable attribute from /usr/local/bin/start-v2ray-multi.sh, continuing..."
        fi
    fi

    # Шаблон для основного скрипта - используем одинарные кавычки в heredoc,
    # чтобы переменные не подставлялись инсталлером
    local main_script_template
    main_script_template=$(
        cat << 'TEMPLATE_EOF'
#!/bin/bash
set -euo pipefail

LOCKTAG="v2ray-multi"
LOCKFILE="/var/lock/$LOCKTAG.lock"

logit() {
  local level=${1:-info}
  local msg=${2:-}
  echo "$(date -u '+%Y-%m-%d %H:%M:%S') [${level^^}]: $msg" >&2
  logger -p "user.$level" -t "$LOCKTAG" "$msg"
}

acquire_lock() {
  exec 200>"$LOCKFILE"
  if ! flock -w 20 200; then
    logit error "Deadlock/timeout, script already running"
    exit 98
  fi
  trap 'rm -f "$LOCKFILE"' EXIT
}
acquire_lock

rollback() {
  logit error "ROLLBACK due to error at line $LINENO"
  local LATEST_BAK
  LATEST_BAK=$(ls -tp /var/tmp/v2ray_ports.list.bak.* 2>/dev/null | head -n1 || true)
  if [[ -f "$LATEST_BAK" ]] && sha256sum -c "${LATEST_BAK}.sha256" &>/dev/null; then
    cp "$LATEST_BAK" /etc/v2ray_ports.list && chmod 600 /etc/v2ray_ports.list
    logit info "Ports restored from SHA-verified backup"
  fi
  local LATEST_LOG_BAK
  LATEST_LOG_BAK=$(ls -tp /var/tmp/v2ray-multi.log.bak.* 2>/dev/null | head -n1 || true)
  if [[ -f "$LATEST_LOG_BAK" ]] && sha256sum -c "${LATEST_LOG_BAK}.sha256" &>/dev/null; then
    cp "$LATEST_LOG_BAK" /var/log/v2ray-multi.log && chmod 600 /var/log/v2ray-multi.log
    logit info "Log restored from SHA-verified backup"
  fi
  logit error "V2RAY-MULTI rollback completed"
}
trap 'rollback' ERR

check_util() {
  for util in pwgen shuf awk ss ss-server logger sha256sum flock systemctl chmod chown df v2ray-plugin; do
    if ! command -v "$util" &>/dev/null; then
      logit error "Utility/binary $util not found"
      exit 2
    fi
  done
  FREE_KB=$(df / | awk 'NR==2{print $4}')
  if (( FREE_KB < 20480 )); then
    logit error "Disk space critically low (<20MB)!"
    exit 10
  fi
}
check_util

NUM_PORTS=${V2RAY_NUM_PORTS:-7}
LOG="/var/log/v2ray-multi.log"
BAK_TIME=$(date +%s)

# Backup existing files
if [ -f /etc/v2ray_ports.list ]; then
  # Check and remove immutable attribute before backup if it exists
  logit info "Checking /etc/v2ray_ports.list for immutable attribute before backup..."
  if lsattr /etc/v2ray_ports.list 2>/dev/null | grep -q 'i'; then
      logit info "Removing immutable attribute from /etc/v2ray_ports.list"
      chattr -i /etc/v2ray_ports.list 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/v2ray_ports.list, continuing..."
  fi
  cp /etc/v2ray_ports.list "/var/tmp/v2ray_ports.list.bak.$BAK_TIME"
  sha256sum "/var/tmp/v2ray_ports.list.bak.$BAK_TIME" >"/var/tmp/v2ray_ports.list.bak.$BAK_TIME.sha256"
fi

if [ -f "$LOG" ]; then
  # Check and remove immutable attribute before backup if it exists
  logit info "Checking $LOG for immutable attribute before backup..."
  if lsattr "$LOG" 2>/dev/null | grep -q 'i'; then
      logit info "Removing immutable attribute from $LOG"
      chattr -i "$LOG" 2>/dev/null || logit warning "Could not remove immutable attribute from $LOG, continuing..."
  fi
  cp "$LOG" "/var/tmp/v2ray-multi.log.bak.$BAK_TIME"
  sha256sum "/var/tmp/v2ray-multi.log.bak.$BAK_TIME" >"/var/tmp/v2ray-multi.log.bak.$BAK_TIME.sha256"
fi

# Cleanup old backups (older than 7 days)
find /var/tmp -name 'v2ray_ports.list.bak.*' -mtime +7 -delete
find /var/tmp -name 'v2ray_ports.list.bak.*.sha256' -mtime +7 -delete
find /var/tmp -name 'v2ray-multi.log.bak.*' -mtime +7 -delete
find /var/tmp -name 'v2ray-multi.log.bak.*.sha256' -mtime +7 -delete

# Clear log file
: >"$LOG"
chmod 600 "$LOG"
chown root:root "$LOG"

# Generate random port range for main ports
RANDOM_START=$((RANDOM % (65000 - 1065 - 200) + 1065))
RANDOM_END=$((RANDOM_START + 199))
logit info "Port rotation range for main services [$RANDOM_START-$RANDOM_END]"

# Get currently used ports
ALL_USED_PORTS=$(ss -lntupH 2>/dev/null | awk '{split($5,a,":"); n=a[length(a)]; if(n~/^[0-9]+$/) print n;}' | sort -n | uniq)
declare -A USED_PORTS_MAP
while IFS= read -r port; do
  [[ -n "$port" ]] && USED_PORTS_MAP["$port"]=1
done <<< "$ALL_USED_PORTS"

port_in_use() {
  local port=$1
  [[ -n "${USED_PORTS_MAP[$port]+isset}" ]]
}

# Find available ports for main services
AVAILABLE_PORTS=()
for PORT in $(seq "$RANDOM_START" "$RANDOM_END"); do
  port_in_use "$PORT" && continue
  AVAILABLE_PORTS+=("$PORT")
  if [[ ${#AVAILABLE_PORTS[@]} -ge $NUM_PORTS ]]; then
    break
  fi
done

if [[ ${#AVAILABLE_PORTS[@]} -lt $NUM_PORTS ]]; then
    logit error "Could not find $NUM_PORTS available ports in range [$RANDOM_START-$RANDOM_END] for main services"
    exit 1
fi

# Check if the target file exists and remove immutable attribute if it does
logit info "Checking /etc/v2ray_ports.list for immutable attribute before writing..."
if [[ -f /etc/v2ray_ports.list ]]; then
    if lsattr /etc/v2ray_ports.list 2>/dev/null | grep -q 'i'; then
        logit info "Removing immutable attribute from /etc/v2ray_ports.list"
        chattr -i /etc/v2ray_ports.list 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/v2ray_ports.list, continuing..."
    fi
else
    logit info "/etc/v2ray_ports.list does not exist yet, will be created."
fi

# Check writability before writing the main ports list
if ! touch /etc/v2ray_ports.list 2>/dev/null; then
    logit error "Cannot write /etc/v2ray_ports.list. Read-only FS?"
    exit 1
fi
printf '%s\n' "${AVAILABLE_PORTS[@]}" > /etc/v2ray_ports.list || {
    logit error "Cannot write /etc/v2ray_ports.list. Read-only FS?"
    exit 1
}

# Handle password rotation
ROTATE_ENV="${ROTATE_PW:-}"
DO_ROTATE=$((RANDOM % 2))
if [[ "$ROTATE_ENV" == "1" || "$DO_ROTATE" -eq 1 ]]; then
  PASSWORD=$(pwgen 16 1)
  # Check if the target file exists and remove immutable attribute if it does
  logit info "Checking /etc/v2ray_passwd for immutable attribute before writing password..."
  if [[ -f /etc/v2ray_passwd ]]; then
    if lsattr /etc/v2ray_passwd 2>/dev/null | grep -q 'i'; then
        logit info "Removing immutable attribute from /etc/v2ray_passwd"
        chattr -i /etc/v2ray_passwd 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/v2ray_passwd, continuing..."
    fi
  else
    logit info "/etc/v2ray_passwd does not exist yet, will be created."
  fi

  # Check writability before writing the password file
  if ! touch /etc/v2ray_passwd 2>/dev/null; then
      logit error "Cannot write /etc/v2ray_passwd. Read-only FS?"
      exit 1
  fi
  echo "$PASSWORD" > /etc/v2ray_passwd || {
      logit error "Cannot write /etc/v2ray_passwd. Read-only FS?"
      exit 1
  }
  chmod 600 /etc/v2ray_passwd
  logit info "Password and ports rotated (ENV='$ROTATE_ENV' RANDOM='$DO_ROTATE')"
else
  if [[ -f /etc/v2ray_passwd ]]; then
      # Check and remove immutable attribute before reading if it exists
      logit info "Checking /etc/v2ray_passwd for immutable attribute before reading..."
      if lsattr /etc/v2ray_passwd 2>/dev/null | grep -q 'i'; then
          logit info "Removing immutable attribute from /etc/v2ray_passwd"
          chattr -i /etc/v2ray_passwd 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/v2ray_passwd, continuing..."
      fi
      PASSWORD="$(cat /etc/v2ray_passwd)"
      logit info "No rotation (ENV='$ROTATE_ENV' RANDOM='$DO_ROTATE')"
  else
      PASSWORD=$(pwgen 16 1)
      # Check if the target file exists and remove immutable attribute if it does (it shouldn't)
      logit info "Checking /etc/v2ray_passwd for immutable attribute (should not exist)..."
      if [[ -f /etc/v2ray_passwd ]]; then
        if lsattr /etc/v2ray_passwd 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from /etc/v2ray_passwd"
            chattr -i /etc/v2ray_passwd 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/v2ray_passwd, continuing..."
        fi
      else
        logit info "/etc/v2ray_passwd does not exist yet, will be created."
      fi

      # Check writability before writing the password file
      if ! touch /etc/v2ray_passwd 2>/dev/null; then
          logit error "Cannot write /etc/v2ray_passwd. Read-only FS?"
          exit 1
      fi
      echo "$PASSWORD" > /etc/v2ray_passwd || {
          logit error "Cannot write /etc/v2ray_passwd. Read-only FS?"
          exit 1
      }
      chmod 600 /etc/v2ray_passwd
      logit info "Generated initial password and ports (ENV='$ROTATE_ENV' RANDOM='$DO_ROTATE')"
  fi
fi

METHOD="chacha20-ietf-poly1305"
PLUGIN="/usr/bin/v2ray-plugin"
if [[ ! -x "$PLUGIN" ]]; then
    logit error "v2ray-plugin not found or not executable: $PLUGIN"
    exit 2
fi

# Random WebSocket path selection
WS_PATHS=(
  "/ws"
  "/websocket"
  "/api/ws"
  "/api/websocket"
  "/sockjs"
  "/sockjs/websocket"
  "/tunnel"
  "/tunnel/ws"
)
RANDOM_WS_PATH="${WS_PATHS[RANDOM % ${#WS_PATHS[@]}]}"
logit info "Selected random WebSocket path: $RANDOM_WS_PATH"

# Create configuration files and manage main services
for port in "${AVAILABLE_PORTS[@]}"; do
    CONFIG_FILE="/etc/shadowsocks-libev/${port}.json"
    # Check if the target file exists and remove immutable attribute if it does
    logit info "Checking $CONFIG_FILE for immutable attribute before writing..."
    if [[ -f "$CONFIG_FILE" ]]; then
        if lsattr "$CONFIG_FILE" 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from $CONFIG_FILE"
            chattr -i "$CONFIG_FILE" 2>/dev/null || logit warning "Could not remove immutable attribute from $CONFIG_FILE, continuing..."
        fi
    else
        logit info "$CONFIG_FILE does not exist yet, will be created."
    fi

    # Check writability before creating config file
    if ! touch "$CONFIG_FILE" 2>/dev/null; then
        logit error "Cannot create config file $CONFIG_FILE. Read-only FS?"
        continue # Продолжаем с другими портами
    fi
    # Используем printf для создания JSON-файла
    printf '{\n    "server_port":%s,\n    "password":"%s",\n    "method":"%s",\n    "plugin":"%s",\n    "plugin_opts":"server;path=%s"\n}\n' \
           "$port" "$PASSWORD" "$METHOD" "$PLUGIN" "$RANDOM_WS_PATH" > "$CONFIG_FILE" || {
               logit error "Failed to create config file for main port $port"
               continue # Продолжаем с другими портами
           }
    chmod 600 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    logit info "Created config for main port $port: $CONFIG_FILE"
done

# Stop old main services
for old_port in $(systemctl list-units --type=service --state=active --no-legend 2>/dev/null | grep -oE 'ss-server-v2ray@[0-9]+\.service' | sed 's/ss-server-v2ray@//;s/\.service//'); do
    if ! printf '%s\n' "${AVAILABLE_PORTS[@]}" | grep -q "^${old_port}$"; then
        systemctl stop --now "ss-server-v2ray@${old_port}.service" 2>/dev/null || true
        systemctl disable "ss-server-v2ray@${old_port}.service" 2>/dev/null || true
        logit info "Stopped and disabled unit for old main port $old_port"
    fi
done

# Start main services for new ports
for port in "${AVAILABLE_PORTS[@]}"; do
    systemctl enable --now "ss-server-v2ray@${port}.service" 2>/dev/null || {
        logit warning "Failed to start main service for port $port"
    }
    logit info "Started main unit for port $port"
done

logit info "All main units updated. Installation complete."
TEMPLATE_EOF
    )

    # Write the template to file after ensuring it's writable and clean
    printf '%s\n' "$main_script_template" > /usr/local/bin/start-v2ray-multi.sh
    chmod +x /usr/local/bin/start-v2ray-multi.sh
    logit info "Main configuration script created and made executable"
}

# Create systemd template unit using printf
create_systemd_template() {
    logit info "Creating systemd template unit..."

    # Ensure writability and clean attributes before creating the service file
    ensure_writable_and_clean

    # Check if the target file exists and remove immutable attribute if it does
    if [[ -f /etc/systemd/system/ss-server-v2ray@.service ]]; then
        logit info "Checking /etc/systemd/system/ss-server-v2ray@.service for immutable attribute..."
        if lsattr /etc/systemd/system/ss-server-v2ray@.service 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from /etc/systemd/system/ss-server-v2ray@.service"
            chattr -i /etc/systemd/system/ss-server-v2ray@.service 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/systemd/system/ss-server-v2ray@.service, continuing..."
        fi
    fi

    # Шаблон для systemd-юнита
    local systemd_template
    systemd_template=$(
        cat << 'SYSTEMD_EOF'
[Unit]
Description=Shadowsocks-libev server with v2ray-plugin (ws) on port %i
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/%i.json
Restart=always
RestartSec=5
User=root
Group=root

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
    )

    # Check writability before writing the service file
    if ! touch /etc/systemd/system/ss-server-v2ray@.service 2>/dev/null; then
        logit error "Cannot write /etc/systemd/system/ss-server-v2ray@.service. Read-only FS?"
        exit 1
    fi
    printf '%s\n' "$systemd_template" > /etc/systemd/system/ss-server-v2ray@.service
}

# Create obfuscation script using a template string and printf
create_obfuscation_script() {
    logit info "Creating obfuscation script..."

    # Ensure writability and clean attributes before creating the script file
    ensure_writable_and_clean

    # Check if the target file exists and remove immutable attribute if it does
    if [[ -f /usr/local/bin/send-nonstandard-frame.sh ]]; then
        logit info "Checking /usr/local/bin/send-nonstandard-frame.sh for immutable attribute..."
        if lsattr /usr/local/bin/send-nonstandard-frame.sh 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from /usr/local/bin/send-nonstandard-frame.sh"
            chattr -i /usr/local/bin/send-nonstandard-frame.sh 2>/dev/null || logit warning "Could not remove immutable attribute from /usr/local/bin/send-nonstandard-frame.sh, continuing..."
        fi
    fi

    local obfuscation_script_template
    obfuscation_script_template=$(
        cat << 'OBFUSCATION_EOF'
#!/bin/bash
set -euo pipefail

LOCKTAG="send-nonstandard-frame"
LOCKFILE="/var/lock/${LOCKTAG}.lock"

logit() {
  local level="${1:-info}"
  local msg="${2:-}"
  echo "$(date -u '+%Y-%m-%d %H:%M:%S') [${level^^}]: $msg" >&2
  logger -p "user.$level" -t "$LOCKTAG" "$msg"
}

acquire_lock() {
  exec 200>"$LOCKFILE"
  flock -w 20 200 || {
    logit error "Deadlock/timeout, script already running"
    exit 98
  }
  trap 'rm -f "$LOCKFILE"' EXIT
}
acquire_lock

rollback() {
  logit error "ROLLBACK: Error at line $LINENO"
  local LATEST_LOG_BAK
  LATEST_LOG_BAK=$(ls -tp /var/tmp/send-nonstandard-frame.log.bak.* 2>/dev/null | head -n1 || true)
  if [[ -f "$LATEST_LOG_BAK" ]] && sha256sum -c "${LATEST_LOG_BAK}.sha256" &>/dev/null; then
    cp "$LATEST_LOG_BAK" /var/log/send-nonstandard-frame.log && chmod 600 /var/log/send-nonstandard-frame.log
    logit info "Log restored from SHA-verified backup"
  fi
}
trap 'rollback' ERR

for util in ss nc pwgen flock sha256sum logger awk chmod chown socat; do
  command -v "$util" &>/dev/null || {
    logit error "$util not found!"
    exit 2
  }
done

LOG="/var/log/send-nonstandard-frame.log"
BAK_TIME="$(date +%s)"
if [[ -f "$LOG" ]]; then
  # Check and remove immutable attribute before backup if it exists
  logit info "Checking $LOG for immutable attribute before backup..."
  if lsattr "$LOG" 2>/dev/null | grep -q 'i'; then
      logit info "Removing immutable attribute from $LOG"
      chattr -i "$LOG" 2>/dev/null || logit warning "Could not remove immutable attribute from $LOG, continuing..."
  fi
  cp "$LOG" "/var/tmp/send-nonstandard-frame.log.bak.$BAK_TIME"
  sha256sum "/var/tmp/send-nonstandard-frame.log.bak.$BAK_TIME" >"/var/tmp/send-nonstandard-frame.log.bak.$BAK_TIME.sha256"
  chmod 600 "/var/tmp/send-nonstandard-frame.log.bak.$BAK_TIME" "/var/tmp/send-nonstandard-frame.log.bak.$BAK_TIME.sha256"
fi
find /var/tmp -name 'send-nonstandard-frame.log.bak.*' -mtime +7 -delete
find /var/tmp -name 'send-nonstandard-frame.log.bak.*.sha256' -mtime +7 -delete

exec >>"$LOG" 2>&1
chmod 600 "$LOG"
chown root:root "$LOG"

logit info "Starting obfuscation script..."

# Получаем список портов VPN из файла (если он существует)
VPN_PORTS=()
if [[ -f /etc/v2ray_ports.list ]]; then
    # Check and remove immutable attribute before reading if it exists
    logit info "Checking /etc/v2ray_ports.list for immutable attribute before reading VPN ports..."
    if lsattr /etc/v2ray_ports.list 2>/dev/null | grep -q 'i'; then
        logit info "Removing immutable attribute from /etc/v2ray_ports.list"
        chattr -i /etc/v2ray_ports.list 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/v2ray_ports.list, continuing..."
    fi
    readarray -t VPN_PORTS < /etc/v2ray_ports.list
    logit info "Loaded VPN ports: ${VPN_PORTS[*]}"
else
    logit info "No VPN ports file found, assuming none."
fi

# Получаем список текущих портов обфускации из файла (если он существует)
CURRENT_OBF_PORTS_FILE="/tmp/current_obf_ports.list"
CURRENT_OBF_PORTS=()
if [[ -f "$CURRENT_OBF_PORTS_FILE" ]]; then
    # Check and remove immutable attribute before reading if it exists
    logit info "Checking $CURRENT_OBF_PORTS_FILE for immutable attribute before reading old obf ports..."
    if lsattr "$CURRENT_OBF_PORTS_FILE" 2>/dev/null | grep -q 'i'; then
        logit info "Removing immutable attribute from $CURRENT_OBF_PORTS_FILE"
        chattr -i "$CURRENT_OBF_PORTS_FILE" 2>/dev/null || logit warning "Could not remove immutable attribute from $CURRENT_OBF_PORTS_FILE, continuing..."
    fi
    readarray -t CURRENT_OBF_PORTS < "$CURRENT_OBF_PORTS_FILE"
    logit info "Loaded previous obfuscation ports: ${CURRENT_OBF_PORTS[*]}"
    # Убиваем старые процессы socat для этих портов
    for port in "${CURRENT_OBF_PORTS[@]}"; do
        pkill -f "socat UDP-LISTEN:$port" 2>/dev/null || true
        logit info "Killed old obfuscation listener on UDP port $port"
    done
else
    logit info "No previous obfuscation ports file found."
fi

# Собираем все занятые порты (системные, VPN, старые обфускации)
ALL_USED_PORTS=$(ss -lntupH 2>/dev/null | awk '{split($5,a,":"); n=a[length(a)]; if(n~/^[0-9]+$/) print n;}' | sort -n | uniq)
declare -A USED_PORTS_MAP
while IFS= read -r port; do
  [[ -n "$port" ]] && USED_PORTS_MAP["$port"]=1
done <<< "$ALL_USED_PORTS"

# Добавляем порты VPN в занятые
for port in "${VPN_PORTS[@]}"; do
    USED_PORTS_MAP["$port"]=1
done

# Добавляем старые порты обфускации в занятые
for port in "${CURRENT_OBF_PORTS[@]}"; do
    USED_PORTS_MAP["$port"]=1
done

port_in_use() {
  local port=$1
  [[ -n "${USED_PORTS_MAP[$port]+isset}" ]]
}

# Генерируем новый случайный диапазон для поиска
RANDOM_START=$((RANDOM % (65000 - 1065 - 500) + 1065))
RANDOM_END=$((RANDOM_START + 499))
logit info "Scanning for new obfuscation ports in range $RANDOM_START-$RANDOM_END..."

# Находим 7 новых доступных портов
NEW_OBF_PORTS=()
for PORT in $(seq "$RANDOM_START" "$RANDOM_END"); do
  port_in_use "$PORT" && continue
  NEW_OBF_PORTS+=("$PORT")
  if [[ ${#NEW_OBF_PORTS[@]} -ge 7 ]]; then
    break
  fi
done

if [[ ${#NEW_OBF_PORTS[@]} -lt 7 ]]; then
    logit error "Could not find 7 available ports for obfuscation in range [$RANDOM_START-$RANDOM_END]. Found only ${#NEW_OBF_PORTS[@]}."
    # Попробовать снова или использовать найденные?
    # Пока просто выйдем с ошибкой.
    exit 3
fi

logit info "Selected new obfuscation ports: ${NEW_OBF_PORTS[*]}"

# Открываем каждый новый порт с помощью socat и отправляем мусор
for port in "${NEW_OBF_PORTS[@]}"; do
    # socat UDP-LISTEN:$port,fork EXEC:'dd if=/dev/urandom bs=1024 count=10',pty &
    # Используем SYSTEM для большей гибкости и чтобы не зависеть от pty
    socat UDP-LISTEN:$port,fork SYSTEM:'dd if=/dev/urandom bs=1024 count=10 2>/dev/null; sleep 1' &
    logit info "Started obfuscation listener on UDP port $port"
done

# Сохраняем список новых портов обфускации в файл для следующего запуска
# Remove immutable attribute before writing the current obf ports list (if it exists)
logit info "Checking $CURRENT_OBF_PORTS_FILE for immutable attribute before writing new obf ports..."
if [[ -f "$CURRENT_OBF_PORTS_FILE" ]]; then
    if lsattr "$CURRENT_OBF_PORTS_FILE" 2>/dev/null | grep -q 'i'; then
        logit info "Removing immutable attribute from $CURRENT_OBF_PORTS_FILE"
        chattr -i "$CURRENT_OBF_PORTS_FILE" 2>/dev/null || logit warning "Could not remove immutable attribute from $CURRENT_OBF_PORTS_FILE, continuing..."
    fi
else
    logit info "$CURRENT_OBF_PORTS_FILE does not exist yet, will be created."
fi
# Check writability before writing the current obf ports list
if ! touch "$CURRENT_OBF_PORTS_FILE" 2>/dev/null; then
    logit error "Cannot write $CURRENT_OBF_PORTS_FILE. Read-only FS?"
    exit 1
fi
printf '%s\n' "${NEW_OBF_PORTS[@]}" > "$CURRENT_OBF_PORTS_FILE"
chmod 600 "$CURRENT_OBF_PORTS_FILE"
logit info "Saved new obfuscation ports to $CURRENT_OBF_PORTS_FILE"

logit info "Obfuscation listeners updated."
exit 0
OBFUSCATION_EOF
    )

    # Check writability before writing the script file
    if ! touch /usr/local/bin/send-nonstandard-frame.sh 2>/dev/null; then
        logit error "Cannot write /usr/local/bin/send-nonstandard-frame.sh. Read-only FS?"
        exit 1
    fi
    printf '%s\n' "$obfuscation_script_template" > /usr/local/bin/send-nonstandard-frame.sh
    chmod +x /usr/local/bin/send-nonstandard-frame.sh
    logit info "Obfuscation script created and made executable"
}

# Create systemd service for obfuscation using printf
create_obfuscation_service() {
    logit info "Creating obfuscation systemd service..."

    # Ensure writability and clean attributes before creating the service file
    ensure_writable_and_clean

    # Check if the target file exists and remove immutable attribute if it does
    if [[ -f /etc/systemd/system/send-nonstandard-frame.service ]]; then
        logit info "Checking /etc/systemd/system/send-nonstandard-frame.service for immutable attribute..."
        if lsattr /etc/systemd/system/send-nonstandard-frame.service 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from /etc/systemd/system/send-nonstandard-frame.service"
            chattr -i /etc/systemd/system/send-nonstandard-frame.service 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/systemd/system/send-nonstandard-frame.service, continuing..."
        fi
    fi

    local obfuscation_service_template
    obfuscation_service_template=$(
        cat << 'OBFUSCATION_SERVICE_EOF'
[Unit]
Description=Send nonstandard UDP/TCP frames for v2ray system hardening
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/send-nonstandard-frame.sh
WorkingDirectory=/tmp
RemainAfterExit=true
Restart=on-failure
RestartSec=45
TimeoutStartSec=1300
StandardOutput=journal+console
StandardError=journal+console
User=root
Nice=5
OOMScoreAdjust=500
LimitNOFILE=8192
LimitNPROC=256

# Security
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
ReadWritePaths=/tmp /var/log /etc

Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
OBFUSCATION_SERVICE_EOF
    )

    # Check writability before writing the service file
    if ! touch /etc/systemd/system/send-nonstandard-frame.service 2>/dev/null; then
        logit error "Cannot write /etc/systemd/system/send-nonstandard-frame.service. Read-only FS?"
        exit 1
    fi
    printf '%s\n' "$obfuscation_service_template" > /etc/systemd/system/send-nonstandard-frame.service
}

# Create systemd timer for obfuscation using printf
create_obfuscation_timer() {
    logit info "Creating obfuscation systemd timer..."

    # Ensure writability and clean attributes before creating the timer file
    ensure_writable_and_clean

    # Check if the target file exists and remove immutable attribute if it does
    if [[ -f /etc/systemd/system/send-nonstandard-frame.timer ]]; then
        logit info "Checking /etc/systemd/system/send-nonstandard-frame.timer for immutable attribute..."
        if lsattr /etc/systemd/system/send-nonstandard-frame.timer 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from /etc/systemd/system/send-nonstandard-frame.timer"
            chattr -i /etc/systemd/system/send-nonstandard-frame.timer 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/systemd/system/send-nonstandard-frame.timer, continuing..."
        fi
    fi

    local obfuscation_timer_template
    obfuscation_timer_template=$(
        cat << 'OBFUSCATION_TIMER_EOF'
[Unit]
Description=Timer for send-nonstandard-frame.sh
Requires=send-nonstandard-frame.service
After=network-online.target
Wants=network-online.target

[Timer]
OnUnitActiveSec=1h
RandomizedDelaySec=40min
AccuracySec=2min
Persistent=true
Unit=send-nonstandard-frame.service

WakeSystem=true

[Install]
WantedBy=timers.target
OBFUSCATION_TIMER_EOF
    )

    # Check writability before writing the timer file
    if ! touch /etc/systemd/system/send-nonstandard-frame.timer 2>/dev/null; then
        logit error "Cannot write /etc/systemd/system/send-nonstandard-frame.timer. Read-only FS?"
        exit 1
    fi
    printf '%s\n' "$obfuscation_timer_template" > /etc/systemd/system/send-nonstandard-frame.timer
}

# Create main service using printf
create_main_service() {
    logit info "Creating main systemd service..."

    # Ensure writability and clean attributes before creating the service file
    ensure_writable_and_clean

    # Check if the target file exists and remove immutable attribute if it does
    if [[ -f /etc/systemd/system/v2ray-multi.service ]]; then
        logit info "Checking /etc/systemd/system/v2ray-multi.service for immutable attribute..."
        if lsattr /etc/systemd/system/v2ray-multi.service 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from /etc/systemd/system/v2ray-multi.service"
            chattr -i /etc/systemd/system/v2ray-multi.service 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/systemd/system/v2ray-multi.service, continuing..."
        fi
    fi

    local main_service_template
    main_service_template=$(
        cat << 'MAIN_SERVICE_EOF'
[Unit]
Description=V2Ray Proxy/ShadowSocks (ws) dynamic restart and port rotation
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/start-v2ray-multi.sh
WorkingDirectory=/tmp
User=root
Nice=5
StandardOutput=journal+console
StandardError=journal+console
Restart=on-failure
RestartSec=45
TimeoutStartSec=180
RemainAfterExit=true

# Security and resource limits
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
LimitNOFILE=8192
LimitNPROC=256
OOMScoreAdjust=500

ReadWritePaths=/tmp /var/log /var/tmp /etc /etc/systemd/system

Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
MAIN_SERVICE_EOF
    )

    # Check writability before writing the service file
    if ! touch /etc/systemd/system/v2ray-multi.service 2>/dev/null; then
        logit error "Cannot write /etc/systemd/system/v2ray-multi.service. Read-only FS?"
        exit 1
    fi
    printf '%s\n' "$main_service_template" > /etc/systemd/system/v2ray-multi.service
}

# Create main timer using printf
create_main_timer() {
    logit info "Creating main systemd timer..."

    # Ensure writability and clean attributes before creating the timer file
    ensure_writable_and_clean

    # Check if the target file exists and remove immutable attribute if it does
    if [[ -f /etc/systemd/system/v2ray-multi.timer ]]; then
        logit info "Checking /etc/systemd/system/v2ray-multi.timer for immutable attribute..."
        if lsattr /etc/systemd/system/v2ray-multi.timer 2>/dev/null | grep -q 'i'; then
            logit info "Removing immutable attribute from /etc/systemd/system/v2ray-multi.timer"
            chattr -i /etc/systemd/system/v2ray-multi.timer 2>/dev/null || logit warning "Could not remove immutable attribute from /etc/systemd/system/v2ray-multi.timer, continuing..."
        fi
    fi

    local main_timer_template
    main_timer_template=$(
        cat << 'MAIN_TIMER_EOF'
[Unit]
Description=V2Ray/SS (ws) periodic dynamic restart every 30 min
After=network-online.target
Wants=network-online.target

[Timer]
OnBootSec=1min
OnUnitActiveSec=30min
RandomizedDelaySec=11min
AccuracySec=1min
Persistent=true
Unit=v2ray-multi.service
WakeSystem=true

[Install]
WantedBy=timers.target
MAIN_TIMER_EOF
    )

    # Check writability before writing the timer file
    if ! touch /etc/systemd/system/v2ray-multi.timer 2>/dev/null; then
        logit error "Cannot write /etc/systemd/system/v2ray-multi.timer. Read-only FS?"
        exit 1
    fi
    printf '%s\n' "$main_timer_template" > /etc/systemd/system/v2ray-multi.timer
}

# --- ФИНАЛИЗАЦИЯ ---

# Finalize installation
finalize_installation() {
    logit info "Reloading systemd daemon..."
    # Ensure writability and clean attributes before daemon-reload (indirectly checks systemd dir)
    ensure_writable_and_clean
    systemctl daemon-reload

    logit info "Enabling and starting services..."
    # Включаем таймеры
    # Ensure writability and clean attributes before enabling services (indirectly checks systemd dir)
    ensure_writable_and_clean
    systemctl enable v2ray-multi.timer
    systemctl enable send-nonstandard-frame.timer

    # Запускаем таймеры (это запустит сервисы по расписанию, но также можно запустить сразу)
    systemctl start v2ray-multi.timer
    systemctl start send-nonstandard-frame.timer

    # Запускаем основной сервис *сразу* после установки
    logit info "Starting main configuration script immediately after installation..."
    systemctl start v2ray-multi.service

    # Запускаем обфускационный сервис *сразу* после установки
    logit info "Starting obfuscation configuration script immediately after installation..."
    systemctl start send-nonstandard-frame.service

    logit info "Verifying services..."
    systemctl status v2ray-multi.timer --no-pager
    systemctl status send-nonstandard-frame.timer --no-pager

    logit info "Listing active timers..."
    systemctl list-timers --all | grep -E "(v2ray-multi|send-nonstandard-frame)"

    logit info "Listing active services..."
    systemctl list-units --type=service --state=active | grep -E "(ss-server-v2ray@|send-nonstandard-frame)"

    logit info "Installation completed successfully!"
    logit info "Services will automatically start on boot and rotate ports every 30 minutes"
}

# --- ОСНОВНАЯ ФУНКЦИЯ ---

# Main installation function
main() {
    logit info "Starting V2Ray-Plugin Multi-Port Auto-Rotator installation..."

    acquire_lock
    trap 'rollback' ERR

    validate_system
    check_dependencies
    install_packages
    install_v2ray_plugin
    create_directories
    create_main_script
    create_systemd_template
    create_obfuscation_script
    create_obfuscation_service
    create_obfuscation_timer
    create_main_service
    create_main_timer
    finalize_installation

    logit info "Installation completed successfully!"
}

# Run main function
main "$@"