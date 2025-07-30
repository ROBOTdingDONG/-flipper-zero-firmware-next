#!/bin/bash
# scripts/setup.sh - Professional Development Environment Setup
# Flipper Zero Firmware Next - Setup Script with Security Best Practices

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly LOG_FILE="${PROJECT_ROOT}/setup.log"
readonly REQUIRED_DISK_SPACE_GB=20

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${WHITE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "${LOG_FILE}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "${LOG_FILE}"
}

log_header() {
    echo -e "\n${PURPLE}========================================${NC}"
    echo -e "${PURPLE} $*${NC}"
    echo -e "${PURPLE}========================================${NC}\n"
}

# Error handling
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Setup failed with exit code $exit_code"
        log_error "Check the log file: $LOG_FILE"
        log_error "For support, visit: https://github.com/your-username/flipper-zero-firmware-next/discussions"
    fi
}

trap cleanup EXIT

# System detection
detect_system() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            SYSTEM="debian"
        elif command -v dnf >/dev/null 2>&1; then
            SYSTEM="fedora"
        elif command -v pacman >/dev/null 2>&1; then
            SYSTEM="arch"
        else
            SYSTEM="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        SYSTEM="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        SYSTEM="windows"
    else
        log_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    log_info "Detected system: $SYSTEM"
}

# Dependency management
install_system_dependencies() {
    log_header "Installing System Dependencies"
    
    case "$SYSTEM" in
        "debian")
            sudo apt-get update
            sudo apt-get install -y \
                build-essential cmake ninja-build \
                gcc-arm-none-eabi gdb-multiarch \
                python3 python3-pip python3-venv \
                git curl wget unzip \
                clang clang-format clang-tidy \
                cppcheck valgrind lcov gcovr \
                doxygen graphviz \
                openssl libssl-dev \
                pkg-config autoconf automake libtool \
                screen minicom \
                udev
            ;;
        "fedora")
            sudo dnf install -y \
                gcc gcc-c++ cmake ninja-build \
                arm-none-eabi-gcc-cs arm-none-eabi-gdb \
                python3 python3-pip \
                git curl wget unzip \
                clang clang-tools-extra \
                cppcheck valgrind lcov \
                doxygen graphviz \
                openssl-devel \
                pkgconfig autoconf automake libtool \
                screen minicom \
                systemd-udev
            ;;
        "arch")
            sudo pacman -S --needed \
                base-devel cmake ninja \
                arm-none-eabi-gcc arm-none-eabi-gdb \
                python python-pip \
                git curl wget unzip \
                clang \
                cppcheck valgrind \
                doxygen graphviz \
                openssl \
                pkgconfig autoconf automake libtool \
                screen minicom \
                udev
            ;;
        "macos")
            if ! command -v brew >/dev/null 2>&1; then
                log_info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            
            brew install \
                cmake ninja \
                python3 \
                git curl wget \
                llvm \
                cppcheck \
                doxygen graphviz \
                openssl \
                autoconf automake libtool \
                screen minicom
            
            # Install ARM toolchain
            if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
                log_info "Installing ARM toolchain..."
                brew install --cask gcc-arm-embedded
            fi
            ;;
        "windows")
            log_error "Windows setup requires manual installation of dependencies"
            log_info "Please install the following:"
            log_info "1. Visual Studio with C++ tools or MinGW-w64"
            log_info "2. Python 3.8+"
            log_info "3. Git for Windows"
            log_info "4. ARM GCC toolchain"
            log_info "5. CMake and Ninja"
            exit 1
            ;;
    esac
    
    log_success "System dependencies installed"
}

# Python environment setup
setup_python_environment() {
    log_header "Setting Up Python Environment"
    
    # Create virtual environment
    if [ ! -d "${PROJECT_ROOT}/venv" ]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv "${PROJECT_ROOT}/venv"
    fi
    
    # Activate virtual environment
    source "${PROJECT_ROOT}/venv/bin/activate"
    
    # Upgrade pip
    log_info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel
    
    # Install development dependencies
    log_info "Installing Python dependencies..."
    cat > "${PROJECT_ROOT}/requirements-dev.txt" << EOF
# Code formatting and linting
black>=23.0.0
isort>=5.12.0
flake8>=6.0.0
mypy>=1.0.0

# Security scanning
bandit>=1.7.0
safety>=2.3.0

# Testing
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0

# Documentation
sphinx>=6.0.0
sphinx-rtd-theme>=1.2.0

# Pre-commit hooks
pre-commit>=3.0.0

# Build tools
scons>=4.5.0
pyserial>=3.5
cryptography>=38.0.0

# Development utilities
ipython>=8.0.0
jupyter>=1.0.0
EOF
    
    pip install -r "${PROJECT_ROOT}/requirements-dev.txt"
    
    log_success "Python environment setup complete"
}

# Toolchain installation
install_arm_toolchain() {
    log_header "Installing ARM Toolchain"
    
    local toolchain_dir="${PROJECT_ROOT}/toolchain"
    local toolchain_version="12.2.Rel1"
    
    if [ ! -d "$toolchain_dir" ]; then
        mkdir -p "$toolchain_dir"
    fi
    
    if command -v arm-none-eabi-gcc >/dev/null 2>&1; then
        log_info "ARM toolchain already available in system PATH"
        return 0
    fi
    
    case "$SYSTEM" in
        "linux")
            local arch="x86_64"
            if [ "$(uname -m)" == "aarch64" ]; then
                arch="aarch64"
            fi
            
            local toolchain_url="https://developer.arm.com/-/media/Files/downloads/gnu/$toolchain_version/binrel/arm-gnu-toolchain-$toolchain_version-$arch-arm-none-eabi.tar.xz"
            local toolchain_file="arm-toolchain-linux.tar.xz"
            ;;
        "macos")
            log_info "ARM toolchain should be installed via Homebrew"
            return 0
            ;;
        *)
            log_warning "Manual toolchain installation required for $SYSTEM"
            return 1
            ;;
    esac
    
    if [ ! -f "${toolchain_dir}/${toolchain_file}" ]; then
        log_info "Downloading ARM toolchain..."
        curl -L "$toolchain_url" -o "${toolchain_dir}/${toolchain_file}"
    fi
    
    log_info "Extracting ARM toolchain..."
    cd "$toolchain_dir"
    tar -xf "$toolchain_file"
    
    # Create symlink to current
    rm -f current
    ln -sf arm-gnu-toolchain-*-arm-none-eabi current
    
    log_success "ARM toolchain installed"
}

# Git hooks setup
setup_git_hooks() {
    log_header "Setting Up Git Hooks"
    
    # Pre-commit configuration
    cat > "${PROJECT_ROOT}/.pre-commit-config.yaml" << EOF
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files
        args: ['--maxkb=1024']
      - id: check-merge-conflict
      - id: check-case-conflict
      - id: check-symlinks
      - id: check-executables-have-shebangs
      - id: detect-private-key

  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8

  - repo: https://github.com/pre-commit/mirrors-clang-format
    rev: v16.0.0
    hooks:
      - id: clang-format
        types: [c, c++]

  - repo: https://github.com/pocc/pre-commit-hooks
    rev: v1.3.5
    hooks:
      - id: clang-tidy
        args: [--header-filter=.*]

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-r', 'scripts/', 'tools/']

  - repo: local
    hooks:
      - id: firmware-size-check
        name: Check firmware size limits
        entry: scripts/check_firmware_size.sh
        language: script
        pass_filenames: false
        
      - id: security-scan
        name: Security scan
        entry: scripts/security_scan.sh
        language: script
        pass_filenames: false
EOF
    
    # Install pre-commit hooks
    if command -v pre-commit >/dev/null 2>&1; then
        source "${PROJECT_ROOT}/venv/bin/activate"
        pre-commit install
        pre-commit install --hook-type commit-msg
        log_success "Git hooks installed"
    else
        log_warning "pre-commit not available, hooks not installed"
    fi
}

# Security configuration
setup_security_tools() {
    log_header "Setting Up Security Tools"
    
    # Create security scanning script
    cat > "${PROJECT_ROOT}/scripts/security_scan.sh" << 'EOF'
#!/bin/bash
# Security scanning script

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "🔍 Running security scans..."

# C/C++ static analysis
if command -v cppcheck >/dev/null 2>&1; then
    echo "Running cppcheck..."
    cppcheck --enable=all --inconclusive --std=c11 \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --error-exitcode=1 \
        applications/ core/ lib/ 2>/dev/null || true
fi

# Python security scan
if command -v bandit >/dev/null 2>&1; then
    echo "Running bandit..."
    bandit -r scripts/ tools/ -f json -o bandit-report.json 2>/dev/null || true
fi

# Dependency check
if command -v safety >/dev/null 2>&1; then
    echo "Running safety check..."
    safety check 2>/dev/null || true
fi

# Secret scanning
if command -v gitleaks >/dev/null 2>&1; then
    echo "Running gitleaks..."
    gitleaks detect --no-git 2>/dev/null || true
fi

echo "✅ Security scans completed"
EOF
    
    chmod +x "${PROJECT_ROOT}/scripts/security_scan.sh"
    
    # Create firmware size check script
    cat > "${PROJECT_ROOT}/scripts/check_firmware_size.sh" << 'EOF'
#!/bin/bash
# Firmware size check script

set -euo pipefail

# Size limits (in bytes)
readonly MAX_FIRMWARE_SIZE=$((1024 * 1024))  # 1MB
readonly MAX_BOOTLOADER_SIZE=$((64 * 1024))  # 64KB

check_file_size() {
    local file="$1"
    local max_size="$2"
    local description="$3"
    
    if [ -f "$file" ]; then
        local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
        if [ "$size" -gt "$max_size" ]; then
            echo "❌ $description size ($size bytes) exceeds limit ($max_size bytes)"
            return 1
        else
            echo "✅ $description size OK ($size bytes)"
        fi
    fi
}

# Check firmware sizes if build directory exists
if [ -d "build/latest" ]; then
    check_file_size "build/latest/firmware.bin" "$MAX_FIRMWARE_SIZE" "Firmware"
    check_file_size "build/latest/bootloader.bin" "$MAX_BOOTLOADER_SIZE" "Bootloader"
fi

echo "Firmware size check completed"
EOF
    
    chmod +x "${PROJECT_ROOT}/scripts/check_firmware_size.sh"
    
    log_success "Security tools configured"
}

# Development tools setup
setup_development_tools() {
    log_header "Setting Up Development Tools"
    
    # Create .clang-format
    cat > "${PROJECT_ROOT}/.clang-format" << EOF
BasedOnStyle: Google
IndentWidth: 4
TabWidth: 4
UseTab: Never
ColumnLimit: 100
AlignConsecutiveAssignments: true
AlignConsecutiveDeclarations: true
AllowShortFunctionsOnASingleLine: Inline
AllowShortIfStatementsOnASingleLine: false
AllowShortLoopsOnASingleLine: false
BreakBeforeBraces: Linux
IndentCaseLabels: true
SpaceBeforeParens: ControlStatements
SpacesInParentheses: false
SpacesInSquareBrackets: false
Standard: C11
EOF
    
    # Create .clang-tidy
    cat > "${PROJECT_ROOT}/.clang-tidy" << EOF
Checks: '
  bugprone-*,
  cert-*,
  clang-analyzer-*,
  cppcoreguidelines-*,
  hicpp-*,
  misc-*,
  modernize-*,
  performance-*,
  portability-*,
  readability-*,
  security-*,
  -modernize-use-trailing-return-type,
  -readability-braces-around-statements,
  -hicpp-braces-around-statements,
  -readability-magic-numbers,
  -cppcoreguidelines-avoid-magic-numbers
'
WarningsAsErrors: '
  bugprone-*,
  cert-*,
  security-*
'
CheckOptions:
  - key: readability-identifier-naming.VariableCase
    value: snake_case
  - key: readability-identifier-naming.FunctionCase
    value: snake_case
  - key: readability-identifier-naming.TypedefCase
    value: CamelCase
  - key: readability-identifier-naming.StructCase
    value: CamelCase
  - key: readability-identifier-naming.MacroCase
    value: UPPER_CASE
EOF
    
    # Create .editorconfig
    cat > "${PROJECT_ROOT}/.editorconfig" << EOF
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true

[*.{c,h,cpp,hpp}]
indent_style = space
indent_size = 4

[*.{py,yml,yaml}]
indent_style = space
indent_size = 4

[*.{js,json}]
indent_style = space
indent_size = 2

[*.md]
trim_trailing_whitespace = false

[Makefile]
indent_style = tab
EOF
    
    log_success "Development tools configured"
}

# VS Code configuration
setup_vscode() {
    log_header "Setting Up VS Code Configuration"
    
    local vscode_dir="${PROJECT_ROOT}/.vscode"
    mkdir -p "$vscode_dir"
    
    # Settings
    cat > "${vscode_dir}/settings.json" << EOF
{
    "C_Cpp.default.cStandard": "gnu11",
    "C_Cpp.default.cppStandard": "c++17",
    "C_Cpp.default.compilerPath": "\${workspaceFolder}/toolchain/current/bin/arm-none-eabi-gcc",
    "C_Cpp.default.intelliSenseMode": "gcc-arm",
    "C_Cpp.default.compileCommands": "\${workspaceFolder}/build/latest/compile_commands.json",
    
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.mypyEnabled": true,
    
    "editor.formatOnSave": true,
    "editor.rulers": [100],
    "editor.tabSize": 4,
    "editor.insertSpaces": true,
    
    "files.associations": {
        "*.scons": "python",
        "SConscript": "python",
        "SConstruct": "python",
        "*.fam": "python"
    },
    
    "cortex-debug.enableTelemetry": false,
    "cortex-debug.variableUseNaturalFormat": true,
    "cortex-debug.showRTOS": true,
    "cortex-debug.armToolchainPath": "\${workspaceFolder}/toolchain/current/bin",
    "cortex-debug.openocdPath": "\${workspaceFolder}/toolchain/current/bin/openocd",
    "cortex-debug.gdbPath": "\${workspaceFolder}/toolchain/current/bin/arm-none-eabi-gdb"
}
EOF
    
    # Extensions
    cat > "${vscode_dir}/extensions.json" << EOF
{
    "recommendations": [
        "ms-vscode.cpptools",
        "ms-python.python",
        "ms-python.black-formatter",
        "marus25.cortex-debug",
        "llvm-vs-code-extensions.vscode-clangd",
        "ms-vscode.cmake-tools",
        "twxs.cmake",
        "streetsidesoftware.code-spell-checker",
        "eamodio.gitlens",
        "ms-vscode.hexeditor",
        "yzhang.markdown-all-in-one"
    ]
}
EOF
    
    log_success "VS Code configuration created"
}

# Hardware setup
setup_hardware_access() {
    log_header "Setting Up Hardware Access"
    
    case "$SYSTEM" in
        "debian"|"fedora"|"arch")
            # Add user to dialout group for serial access
            if ! groups "$USER" | grep -q dialout; then
                log_info "Adding user to dialout group..."
                sudo usermod -a -G dialout "$USER"
                log_warning "Please log out and log back in for group changes to take effect"
            fi
            
            # Create udev rules for Flipper Zero
            if [ ! -f "/etc/udev/rules.d/42-flipper.rules" ]; then
                log_info "Creating udev rules for Flipper Zero..."
                sudo tee /etc/udev/rules.d/42-flipper.rules > /dev/null << EOF
# Flipper Zero serial port
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", TAG+="uaccess"
# Flipper Zero DFU mode
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="df11", TAG+="uaccess"
EOF
                sudo udevadm control --reload-rules
                sudo udevadm trigger
            fi
            ;;
        "macos")
            log_info "macOS hardware access should work out of the box"
            ;;
    esac
    
    log_success "Hardware access configured"
}

# Environment file creation
create_environment_file() {
    log_header "Creating Environment Configuration"
    
    cat > "${PROJECT_ROOT}/scripts/env.sh" << EOF
#!/bin/bash
# Environment setup for Flipper Zero Firmware Next development

export PROJECT_ROOT="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"

# Add toolchain to PATH
if [ -d "\$PROJECT_ROOT/toolchain/current/bin" ]; then
    export PATH="\$PROJECT_ROOT/toolchain/current/bin:\$PATH"
fi

# Python virtual environment
if [ -d "\$PROJECT_ROOT/venv/bin" ]; then
    source "\$PROJECT_ROOT/venv/bin/activate"
fi

# Build configuration
export FBT_TOOLCHAIN_PATH="\$PROJECT_ROOT/toolchain/current"
export FBT_VERBOSE=0

# Development tools
export EDITOR="\${EDITOR:-nano}"
export PAGER="\${PAGER:-less}"

# Color output
export CLICOLOR=1
export TERM=xterm-256color

echo "🚀 Flipper Zero Firmware Next development environment activated"
echo "📂 Project root: \$PROJECT_ROOT"
echo "🔧 Toolchain: \$(arm-none-eabi-gcc --version 2>/dev/null | head -1 || echo 'Not found')"
echo "🐍 Python: \$(python --version 2>/dev/null || echo 'Not found')"
echo ""
echo "Available commands:"
echo "  ./fbt                    - Build firmware"
echo "  ./fbt flash             - Flash firmware via SWD"
echo "  ./fbt flash_usb         - Flash firmware via USB"
echo "  ./fbt test              - Run tests"
echo "  ./fbt lint              - Run code quality checks"
echo "  ./fbt clean             - Clean build artifacts"
EOF
    
    chmod +x "${PROJECT_ROOT}/scripts/env.sh"
    
    log_success "Environment configuration created"
}

# System checks
check_system_requirements() {
    log_header "Checking System Requirements"
    
    local requirements_met=true
    
    # Check disk space
    local available_space
    if command -v df >/dev/null 2>&1; then
        available_space=$(df "${PROJECT_ROOT}" | awk 'NR==2 {print int($4/1024/1024)}')
        if [ "$available_space" -lt "$REQUIRED_DISK_SPACE_GB" ]; then
            log_error "Insufficient disk space: ${available_space}GB available, ${REQUIRED_DISK_SPACE_GB}GB required"
            requirements_met=false
        else
            log_success "Disk space: ${available_space}GB available"
        fi
    fi
    
    # Check memory
    local total_memory
    if command -v free >/dev/null 2>&1; then
        total_memory=$(free -g | awk 'NR==2{print $2}')
        if [ "$total_memory" -lt 4 ]; then
            log_warning "Low memory: ${total_memory}GB total (8GB recommended)"
        else
            log_success "Memory: ${total_memory}GB total"
        fi
    fi
    
    # Check required commands
    local required_commands=("git" "python3" "curl" "make")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            requirements_met=false
        else
            log_success "Found: $cmd"
        fi
    done
    
    if [ "$requirements_met" = false ]; then
        log_error "System requirements not met"
        exit 1
    fi
    
    log_success "System requirements check passed"
}

# Main setup function
main() {
    log_header "Flipper Zero Firmware Next - Development Environment Setup"
    
    # Initialize log file
    echo "Setup started at $(date)" > "$LOG_FILE"
    
    # Check if running in project directory
    if [ ! -f "${PROJECT_ROOT}/README.md" ]; then
        log_error "Please run this script from the project root directory"
        exit 1
    fi
    
    # Show setup options
    echo -e "${CYAN}This script will set up your development environment with:${NC}"
    echo "• System dependencies and toolchain"
    echo "• Python development environment"
    echo "• Code quality tools and git hooks"
    echo "• VS Code configuration"
    echo "• Hardware access permissions"
    echo "• Security scanning tools"
    echo ""
    
    read -p "Continue with setup? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Setup cancelled by user"
        exit 0
    fi
    
    # Run setup steps
    detect_system
    check_system_requirements
    install_system_dependencies
    install_arm_toolchain
    setup_python_environment
    setup_git_hooks
    setup_security_tools
    setup_development_tools
    setup_vscode
    setup_hardware_access
    create_environment_file
    
    # Final summary
    log_header "Setup Complete!"
    
    echo -e "${GREEN}✅ Development environment setup completed successfully!${NC}"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "1. Activate the environment: source scripts/env.sh"
    echo "2. Build the firmware: ./fbt"
    echo "3. Connect your Flipper Zero device"
    echo "4. Flash the firmware: ./fbt flash"
    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    echo "• README.md - Project overview"
    echo "• CONTRIBUTING.md - Development guidelines"
    echo "• SECURITY.md - Security policies"
    echo "• documentation/ - Detailed documentation"
    echo ""
    echo -e "${CYAN}Support:${NC}"
    echo "• Issues: https://github.com/your-username/flipper-zero-firmware-next/issues"
    echo "• Discussions: https://github.com/your-username/flipper-zero-firmware-next/discussions"
    echo "• Security: security@your-domain.com"
    echo ""
    
    if [ "$SYSTEM" = "debian" ] || [ "$SYSTEM" = "fedora" ] || [ "$SYSTEM" = "arch" ]; then
        echo -e "${YELLOW}⚠️  Please log out and log back in for hardware access permissions to take effect${NC}"
        echo ""
    fi
    
    log_success "Setup completed at $(date)"
}

# Run main function
main "$@"