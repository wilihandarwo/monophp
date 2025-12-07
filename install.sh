#!/bin/bash

# MonoPHP Installer
# Usage: curl -s https://raw.githubusercontent.com/wilihandarwo/monophp/main/install.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="$HOME/.monophp"
BIN_DIR="$INSTALL_DIR/bin"

echo -e "${BLUE}"
echo "  __  __                   _____  _    _ _____  "
echo " |  \/  |                 |  __ \| |  | |  __ \ "
echo " | \  / | ___  _ __   ___ | |__) | |__| | |__) |"
echo " | |\/| |/ _ \| '_ \ / _ \|  ___/|  __  |  ___/ "
echo " | |  | | (_) | | | | (_) | |    | |  | | |     "
echo " |_|  |_|\___/|_| |_|\___/|_|    |_|  |_|_|     "
echo -e "${NC}"
echo "  Installing MonoPHP CLI..."
echo ""

# Check for required commands
if ! command -v git &> /dev/null; then
    echo -e "${RED}Error: git is required but not installed${NC}"
    exit 1
fi

# Create installation directory
echo -e "${YELLOW}➜${NC} Creating installation directory..."
mkdir -p "$BIN_DIR"

# Download the CLI script
echo -e "${YELLOW}➜${NC} Downloading MonoPHP CLI..."
curl -sL "https://raw.githubusercontent.com/wilihandarwo/monophp/main/bin/monophp" -o "$BIN_DIR/monophp"
chmod +x "$BIN_DIR/monophp"

# Detect shell and config file
SHELL_NAME=$(basename "$SHELL")
case "$SHELL_NAME" in
    zsh)
        SHELL_CONFIG="$HOME/.zshrc"
        ;;
    bash)
        if [[ -f "$HOME/.bash_profile" ]]; then
            SHELL_CONFIG="$HOME/.bash_profile"
        else
            SHELL_CONFIG="$HOME/.bashrc"
        fi
        ;;
    *)
        SHELL_CONFIG="$HOME/.profile"
        ;;
esac

# Add to PATH if not already there
PATH_EXPORT="export PATH=\"\$HOME/.monophp/bin:\$PATH\""
if ! grep -q ".monophp/bin" "$SHELL_CONFIG" 2>/dev/null; then
    echo -e "${YELLOW}➜${NC} Adding MonoPHP to PATH in $SHELL_CONFIG..."
    echo "" >> "$SHELL_CONFIG"
    echo "# MonoPHP CLI" >> "$SHELL_CONFIG"
    echo "$PATH_EXPORT" >> "$SHELL_CONFIG"
fi

echo ""
echo -e "${GREEN}✓ MonoPHP CLI installed successfully!${NC}"
echo ""
echo -e "To start using monophp, run:"
echo -e "  ${BLUE}source $SHELL_CONFIG${NC}"
echo ""
echo -e "Or open a new terminal, then:"
echo -e "  ${BLUE}monophp new myproject${NC}"
echo ""
