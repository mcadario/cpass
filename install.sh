#installation script

set -e  #exit if any error

# colors :)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # no color

# config
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="cpass"

# print pretty header
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  cpass INSTALLATION${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_requirements() {
    print_info "Checking requirements..."
    
    # check gcc
    if ! command -v gcc &> /dev/null; then
        print_error "gccnot installed"
        exit 1
    fi
    print_success "gcc found: $(gcc --version | head -n1)"
    
    # check make
    if ! command -v make &> /dev/null; then
        print_warning "make not installed"
        return 1
    fi
    print_success "make found: $(make --version | head -n1)"
    
    return 0
}

compile_program() {
    print_info "Compiling cpass..."
    
    if command -v make &> /dev/null; then
        # use makefile
        make clean
        make
    else
        print_info "ERROR: Makefile not found"
    fi
    
    if [ -f "./cpass" ]; then
        print_success "Compilation successful!"
    else
        print_error "ERROR: Compilation failed"
        exit 1
    fi
}

install_binary() {
    print_info "Installing cpass to $INSTALL_DIR..."

    if [ ! -w "$INSTALL_DIR" ]; then
        print_warning "Need sudo privileges to install to $INSTALL_DIR"
        sudo install -m 755 ./cpass "$INSTALL_DIR/$BINARY_NAME"
    else
        install -m 755 ./cpass "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    print_success "installed to $INSTALL_DIR/$BINARY_NAME"
}

verify_installation() {
    print_info "Verifying installation..."
    
    if command -v cpass &> /dev/null; then
        print_success "cpass is now available globally!"
        echo ""
        print_info "Test it with: cpass"
    else
        print_error "Installation verification failed!"
        print_warning "try to add $INSTALL_DIR to your PATH"
        exit 1
    fi
}

print_usage_info() {
    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    echo "Usage examples:"
    echo "> cpass                              # Show help"
    echo "> cpass add mysite user password     # Add a password"
    echo "> cpass list                         # List all passwords"
    echo "> cpass find mysite                  # Find passwords for a site"
    echo "> cpass delete mysite                # Delete a password"
    echo ""
    echo "Your passwords will be stored in: ~/.cpass/"
    echo ""
}

uninstall() {
    print_header
    print_warning "Uninstalling cpass..."
    
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        if [ ! -w "$INSTALL_DIR" ]; then
            sudo rm -f "$INSTALL_DIR/$BINARY_NAME"
        else
            rm -f "$INSTALL_DIR/$BINARY_NAME"
        fi
        print_success "Binary removed from $INSTALL_DIR"
    else
        print_info "Binary not found in $INSTALL_DIR"
    fi
    
    # Ask about user data
    echo ""
    read -p "Do you want to remove password data in ~/.cpass/? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf ~/.cpass
        print_success "User data removed"
    else
        print_info "User data preserved in ~/.cpass/"
    fi
    
    echo ""
    print_success "Uninstall complete!"
    exit 0
}

# main process
main() {
    print_header
    
    # check uninstall flah
    if [ "$1" == "--uninstall" ] || [ "$1" == "-u" ]; then
        uninstall
    fi
    
    # check help flag
    if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        echo "Usage: ./install.sh [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h       Show this help message"
        echo "  --uninstall, -u  Uninstall cpass"
        echo ""
        echo "!!! >> Without options, will compile and install cpass."
        exit 0
    fi
    
    check_requirements
    compile_program
    install_binary
    verify_installation
    print_usage_info
}

# run main
main "$@"