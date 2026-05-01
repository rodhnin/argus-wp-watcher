#!/bin/bash
# Argus - Interactive Deployment Script
# Helps users choose between production and testing environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo ""
echo "========================================"
echo "  Argus - WordPress Security Scanner"
echo "  Docker Deployment Helper"
echo "========================================"
echo ""

# Function to print colored messages
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not available. Please install Docker Compose."
    exit 1
fi

print_success "Docker and Docker Compose are available"
echo ""

# Ask user what they want to deploy
echo "What would you like to deploy?"
echo ""
echo "  1) Production - Argus Scanner only (for scanning external sites)"
echo "  2) Testing Lab - Vulnerable WordPress environment (for security testing)"
echo "  3) Both - Production scanner + Testing lab"
echo "  4) Stop all services"
echo "  5) Remove all containers and data (reset)"
echo ""
read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        print_info "Deploying Argus Scanner (Production)..."
        echo ""
        
        cd "$(dirname "$0")"
        mkdir -p ./reports ./data
        
        docker compose up -d
        
        echo ""
        print_success "Argus Scanner deployed successfully!"
        echo ""
        print_info "Usage:"
        echo "  docker compose exec argus python -m argus --target <URL>"
        echo ""
        print_info "Example:"
        echo "  docker compose exec argus python -m argus --target https://example.com"
        echo ""
        print_info "Reports will be saved to: ./reports/"
        echo "Database location: ./data/argos.db"
        ;;
        
    2)
        print_warning "WARNING: The testing lab is INTENTIONALLY VULNERABLE!"
        print_warning "DO NOT expose it to the public internet!"
        echo ""
        read -p "Do you understand and want to continue? (yes/no): " confirm
        
        if [ "$confirm" != "yes" ]; then
            print_info "Deployment cancelled."
            exit 0
        fi
        
        print_info "Deploying Testing Lab (Vulnerable WordPress)..."
        echo ""

        cd "$(dirname "$0")"
        mkdir -p ./reports ./data

        # Pull images with retry (network timeouts are common with Docker Hub CDN)
        print_info "Pulling Docker images (retrying up to 5 times on timeout)..."
        for img in "wordpress:6.0" "mariadb:10.11"; do
            if docker image inspect "$img" &>/dev/null; then
                print_info "  $img already cached — skipping pull"
                continue
            fi
            pulled=false
            for attempt in 1 2 3 4 5; do
                print_info "  Pulling $img (attempt $attempt/5)..."
                if docker pull "$img"; then
                    pulled=true
                    break
                fi
                print_warning "  Pull failed — waiting 5s before retry..."
                sleep 5
            done
            if [ "$pulled" = false ]; then
                print_error "Failed to pull $img after 5 attempts. Check your internet connection."
                exit 1
            fi
        done

        docker compose -f compose.testing.yml up -d

        echo ""
        print_info "Containers started. Running lab setup (installs WP + vulnerable plugins)..."
        echo ""
        bash "$(dirname "$0")/setup-lab.sh"
        ;;
        
    3)
        print_warning "WARNING: The testing lab is INTENTIONALLY VULNERABLE!"
        print_warning "DO NOT expose it to the public internet!"
        echo ""
        read -p "Do you understand and want to continue? (yes/no): " confirm
        
        if [ "$confirm" != "yes" ]; then
            print_info "Deployment cancelled."
            exit 0
        fi
        
        print_info "Deploying both Production and Testing Lab..."
        echo ""

        cd "$(dirname "$0")"
        mkdir -p ./reports ./data

        # Pull images with retry
        print_info "Pulling Docker images (retrying up to 5 times on timeout)..."
        for img in "wordpress:6.0" "mariadb:10.11"; do
            if docker image inspect "$img" &>/dev/null; then
                print_info "  $img already cached — skipping pull"
                continue
            fi
            pulled=false
            for attempt in 1 2 3 4 5; do
                print_info "  Pulling $img (attempt $attempt/5)..."
                if docker pull "$img"; then
                    pulled=true
                    break
                fi
                print_warning "  Pull failed — waiting 5s before retry..."
                sleep 5
            done
            if [ "$pulled" = false ]; then
                print_error "Failed to pull $img after 5 attempts. Check your internet connection."
                exit 1
            fi
        done

        # Start testing lab first (creates network)
        print_info "Starting Testing Lab..."
        docker compose -f compose.testing.yml up -d

        print_info "Running lab setup..."
        bash "$(dirname "$0")/setup-lab.sh"

        # Start production scanner
        print_info "Starting Argus Scanner..."
        docker compose up -d

        # Connect Argus to testing network
        print_info "Connecting Argus to testing network..."
        docker network connect argus-test-network argus-scanner 2>/dev/null || true

        echo ""
        print_success "Both environments deployed successfully!"
        echo ""
        print_info "Production Scanner:"
        echo "  docker compose exec argus python -m argus --target <URL>"
        echo ""
        print_info "Testing Lab: http://localhost:8080"
        print_info "Scan from container:"
        echo "  docker compose exec argus python -m argus --target http://wordpress"
        ;;
        
    4)
        print_info "Stopping all services..."
        echo ""
        
        cd "$(dirname "$0")"
        
        # Stop production if running
        if docker compose ps -q 2>/dev/null | grep -q .; then
            print_info "Stopping production environment..."
            docker compose down
        fi
        
        # Stop testing if running
        if docker compose -f compose.testing.yml ps -q 2>/dev/null | grep -q .; then
            print_info "Stopping testing environment..."
            docker compose -f compose.testing.yml down
        fi
        
        echo ""
        print_success "All services stopped"
        ;;
        
    5)
        print_warning "WARNING: This will remove ALL containers and data!"
        print_warning "Reports and database will be PERMANENTLY DELETED!"
        echo ""
        read -p "Are you sure? Type 'DELETE' to confirm: " confirm
        
        if [ "$confirm" != "DELETE" ]; then
            print_info "Reset cancelled."
            exit 0
        fi
        
        print_info "Removing all containers and data..."
        echo ""
        
        cd "$(dirname "$0")"
        
        # Remove production
        if docker compose ps -q 2>/dev/null | grep -q . || docker compose ps -a -q 2>/dev/null | grep -q .; then
            print_info "Removing production environment..."
            docker compose down -v
        fi
        
        # Remove testing
        if docker compose -f compose.testing.yml ps -q 2>/dev/null | grep -q . || \
           docker compose -f compose.testing.yml ps -a -q 2>/dev/null | grep -q .; then
            print_info "Removing testing environment..."
            docker compose -f compose.testing.yml down -v
        fi
        
        # Remove data directories
        if [ -d "./data" ]; then
            print_info "Removing ./data directory..."
            rm -rf ./data
        fi
        
        if [ -d "./reports" ]; then
            print_info "Removing ./reports directory..."
            rm -rf ./reports
        fi
        
        echo ""
        print_success "All containers and data removed"
        ;;
        
    *)
        print_error "Invalid choice. Please run the script again."
        exit 1
        ;;
esac

echo ""
echo "========================================"
echo ""