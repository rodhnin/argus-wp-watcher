#!/usr/bin/env bash
# ==============================================================================
# Argus — Vulnerable WordPress Lab Setup Script
# ==============================================================================
# Configures the Docker lab to a realistic, intentionally-vulnerable state
# that exercises every Argus check. Run after "docker compose -f compose.testing.yml up -d"
#
# Usage:
#   cd docker/
#   bash setup-lab.sh
#
# What this creates:
#   - Realistic WP site (TechCorp Demo) with posts, pages, contact form
#   - Two users (admin + editor) — both discoverable by user enumeration
#   - Outdated vulnerable plugins active (contact-form-7 5.3.1, elementor 3.5.0)
#   - Security misconfigurations: debug ON, XML-RPC enabled, no brute-force
#   - No CAPTCHA, no 2FA enforcement, open registration
#   - Exposed readme.html, license.txt, debug.log
#   - No security headers
#   - All intentional — for demonstrating Argus findings
# ==============================================================================

set -euo pipefail

WP="docker exec argus-test-wp wp --allow-root"
CONTAINER="argus-test-wp"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

# ------------------------------------------------------------------------------
# 0. Pre-flight
# ------------------------------------------------------------------------------
log "Checking container is running..."
if ! docker inspect argus-test-wp &>/dev/null; then
    err "Container argus-test-wp not found."
    err "Run first: docker compose -f compose.testing.yml up -d"
    exit 1
fi

# Wait for wp-config.php (Docker image writes it automatically from env vars)
log "Waiting for WordPress files to be ready..."
for i in $(seq 1 40); do
    if docker exec "$CONTAINER" test -f /var/www/html/wp-config.php 2>/dev/null; then
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

if ! docker exec "$CONTAINER" test -f /var/www/html/wp-config.php 2>/dev/null; then
    err "wp-config.php not found after 2 minutes. Container may not be healthy."
    exit 1
fi

# ------------------------------------------------------------------------------
# 0b. Install WP-CLI if not present
# ------------------------------------------------------------------------------
if ! docker exec "$CONTAINER" which wp &>/dev/null; then
    log "WP-CLI not found — installing into container..."
    docker exec "$CONTAINER" bash -c '
        curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
        chmod +x wp-cli.phar
        mv wp-cli.phar /usr/local/bin/wp
    '
    if docker exec "$CONTAINER" which wp &>/dev/null; then
        log "WP-CLI installed successfully"
    else
        err "WP-CLI installation failed"
        exit 1
    fi
else
    log "WP-CLI already available"
fi

# ------------------------------------------------------------------------------
# 1. WordPress core install (fresh install only)
# ------------------------------------------------------------------------------
if ! $WP core is-installed 2>/dev/null; then
    log "Fresh install detected — running WordPress core install..."
    $WP core install \
        --url="http://localhost:8080" \
        --title="TechCorp Solutions" \
        --admin_user="admin" \
        --admin_password="Admin123!" \
        --admin_email="admin@techcorp-solutions.local" \
        --skip-email
    log "WordPress core installed (admin / Admin123!)"

    # Install vulnerable plugin versions (specific old versions for CVE demo)
    log "Installing vulnerable plugin versions for CVE demonstration..."

    log "  Installing contact-form-7 v5.3.1 (has known CVEs)..."
    $WP plugin install contact-form-7 --version=5.3.1 --force 2>/dev/null \
        || warn "  contact-form-7 5.3.1 not available — installing latest"

    log "  Installing elementor v3.5.0 (has known CVEs)..."
    $WP plugin install elementor --version=3.5.0 --force 2>/dev/null \
        || warn "  elementor 3.5.0 not available — installing latest"

    log "  Installing akismet..."
    $WP plugin install akismet --activate 2>/dev/null || true

    log "  Installing wp-2fa..."
    $WP plugin install wp-2fa --activate 2>/dev/null || true
else
    log "WordPress already installed — skipping core install."
fi

# ------------------------------------------------------------------------------
# 1. Site identity — realistic company demo
# ------------------------------------------------------------------------------
log "Configuring site identity..."
$WP option update blogname "TechCorp Solutions"
$WP option update blogdescription "Enterprise Technology Solutions & IT Consulting"
$WP option update admin_email "admin@techcorp-solutions.local"

# ------------------------------------------------------------------------------
# 2. Permalinks
# ------------------------------------------------------------------------------
log "Setting permalink structure..."
$WP option update permalink_structure "/%postname%/"
$WP rewrite flush

# ------------------------------------------------------------------------------
# 3. Users — admin + editor (both enumerable by Argus)
# ------------------------------------------------------------------------------
log "Configuring users..."

# Update admin user info
$WP user update 1 \
    --display_name="John Admin" \
    --first_name="John" \
    --last_name="Smith"

# Create editor user if not exists
if ! $WP user get editor --field=ID 2>/dev/null; then
    $WP user create editor editor@techcorp-solutions.local \
        --role=editor \
        --display_name="Sarah Editor" \
        --first_name="Sarah" \
        --last_name="Johnson" \
        --user_pass="EditorPass2024!"
    log "Created editor user (Sarah Johnson)"
else
    log "Editor user already exists"
fi

# ------------------------------------------------------------------------------
# 4. Plugins — activate vulnerable versions, keep intentional misconfigs
# ------------------------------------------------------------------------------
log "Configuring plugins..."

# Activate intentionally vulnerable plugins (old versions = real CVEs for scanner)
$WP plugin activate contact-form-7 2>/dev/null && log "  contact-form-7 5.3.1 activated (has known CVEs)" || warn "  contact-form-7 not found"
$WP plugin activate elementor 2>/dev/null && log "  elementor 3.5.0 activated (has known CVEs)" || warn "  elementor not found"
$WP plugin activate akismet 2>/dev/null && log "  akismet activated" || warn "  akismet not found"

# wp-2fa: installed but NOT enforced for all users (scanner should detect plugin present)
$WP plugin activate wp-2fa 2>/dev/null && log "  wp-2fa activated (plugin detected by scanner, not enforced)" || warn "  wp-2fa not found"

# Disable cloudflare turnstile (no API keys configured → scanner should report NO CAPTCHA)
$WP plugin deactivate simple-cloudflare-turnstile 2>/dev/null && log "  cloudflare-turnstile deactivated (no CAPTCHA = scanner finding)" || true

# Remove test mu-plugin artifacts from previous testing sessions
docker exec "$CONTAINER" rm -f \
    /var/www/html/wp-content/mu-plugins/test-captcha-login.php \
    /var/www/html/wp-content/mu-plugins/test-comment.php \
    2>/dev/null && log "  Cleaned test mu-plugin artifacts" || true

# ------------------------------------------------------------------------------
# 5. Security misconfigurations (intentional — what Argus should detect)
# ------------------------------------------------------------------------------
log "Applying intentional security misconfigurations..."

# XML-RPC: ENABLED (scanner detects, ARGUS-WP-060)
$WP eval 'remove_filter("xmlrpc_enabled", "__return_false");' 2>/dev/null || true

# Open registration: ENABLED (scanner detects, ARGUS-WP-074)
$WP option update users_can_register 1
log "  Open registration: ENABLED (scanner will detect)"

# Default user role: subscriber (minimal damage but registration open = finding)
$WP option update default_role subscriber

# No CAPTCHA plugin (scanner will report ARGUS-WP-072 low)
# No brute-force plugin (scanner will report ARGUS-WP-073 high)
# No password policy plugin (scanner will report ARGUS-WP-075 low)

# ------------------------------------------------------------------------------
# 6. Content — realistic pages and posts
# ------------------------------------------------------------------------------
log "Creating site content..."

# Delete default Hello World and Sample Page
$WP post delete 1 --force 2>/dev/null || true
$WP post delete 2 --force 2>/dev/null || true

# Home page
HOME_ID=$($WP post create \
    --post_type=page \
    --post_title="Welcome to TechCorp Solutions" \
    --post_status=publish \
    --post_content="<h1>Enterprise Technology Solutions</h1>
<p>TechCorp Solutions is a leading provider of enterprise IT consulting, cloud infrastructure, and cybersecurity services. We help businesses modernize their technology stack and secure their digital assets.</p>
<h2>Our Services</h2>
<ul>
<li>Cloud Migration &amp; Architecture</li>
<li>Cybersecurity Assessments</li>
<li>WordPress Development &amp; Maintenance</li>
<li>IT Infrastructure Consulting</li>
</ul>
<p><a href='/contact/'>Contact us today</a> for a free consultation.</p>" \
    --porcelain)
$WP option update page_on_front "$HOME_ID"
$WP option update show_on_front page
log "  Home page created (ID: $HOME_ID)"

# About page
ABOUT_ID=$($WP post create \
    --post_type=page \
    --post_title="About Us" \
    --post_status=publish \
    --post_content="<h1>About TechCorp Solutions</h1>
<p>Founded in 2015, TechCorp Solutions has served over 500 enterprise clients across North America and Europe. Our team of certified engineers and security experts brings decades of combined experience.</p>
<h2>Leadership Team</h2>
<p><strong>John Smith</strong> — Chief Executive Officer<br/>
<strong>Sarah Johnson</strong> — Head of Content &amp; Communications<br/>
<strong>Mike Chen</strong> — Chief Technology Officer</p>
<h2>Certifications</h2>
<p>ISO 27001 | SOC 2 Type II | AWS Partner | Microsoft Gold Partner</p>" \
    --porcelain)
log "  About page created (ID: $ABOUT_ID)"

# Contact page (with CF7 form if available)
CF7_SHORTCODE=""
if $WP plugin is-active contact-form-7 2>/dev/null; then
    # Create a CF7 form
    CF7_ID=$($WP eval '
$form = WPCF7_ContactForm::get_template(array(
    "title" => "Contact Form",
    "locale" => "en_US"
));
echo $form->id();
' 2>/dev/null || echo "")
    if [ -n "$CF7_ID" ] && [ "$CF7_ID" -gt 0 ] 2>/dev/null; then
        CF7_SHORTCODE="[contact-form-7 id=\"$CF7_ID\" title=\"Contact Form\"]"
        log "  CF7 form created (ID: $CF7_ID)"
    fi
fi

CONTACT_ID=$($WP post create \
    --post_type=page \
    --post_title="Contact" \
    --post_status=publish \
    --post_content="<h1>Contact Us</h1>
<p>Have a question or want to discuss your project? Fill out the form below and we'll get back to you within 24 hours.</p>
${CF7_SHORTCODE}
<h2>Office Locations</h2>
<p><strong>Headquarters:</strong> 123 Tech Park Drive, San Francisco, CA 94105<br/>
<strong>East Coast:</strong> 456 Innovation Blvd, New York, NY 10001<br/>
<strong>Email:</strong> info@techcorp-solutions.local<br/>
<strong>Phone:</strong> +1 (555) 123-4567</p>" \
    --porcelain)
log "  Contact page created (ID: $CONTACT_ID)"

# Services page
$WP post create \
    --post_type=page \
    --post_title="Services" \
    --post_status=publish \
    --post_content="<h1>Our Services</h1>
<h2>Cloud Infrastructure</h2>
<p>We design, migrate, and manage cloud infrastructure on AWS, Azure, and Google Cloud Platform. Our certified architects ensure high availability, scalability, and cost optimization.</p>
<h2>Cybersecurity</h2>
<p>Comprehensive security assessments, penetration testing, vulnerability management, and compliance consulting (SOC 2, ISO 27001, GDPR, HIPAA).</p>
<h2>WordPress Development</h2>
<p>Custom WordPress development, plugin development, theme customization, and ongoing maintenance. We build secure, performant WordPress solutions for enterprise clients.</p>
<h2>IT Consulting</h2>
<p>Strategic IT consulting to align technology with business objectives. We help CIOs and CTOs build roadmaps for digital transformation.</p>" \
    --porcelain > /dev/null
log "  Services page created"

# Blog posts (2-3 realistic posts so sitemap/RSS has content)
$WP post create \
    --post_type=post \
    --post_title="5 Critical WordPress Security Mistakes to Avoid in 2024" \
    --post_status=publish \
    --post_author=2 \
    --post_content="<p>WordPress powers over 43% of all websites on the internet, making it a prime target for attackers. Here are the five most critical security mistakes we see in our client audits.</p>
<h2>1. Running Outdated Plugins</h2>
<p>Outdated plugins are the #1 attack vector for WordPress sites. Always keep plugins updated and remove unused ones.</p>
<h2>2. Weak Administrator Passwords</h2>
<p>Use strong, unique passwords and enable two-factor authentication for all administrator accounts.</p>
<h2>3. Exposed wp-config.php Backups</h2>
<p>Backup files left in the webroot can expose your database credentials to anyone who knows where to look.</p>
<h2>4. No Security Headers</h2>
<p>Implement Content-Security-Policy, X-Frame-Options, and HSTS headers to protect against common web attacks.</p>
<h2>5. Default Login URL</h2>
<p>The default /wp-login.php URL is well-known. Consider changing it to reduce automated attack attempts.</p>
<p><em>Published by Sarah Johnson, Head of Content</em></p>" \
    --porcelain > /dev/null

$WP post create \
    --post_type=post \
    --post_title="Cloud Migration: A Step-by-Step Guide for Enterprise Teams" \
    --post_status=publish \
    --post_author=1 \
    --post_content="<p>Migrating enterprise infrastructure to the cloud requires careful planning, stakeholder alignment, and a phased approach. Here is our proven methodology refined across 200+ migrations.</p>
<h2>Phase 1: Assessment</h2>
<p>Inventory your current infrastructure, identify dependencies, and establish baseline performance metrics. This phase typically takes 2-4 weeks.</p>
<h2>Phase 2: Planning</h2>
<p>Define migration waves, select target cloud architecture, and establish rollback procedures. Never skip the rollback plan.</p>
<h2>Phase 3: Pilot Migration</h2>
<p>Migrate a non-critical workload first. Validate performance, security controls, and cost projections against estimates.</p>
<h2>Phase 4: Full Migration</h2>
<p>Execute migration in waves, starting with lowest-risk workloads. Maintain parallel running environments during transition.</p>
<p><em>Published by John Smith, CEO</em></p>" \
    --porcelain > /dev/null

log "  Blog posts created (2 posts)"

# Navigation menu
$WP menu create "Main Navigation" 2>/dev/null || true
MENU_ID=$($WP menu list --field=term_id --format=ids 2>/dev/null | head -1 || echo "")
if [ -n "$MENU_ID" ]; then
    $WP menu item add-post "$MENU_ID" "$HOME_ID" 2>/dev/null || true
    $WP menu item add-post "$MENU_ID" "$ABOUT_ID" 2>/dev/null || true
    $WP menu item add-post "$MENU_ID" "$CONTACT_ID" 2>/dev/null || true
    $WP menu location assign "$MENU_ID" primary 2>/dev/null || true
    log "  Navigation menu configured"
fi

# ------------------------------------------------------------------------------
# 7. Create debug.log (scanner should detect this — ARGUS-WP-030 high)
# ------------------------------------------------------------------------------
log "Creating debug.log (intentional — scanner should detect)..."
docker exec "$CONTAINER" bash -c '
mkdir -p /var/www/html/wp-content
cat > /var/www/html/wp-content/debug.log << EOF
[13-Mar-2026 08:00:01 UTC] PHP Warning: include(/var/www/html/wp-content/plugins/old-plugin/missing-file.php): failed to open stream: No such file or directory in /var/www/html/wp-includes/class-wp-hook.php on line 308
[13-Mar-2026 08:00:01 UTC] PHP Notice: Trying to get property of non-object in /var/www/html/wp-content/themes/twentytwentytwo/inc/helper.php on line 45
[13-Mar-2026 09:15:22 UTC] PHP Warning: mysqli_connect(): (HY000/1045): Access denied for user wp_test_user@localhost to database wordpress_test in /var/www/html/wp-includes/class-wpdb.php on line 1612
[13-Mar-2026 09:15:22 UTC] WordPress database error: [Access denied for user wp_test_user]
[13-Mar-2026 10:30:45 UTC] PHP Deprecated: Function get_magic_quotes_gpc() is deprecated in /var/www/html/wp-includes/load.php on line 651
EOF
chown www-data:www-data /var/www/html/wp-content/debug.log
'
log "  debug.log created with realistic PHP errors"

# ------------------------------------------------------------------------------
# 8. Create a realistic robots.txt with some sensitive disclosures
# ------------------------------------------------------------------------------
log "Creating robots.txt..."
docker exec "$CONTAINER" bash -c 'cat > /var/www/html/robots.txt << EOF
User-agent: *
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /wp-content/uploads/
Disallow: /backup/
Disallow: /staging/
Allow: /wp-admin/admin-ajax.php

Sitemap: http://localhost:8080/sitemap.xml
EOF'
log "  robots.txt created (scanner will detect /backup/ and /staging/ disclosures)"

# ------------------------------------------------------------------------------
# 9. Flush and finalize
# ------------------------------------------------------------------------------
log "Flushing rewrite rules and cache..."
$WP rewrite flush 2>/dev/null || true
$WP cache flush 2>/dev/null || true

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Lab Setup Complete!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  URL:       http://localhost:8080"
echo "  Admin:     http://localhost:8080/wp-admin"
echo "  User:      admin / Admin123!"
echo "  User:      editor / EditorPass2024!"
echo ""
echo "  Intentional findings for Argus to detect:"
echo "  - ARGUS-WP-001: WP core 6.0 (outdated, CVEs)"
echo "  - ARGUS-WP-012: contact-form-7 5.3.1 (critical CVEs)"
echo "  - ARGUS-WP-012: elementor 3.5.0 (critical CVEs)"
echo "  - ARGUS-WP-030: readme.html, license.txt, debug.log exposed"
echo "  - ARGUS-WP-040: admin, editor users enumerable"
echo "  - ARGUS-WP-050: missing security headers (CSP, HSTS, etc.)"
echo "  - ARGUS-WP-060: XML-RPC enabled, directory listing"
echo "  - ARGUS-WP-070: wp-login.php accessible"
echo "  - ARGUS-WP-072: no CAPTCHA on login page"
echo "  - ARGUS-WP-073: no brute force protection"
echo "  - ARGUS-WP-074: open user registration enabled"
echo "  - ARGUS-WP-075: no password policy"
echo "  - ARGUS-WP-080: robots.txt discloses /backup/, /staging/"
echo ""
echo "  Run Argus:"
echo "  python -m argus --target http://localhost:8080"
echo "  python -m argus --target http://localhost:8080 --aggressive"
echo ""