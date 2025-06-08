# WordPress CMS Security Checklist (Nuclei-Focused)

This checklist covers areas where Nuclei templates can be highly effective in identifying WordPress-specific security concerns.

---

## I - Core WordPress Vulnerabilities & Misconfigurations

- [ ] **WordPress Core Version Detection**: Accurate detection of WordPress core version to identify known CVEs.
- [ ] **Outdated WordPress Core Installation**: Identifying installations running unsupported or significantly old core versions.
- [ ] **Default `wp-config.php` Backup/Swaps**: Detecting exposed `wp-config.php.bak`, `wp-config.old`, or similar backup files.
- [ ] **Enabled Debugging (`WP_DEBUG`)**: Checking for `WP_DEBUG` being enabled in production, leading to verbose error messages.
- [ ] **Enabled File Editing**: Detecting if `DISALLOW_FILE_EDIT` is not set, allowing direct plugin/theme editing via admin panel.
- [ ] **XML-RPC Enabled (and potential for brute-force/DoS)**: Checking for `/xmlrpc.php` exposure and its susceptibility to brute-force or pingback DoS.
- [ ] **WP-Cron Misconfigurations**: Detecting issues where `wp-cron.php` is accessed externally, leading to potential DoS or information leakage.
- [ ] **`wp-content/uploads/` Directory Listing**: Checking for directory listing enabled on the uploads folder.
- [ ] **`wp-admin/` Directory Listing**: Checking for directory listing enabled on the admin folder.
- [ ] **Unrestricted File Uploads in Core (if applicable to version)**: Detecting scenarios where core functions allow dangerous file uploads.
- [ ] **Login Page Brute-Force Protection Bypass** (e.g., via `xmlrpc.php`, specific parameters): Testing techniques to bypass rate limits on `wp-login.php`.
- [ ] **Username Enumeration via `author=` Archives**: Checking if `/?author=1` or `/?author=N` reveals usernames.
- [ ] **Username Enumeration via REST API** (`/wp-json/wp/v2/users/`): Detecting if the REST API exposes usernames without authentication.
- [ ] **Unrestricted Password Reset** (no rate limit/weak token): Testing for weak password reset mechanisms.
- [ ] **Exposed `readme.html` or `license.txt`**: Identifying these files which reveal the exact WordPress version.

---

## II - Plugin & Theme Vulnerabilities

- [ ] **Vulnerable Plugin Version Detection**: Accurately detecting specific plugin versions (e.g., via `style.css`, `readme.txt` in plugin directories, unique file paths).
- [ ] **Known CVEs in Popular Plugins**:
    - [ ] Elementor Vulnerabilities: (e.g., RCE, LFI, XSS in specific versions).
    - [ ] Rank Math SEO Vulnerabilities: (e.g., authenticated SQLi, XSS).
    - [ ] Yoast SEO Vulnerabilities: (e.g., authenticated XSS, path traversal).
    - [ ] WooCommerce Vulnerabilities: (e.g., arbitrary file upload, IDOR, SQLi in older versions).
    - [ ] Contact Form 7 Vulnerabilities: (e.g., unrestricted file upload, XSS).
    - [ ] WP Super Cache Vulnerabilities: (e.g., RCE, information disclosure).
    - [ ] All-in-One SEO Pack Vulnerabilities: (e.g., XSS, information disclosure).
    - [ ] Advanced Custom Fields (ACF) Vulnerabilities: (e.g., XSS, RCE via deserialization).
    - [ ] WP File Manager Vulnerabilities: (e.g., unauthenticated RCE via arbitrary file upload).
    - [ ] Duplicator Plugin Vulnerabilities: (e.g., unauthenticated arbitrary file download).
    - [ ] Essential Addons for Elementor Vulnerabilities: (e.g., LFI, XSS).
    - [ ] UpdraftPlus Vulnerabilities: (e.g., authenticated arbitrary file download).
    - [ ] Ultimate Member Vulnerabilities: (e.g., authentication bypass, privilege escalation).
    - [ ] WP Fastest Cache Vulnerabilities: (e.g., arbitrary file deletion).
- [ ] **Custom plugin-specific RCE/SQLi/XSS** (beyond known CVEs): Fuzzing common plugin parameters and endpoints for injection flaws.
- [ ] **Vulnerable Theme Version Detection**: Accurately detecting specific theme versions (e.g., via `style.css`).
- [ ] **Known CVEs in Popular Themes**:
    - [ ] Divi Theme Vulnerabilities: (e.g., XSS, arbitrary file upload).
    - [ ] Avada Theme Vulnerabilities: (e.g., authenticated LFI).
    - [ ] Themify Theme Vulnerabilities: (e.g., arbitrary file upload).
    - [ ] Uncode Theme Vulnerabilities: (e.g., arbitrary file upload).
- [ ] **Custom theme-specific RCE/SQLi/XSS**: Fuzzing custom theme parameters and endpoints.
- [ ] **Default Plugin/Theme Files Exposure**: Detecting default configuration files or installation artifacts left behind (e.g., `backup.sql` from a backup plugin, `debug.log` from a specific plugin).
- [ ] **Information Disclosure via Plugin/Theme API Endpoints**: Checking if plugins/themes expose sensitive information via their custom REST API endpoints.
- [ ] **Unauthenticated Plugin/Theme Settings Access**: Probing for misconfigured plugin/theme settings pages accessible without authentication.
- [ ] **File Upload Vulnerabilities in Plugins** (e.g., image resizing, contact forms): Testing for arbitrary file upload through plugin functionalities.
- [ ] **SSRF in Plugin Functionality** (e.g., image import, URL scraping plugins): Exploiting plugins that fetch external URLs for SSRF.
- [ ] **Local File Inclusion (LFI) in Plugin/Theme Parameters**: Testing for LFI via common parameters used by plugins/themes.
- [ ] **Deserialization Vulnerabilities in Plugins/Themes** (e.g., PHP `unserialize()`): Detecting insecure deserialization in plugin/theme code.

---

## III - User & Authentication Management

- [ ] **Weak Usernames** (e.g., `admin`, `test`): Checking for default or common weak usernames.
- [ ] **WordPress Admin Panel Brute-Force** (with IP blocking bypass): Attempting to brute-force `wp-login.php` while testing various bypasses for rate limits.
- [ ] **Password Reset Page Enumeration** (identifying existing users): Using the password reset feature to confirm valid usernames.
- [ ] **Author ID Enumeration** (e.g., `/?author=1`, `/?author=2`): Extracting valid usernames from author archive pages.
- [ ] **WordPress REST API User Enumeration** (`/wp-json/wp/v2/users/`): Detecting if the REST API exposes user data.
- [ ] **XML-RPC Username Enumeration**: Using XML-RPC methods to enumerate usernames.
- [ ] **Weak User Roles/Capabilities Misconfigurations**: Identifying scenarios where users have more permissions than intended.
- [ ] **Comment Spam/DoS Vulnerabilities**: Testing comment forms for susceptibility to spam or DoS attacks.
- [ ] **Media Library File Name Enumeration**: Discovering media files uploaded to `wp-content/uploads/`.

---

## IV - Information Disclosure & Exposed Files

- [ ] **`wp-config.php` (Direct Access/Backup Files)**: Checking for exposed main configuration files or their backups.
- [ ] **`debug.log` File Exposure**: Detecting exposed WordPress debug logs which can contain sensitive information.
- [ ] **Database Backup Files** (`.sql`, `.zip`, `.tgz`): Scanning for inadvertently exposed database backups.
- [ ] **Installed Plugins/Themes Enumeration** (via `wp-content/plugins/` and `wp-content/themes/`): Listing installed plugins and themes for version correlation.
- [ ] **`phpinfo()` File Exposure**: Detecting exposed `phpinfo.php` or similar files.
- [ ] **Shell Backdoors** (`.php` files in `uploads/plugins/themes`): Scanning for known web shell signatures or suspicious files in writable directories.
- [ ] **`.git` or `.svn` Directories in WordPress Root/Subdirectories**: Detecting exposed version control repositories.
- [ ] **`error_log` File Exposure**: Checking for exposed PHP error logs.
- [ ] **Sensitive Data in WordPress Export Files** (`.wxr`): If export functionality is exposed, checking for sensitive data.
- [ ] **WAF/CDN Bypass for WordPress Login/Admin**: Testing common WAF bypasses to reach the login or admin panel directly.

---

## V - WordPress Specific Injection & Attacks

- [ ] **SQL Injection via WordPress Query Parameters**: Targeting custom query parameters for SQLi.
- [ ] **XSS in Comment Fields** (bypass WordPress sanitization): Crafting XSS payloads that bypass WordPress's default comment sanitization.
- [ ] **XSS in Post/Page Content** (if user input is unfiltered): Detecting XSS in post/page content areas if rich text editors are misconfigured.
- [ ] **SSRF via WordPress Heartbeat API** (if exploitable): Leveraging the Heartbeat API for SSRF if a vulnerable plugin processes external URLs.
- [ ] **CSRF on WordPress Admin Actions**: Testing for CSRF vulnerabilities on various admin actions (e.g., plugin activation, user creation).
- [ ] **Authenticated LFI/RCE** (via plugin/theme vulnerabilities requiring login): Probing for vulnerabilities that become exploitable after authentication.
- [ ] **Object Injection in WordPress** (PHP Deserialization): Targeting vulnerable WordPress functions or plugin/theme code that uses `unserialize()`.
- [ ] **WordPress REST API Injection** (SQLi, XSS, Command Injection): Fuzzing various REST API endpoints for injection flaws.
- [ ] **WordPress Nonce Bypass/Prediction**: Attempting to bypass or predict WordPress nonces for CSRF or other attacks.
