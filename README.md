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

## More Scans 


# 🚀 Expanding Our Arsenal: 300 More Advanced Web App Scanner Scenarios for Nuclei

This expansion to our Nuclei template collection focuses on even more granular, cutting-edge, and often niche vulnerabilities that clients are eager to see detected. These scenarios are designed to showcase sophisticated scanning capabilities, emphasizing detection of flaws that evade common tools and require intricate understanding of modern web application stacks.

---

### ✨ Why These Scenarios Matter to Clients

Clients appreciate scanners that:

- Find Real-World Impact: Detect vulnerabilities that directly lead to data breaches, unauthorized access, or significant financial loss.
- Go Beyond Basic Checks: Identify complex, multi-stage, or application-specific flaws.
- Cover Modern Tech: Understand and scan modern frameworks, APIs, and cloud-native environments.
- Provide Actionable Intelligence: Deliver clear indications of compromise or misconfiguration.
- Demonstrate Proactive Security: Show an ability to anticipate and detect emerging threats.

Our new set of Nuclei templates will continue to prioritize "builderable" design principles: modularity, parameterization, and workflow chaining, enabling you to adapt and extend them for diverse client environments.

---

## I - Advanced API Security & Microservices Exploitation

### A - Deeper API Logic & Authentication Bypass

- [ ] API Versioning Bypass: Exploiting misconfigurations in API versioning (e.g., v1 vs. v2) to access deprecated or less secure endpoints.
- [ ] API Gateway Shadow Endpoints: Discovering and accessing unlisted or internal API endpoints exposed via misconfigured API gateways.
- [ ] Bypassing API Rate Limits via Header Manipulation (e.g., X-Forwarded-For, custom headers): Crafting requests to bypass rate limits by manipulating various HTTP headers.
- [ ] Weak API Key Rotation/Revocation: Detecting indicators of static or poorly managed API keys that are never rotated.
- [ ] API Key Abuse for Account Takeover (shared key for multiple users): Identifying scenarios where a single API key can control multiple user accounts.
- [ ] OAuth/OpenID Connect Token Interception/Replay (client-side): Detecting misconfigurations that allow interception or replay of OAuth tokens.
- [ ] API JWT Header Injection (e.g., kid manipulation for arbitrary file read/RCE): Exploiting vulnerabilities in kid (key ID) parameter of JWT headers.
- [ ] API Parameter Type Juggling: Exploiting weak type checking in API parameters (e.g., sending string instead of integer) to bypass validation.
- [ ] API with Insecure Paging/Pagination: Exploiting insecure pagination to access more data than authorized (e.g., limit=0, negative offsets).
- [ ] GraphQL API - Batching for Brute-Force/Enumeration: Using GraphQL batching to efficiently enumerate users or brute-force credentials.
- [ ] GraphQL API - Information Disclosure via Relay/Apollo Tracing: Detecting exposed tracing information that reveals sensitive query details.
- [ ] gRPC API - Reflection Service Exposure: Identifying exposed gRPC reflection services that allow schema introspection.
- [ ] REST API with Verbose Error Messages for Internal Data Structures: Detailed error messages revealing backend database schemas or object structures.
- [ ] API Endpoint Enumeration via HTTP Method Fuzzing (e.g., GET on /delete): Fuzzing HTTP methods on known paths to find hidden functionalities.
- [ ] API with Insecure Object Creation/Update (missing fields/parameters): Creating or updating objects with missing fields to bypass business logic.

### B - Microservices & Inter-Service Communication

- [ ] Internal Service Discovery Endpoints (e.g., Eureka, Consul, ZooKeeper): Identifying exposed service discovery endpoints that reveal internal network topology.
- [ ] Inter-Service Communication with Weak Authentication/No Auth: Detecting exposed internal service APIs that lack proper authentication.
- [ ] Event Bus/Message Queue Listener Injection (e.g., Kafka, RabbitMQ): Injecting malicious messages into internal event buses if web app interacts directly.
- [ ] Sidecar Proxy (e.g., Envoy, Linkerd) Misconfigurations: Detecting misconfigured sidecar proxies that expose internal services or allow traffic manipulation.
- [ ] API Orchestration Layer Vulnerabilities: Exploiting flaws in API gateways or orchestration layers that combine multiple microservices.
- [ ] Service Mesh Policy Bypass: Identifying misconfigurations in service mesh policies that allow unauthorized communication.
- [ ] Distributed Tracing (e.g., Jaeger, Zipkin) Information Leakage: Detecting exposed tracing endpoints that reveal sensitive request flows.

---

## II - Cloud-Native & Container Exploitation Deep Dive

### A - Kubernetes-Specific Attacks

- [ ] Kubernetes Insecure Dashboard Exposure (e.g., Kube-Dashboard): Detecting weakly authenticated or exposed Kubernetes dashboards.
- [ ] Kubernetes Insecure API Server Access (RBAC misconfigurations): Identifying API server access due to overly permissive RBAC policies.
- [ ] Kubernetes kubelet API Exposure: Detecting exposed kubelet API for potential container access.
- [ ] Kubernetes etcd Key-Value Store Exposure: Identifying exposed etcd instances that store cluster configuration and secrets.
- [ ] Kubernetes ConfigMap/Secret Exposure via /var/run/secrets/kubernetes.io/serviceaccount/ paths: Attempting to access mounted Kubernetes secrets via path traversal.
- [ ] Kubernetes Admission Controller Bypass: Identifying misconfigurations in admission controllers that could allow malicious deployments.
- [ ] Kubernetes Helm Chart Repository Exposure: Detecting exposed Helm chart repositories that could reveal application configurations.
- [ ] Kubernetes Network Policy Misconfigurations: Identifying misconfigured network policies that allow unauthorized pod communication.

### B - Serverless & FaaS (Function-as-a-Service)

- [ ] Serverless Function (Lambda, Azure Functions) Excessive Permissions: Detecting if a function has overly broad IAM roles or permissions.
- [ ] Serverless Function Environment Variable Disclosure: Attempting to read sensitive environment variables within serverless functions.
- [ ] Serverless Function URL Enumeration/Fuzzing: Discovering hidden or internal serverless function endpoints.
- [ ] Serverless Function Race Conditions (e.g., on inventory updates): Exploiting race conditions in serverless functions triggered by events.
- [ ] Serverless Function Cold Start Timing Attacks: Using cold start timings to infer information about functions.
- [ ] API Gateway for Lambda/Azure Functions - Insecure Integrations: Detecting misconfigured API Gateway integrations that expose backend functions or data.

### C - Cloud Storage & Data Lake Vulnerabilities

- [ ] AWS S3 Bucket with Public Write Access (specific content types): Beyond public read, identifying S3 buckets allowing arbitrary uploads for defacement or malicious file hosting.
- [ ] Azure Blob Storage Public Write Access: Detecting similar write access on Azure Blob containers.
- [ ] Google Cloud Storage Bucket Public Write Access: Identifying public write access on GCS buckets.
- [ ] Cloud Storage Bucket Policy Enumeration: Attempting to enumerate bucket policies to find subtle access control flaws.
- [ ] CloudFront/Cloudflare (CDN) Misconfigurations (e.g., origin bypass): Detecting CDN misconfigurations that allow direct access to origin servers or bypass WAFs.
- [ ] Cloud Storage Data Exfiltration via Publicly Accessible Logs: Identifying publicly accessible cloud storage buckets containing sensitive application logs.
- [ ] Cloud Storage Versioning Abuse for Data Recovery/Tampering: If versioning is enabled and misconfigured, exploiting it to retrieve old sensitive files or revert changes.

### D - Managed Database Services

- [ ] Managed Database (e.g., RDS, Azure SQL DB) Admin Panel Exposure: Detecting exposed admin panels for cloud-managed databases.
- [ ] Managed Database Connection String Leakage (via error messages, config files): Identifying exposed connection strings to managed databases.
- [ ] NoSQL Database (e.g., DynamoDB, CosmosDB) Access Control Misconfigurations: Exploiting overly permissive IAM policies or access controls for NoSQL databases.

---

## III - Sophisticated Supply Chain & CI/CD Exploitation

### A - Advanced Dependency & Build System Attacks

- [ ] Dependency Confusion with Private Package Registry: Identifying potential dependency confusion scenarios if the web app pulls from both public and private registries.
- [ ] Vulnerable Build Tools/CLI Exposure (e.g., outdated Jenkins CLI, exposed Maven/Gradle repos): Detecting exposed or outdated build tools that could be exploited.
- [ ] Compromised NPM/PyPI/Composer Package Indicators: Looking for known indicators of compromised open-source packages embedded in client-side code.
- [ ] Software Bill of Materials (SBOM) Exposure: Detecting exposed SBOMs that reveal detailed dependency trees, useful for targeted attacks.
- [ ] Package Manager Configuration File Exposure (e.g., .npmrc, pip.conf): Identifying exposed configuration files for package managers that might contain credentials.
- [ ] Docker Compose/Kubernetes Manifest File Exposure: Detecting exposed docker-compose.yml or Kubernetes manifest files with sensitive configurations.
- [ ] Source Code Disclosure via Git/SVN Dumps (.git/HEAD, .svn/entries): Deeper enumeration of Git/SVN directories to reconstruct source code.
- [ ] Web Application Firewall (WAF) Bypass via Encoding/Obfuscation: Testing advanced encoding, double encoding, or custom obfuscation techniques to bypass WAFs.
- [ ] WAF Bypass via HTTP Protocol Downgrade: Attempting to downgrade HTTP/2 to HTTP/1.1 to bypass WAF logic.
- [ ] WAF Bypass via Header Order Manipulation: Manipulating the order of HTTP headers to bypass WAF rules.
- [ ] WAF Bypass via Content-Type Mismatch: Sending a payload with a conflicting Content-Type to bypass WAF parsing.
- [ ] CDN/Reverse Proxy Log File Exposure: Detecting exposed CDN or reverse proxy logs that might contain sensitive request data.
- [ ] Sensitive Data in Webpack Bundles/Source Maps: Deep analysis of bundled JavaScript for hardcoded API keys, credentials, or sensitive business logic.
- [ ] Exposed .DS_Store files: Detecting .DS_Store files which can reveal directory structures and file names on macOS.
- [ ] Exposed .vscode directories: Revealing configuration and extensions used in VS Code projects, potentially exposing sensitive settings.

### B - CI/CD Pipeline Vulnerabilities (Web-Exposed)

- [ ] Jenkins/GitLab/GitHub Actions Webhook Abuse for RCE/SSRF: Exploiting insecure webhooks for CI/CD systems to trigger commands or SSRF.
- [ ] CI/CD Build Log Exposure (sensitive data in logs): Detecting exposed build logs that contain credentials, secrets, or internal server details.
- [ ] CI/CD Artifact Repository Exposure (e.g., Nexus, Artifactory): Identifying exposed artifact repositories with weak authentication.
- [ ] CI/CD Agent/Runner API Exposure: Detecting exposed APIs of CI/CD agents that could be used to execute arbitrary commands.

---

## IV - Advanced Injection & Data Exfiltration

### A - Next-Gen SQL/NoSQL Injection & Bypass

- [ ] Second-Order NoSQL Injection: Exploiting situations where user-controlled input, stored in one query, is later used insecurely in another NoSQL query.
- [ ] NoSQL Injection with Array/JSON Operators: Crafting advanced NoSQL injection payloads leveraging specific operators (e.g., MongoDB $where, $regex).
- [ ] Blind NoSQL Injection (time-based/error-based): Detecting blind NoSQL injection vulnerabilities through timing delays or unique error messages.
- [ ] SQL Injection in JSON/XML/YAML Input Fields: Exploiting SQL injection within structured data inputs like JSON, XML, or YAML.
- [ ] SQL Injection via HTTP Query Parameters (nested/complex): Injecting SQL into complex or deeply nested query parameters.
- [ ] Time-Based Blind SQLi in Less Common DBs (e.g., SQLite, PostgreSQL specific functions): Tailoring time-based payloads for non-MySQL/MSSQL databases.
- [ ] SQL Injection with Side-Channel Attacks (e.g., CPU/memory usage): Detecting subtle changes in server resource consumption indicative of successful injection.
- [ ] NoSQL Injection through Template Injection (SSTI to NoSQL): Chaining SSTI vulnerabilities to achieve NoSQL injection.

### B - Command Injection with Obfuscation & Evasion

- [ ] Command Injection via Environmental Variables (Advanced): Exploiting cases where environment variables can be manipulated for command injection.
- [ ] Command Injection with Path/Input Validation Bypass (e.g., using $ in filenames): Crafting payloads that bypass filename or path validation for command injection.
- [ ] Command Injection through Arbitrary File Upload (e.g., in image metadata, custom file types): Injecting commands into file content that gets executed by a backend process.
- [ ] Command Injection in Document Processors (e.g., LibreOffice, ImageMagick CVEs): Targeting specific CVEs in document or image processing libraries that lead to command injection.
- [ ] Command Injection in eval()/exec() calls (dynamic code execution): Identifying and exploiting insecure use of dynamic code execution functions.

### C - Data Exfiltration & Sensitive Information Leakage

- [ ] Credential Leakage via Error Pages with Specific Stack Traces: Identifying detailed error pages that include database credentials or API keys in stack traces.
- [ ] Unintended Debugging Mode Exposure: Detecting applications running in debug mode that expose sensitive internal information.
- [ ] Log File Injection & Exposure (e.g., injecting sensitive data into logs, then viewing logs): Injecting sensitive data into application logs which are later exposed via a web interface.
- [ ] Arbitrary File Download via Path Traversal with Encoding/Filtering Bypass: Advanced path traversal techniques to download sensitive files.
- [ ] Exposed Sensitive Environment Variables (e.g., cloud provider credentials): Checking for exposed environment variables in JavaScript, error messages, or internal endpoints.
- [ ] Database Backup File Exposure (e.g., .sql, .bak files): Detecting inadvertently exposed database backup files.
- [ ] Password Policy Weakness (detecting guessable/common passwords, length limits): Identifying weak password policies that make brute-force or dictionary attacks feasible.
- [ ] Information Disclosure via HTTP Headers (e.g., custom X-Powered-By, Server details): Extracting sensitive version or technology information from non-standard HTTP headers.
- [ ] Sensitive Data in XML/JSON/YAML Comments: Discovering sensitive data hidden in comments within configuration files or API responses.
- [ ] Client-Side Information Disclosure via Browser Developer Tools: Indicators that sensitive data is logged to the console or stored in localStorage insecurely.

---

## V - Advanced Client-Side Vulnerabilities & Browser Exploitation

### A - Deep XSS & DOM Manipulation

- [ ] DOM XSS via postMessage Listener Injection: Exploiting insecure postMessage event listeners for DOM XSS.
- [ ] DOM XSS in Client-Side Routers/URL Parsers: Identifying XSS vulnerabilities in how client-side routing libraries handle URL parameters.
- [ ] Client-Side Template Injection (CSTI) in JavaScript Frameworks (e.g., Angular, Vue.js): Exploiting client-side template engines for XSS.
- [ ] Mutation XSS (mXSS) in SVG/HTML srcset or data: attributes: Crafting complex mXSS payloads that leverage attribute parsing quirks.
- [ ] XSS in WebSockets (complex message types, nested JSON): Injecting XSS payloads into sophisticated WebSocket message structures.
- [ ] XSS via Blob/File URI Scheme Injection: Using blob: or file: URIs to bypass content-type restrictions and achieve XSS.
- [ ] CSS Injection for Data Exfiltration (e.g., via attribute selectors and CSS properties): Exploiting CSS injection to exfiltrate sensitive data.
- [ ] Content Security Policy (CSP) Bypass via eval()/setTimeout() with nonces: Identifying CSP bypasses when nonces are not properly implemented or are predictable.
- [ ] CSP Bypass via Trusted Types Misconfigurations: Exploiting insecure configurations of Trusted Types.
- [ ] XSS via window.name property manipulation: Exploiting vulnerabilities where window.name is used insecurely.
- [ ] Client-Side Prototype Pollution Leading to CSRF Bypass: Using prototype pollution to manipulate CSRF tokens or origin checks.
- [ ] Clickjacking with Scroll-Based Obfuscation: Crafting clickjacking attacks that use scroll positioning to hide malicious elements.
- [ ] Clickjacking with X-Frame-Options Bypass (e.g., data: URI, SVG): Using unconventional methods to bypass X-Frame-Options.
- [ ] UI Redressing (e.g., Login Overlay Attacks): Detecting scenarios where UI elements can be maliciously overlaid.

### B - Advanced Browser & Web API Attacks

- [ ] Web Messaging (postMessage) Vulnerabilities (Target Origin Bypass): Exploiting postMessage vulnerabilities due to incorrect target origin validation.
- [ ] Service Worker Cross-Site Scripting (SW-XSS): Injecting malicious code into a service worker, leading to persistent XSS.
- [ ] Service Worker Cache Poisoning: Manipulating service worker caches to deliver malicious content.
- [ ] Web Push Notification Abuse (unauthorized sending): If the web app uses Web Push, checking for vulnerabilities allowing unauthorized notification sending.
- [ ] WebAuthn (FIDO2) API Bypass/Misconfiguration: Detecting flaws in WebAuthn implementations that could lead to authentication bypass.
- [ ] WebRTC IP Leakage (even with VPN/Proxy): Identifying configurations that allow WebRTC to leak real IP addresses.
- [ ] Web Sockets with Insufficient Origin Validation: Detecting WebSockets that accept connections from any origin, making them vulnerable to cross-site attacks.
- [ ] Browser Extension Vulnerabilities (if specific extensions required): While external, patterns could detect if a web app relies on a vulnerable extension.
- [ ] Content Security Policy (CSP) Bypass via JSONP with Callback Manipulation: Specific JSONP callback manipulation to bypass CSP.
- [ ] Client-Side Cache Poisoning (e.g., via Vary header abuse): Causing a client's browser cache to store malicious content.
- [ ] Client-Side HTTP Request Smuggling (Browser-to-Proxy): Detecting subtle differences in how browsers and proxies interpret HTTP requests.
- [ ] HTML Injection with Script Gadgets (using benign tags to trigger XSS): Injecting HTML that, while not directly XSS, contains elements that can be exploited by existing scripts.
- [ ] Client-Side Deserialization Vulnerabilities (e.g., localStorage objects): If client-side code deserializes user-controlled data from localStorage or sessionStorage insecurely.

---

## VI - Niche Protocol & Emerging Technology Exploitation

### A - Web3 / Blockchain Interactions

- [ ] Front-End Smart Contract Interaction Logic Flaws: Analyzing how the web app builds smart contract transactions for manipulation.
- [ ] Decentralized Identity (DID) Misconfigurations: If using DIDs, checking for insecure implementations.
- [ ] WalletConnect Session Hijacking (misconfigured dapp): Detecting vulnerabilities in WalletConnect integrations that could lead to session hijacking.
- [ ] IPFS Gateway Misconfigurations (e.g., path traversal on IPFS hashes): Exploiting insecure IPFS gateway configurations.
- [ ] ENS (Ethereum Name Service) Resolution Vulnerabilities: If the app resolves ENS names, checking for injection flaws.

### B - GraphQL & Query Language Exploitation

- [ ] GraphQL Introspection Limit Bypass: Finding ways to bypass limits on GraphQL introspection queries.
- [ ] GraphQL Schema Stitching Vulnerabilities (Advanced): Exploiting complex interactions between stitched GraphQL schemas.
- [ ] GraphQL N+1 Query Problem for DoS/Resource Exhaustion: Detecting GraphQL queries that lead to excessive backend database calls.
- [ ] GraphQL Mutations with Missing Authorization: Identifying GraphQL mutations that lack proper authorization checks.
- [ ] GraphQL Subscription Information Disclosure: Exploiting GraphQL subscriptions to receive unauthorized sensitive data in real-time.

### C - Other Niche Protocols & Web Tech

- [ ] WebAssembly (Wasm) Memory Corruption (if web app serves vulnerable Wasm): Identifying specific Wasm modules known to have memory corruption vulnerabilities.
- [ ] WebTransport API Misuse/Vulnerabilities (e.g., unauthenticated streams): If leveraging Web Transport, checking for misuse or flaws in its implementation.
- [ ] QUIC Protocol Downgrade Attacks: Attempting to force a downgrade to a less secure protocol version.
- [ ] Server-Sent Events (SSE) Cross-Site Information Disclosure: Exploiting SSE to leak sensitive data across origins.
- [ ] WebSockets with Insufficient Rate Limiting: Identifying WebSocket endpoints vulnerable to denial of service via excessive messages.
- [ ] WebSockets with Message Replay Attacks: Detecting if WebSocket messages lack sufficient nonces or timestamps to prevent replay.

---

## VII - Advanced Reconnaissance & Information Disclosure

### A - Deep OSINT & Footprinting

- [ ] Sensitive Data in Git History (exposed .git dir): Analyzing exposed Git repositories for sensitive data in commit history.
- [ ] Exposed Kubernetes Kubeconfig Files: Detecting exposed .kube/config files that grant cluster access.
- [ ] Internal Network Range Disclosure (e.g., in error messages, verbose logs): Extracting internal IP ranges from various application responses.
- [ ] Employee Email/Username Enumeration (e.g., via "Forgot Password" or registration flows): Identifying valid employee accounts.
- [ ] Exposed .ssh directories or SSH keys: Detecting exposed SSH configuration or private keys.
- [ ] Configuration Management Files (e.g., Ansible, Puppet, Chef) Exposure: Identifying exposed configuration management files that reveal infrastructure details.
- [ ] Database Schema Disclosure (e.g., via specific error messages or debug endpoints): Detailed database schema information leaked.
- [ ] Hardcoded AWS/Azure/GCP Access Keys/Secrets in JS/Config Files: Actively looking for cloud provider credentials.
- [ ] Software Bill of Materials (SBOM) Exposure via /sbom.json or similar paths: Automated detection of SBOMs for deeper dependency analysis.
- [ ] Exposed OpenAPI/Swagger/Postman Collection files (sensitive endpoints/params): Finding API documentation files that expose sensitive or internal endpoints.
- [ ] Server-Side Rendering (SSR) Context Information Leakage: If SSR, looking for accidentally exposed server-side context data.
- [ ] Legacy/Deprecated API Endpoint Discovery: Using wordlists and historical data to find old API versions that might be less secure.
- [ ] HTTP Request History Files (e.g., curl_history, wget-log): Detecting inadvertently exposed command history files.
- [ ] Exposed .htaccess or web.config files revealing sensitive rewrite rules/auth: Finding web server configuration files that might reveal bypass opportunities.
- [ ] Sensitive Data in Application Logs (e.g., usernames, emails, internal IDs): Scanning for directly exposed application logs with PII or other sensitive data.
- [ ] Information Disclosure via GraphQL Introspection (filtered but bypassable): Even with introspection filters, finding ways to extract partial schema info.
- [ ] Exposed /metrics endpoints (e.g., Prometheus, Grafana, exposing internal metrics): Detecting monitoring endpoints with sensitive system metrics.
- [ ] Sensitive Data in CDN Edge Cache (e.g., miscached authenticated content): Checking for sensitive data being inadvertently cached by CDNs.

### B - Advanced Fingerprinting & Version Detection

- [ ] Component Version Fingerprinting (Nth-degree precision): Detecting specific patch versions of libraries and frameworks to correlate with known CVEs.
- [ ] Operating System Fingerprinting (via specific error messages, headers, or file paths): Inferring the underlying OS.
- [ ] Database Server Fingerprinting (specific versions/builds): Detailed database version identification.
- [ ] Load Balancer/Proxy Fingerprinting (specific vendor/version): Identifying specific load balancer or proxy technologies.
- [ ] Container Runtime Fingerprinting (e.g., Docker, Containerd, CRI-O): Inferring the container runtime used.
- [ ] Virtualization Technology Fingerprinting (e.g., VMWare, KVM indicators): Detecting virtualization platforms through subtle clues.
- [ ] Endpoint Functionality Fingerprinting (e.g., if it's an upload, login, search, etc.): Categorizing endpoints by functionality.
- [ ] Language/Framework Specific Default Files/Paths: Detecting common default files/paths for specific languages/frameworks (e.g., struts2-showcase.war).
- [ ] Cloud Provider Service Fingerprinting (e.g., specific AWS SQS/SNS endpoints): Identifying explicit cloud service endpoints in use.
- [ ] Backend Caching Mechanism Fingerprinting (e.g., Redis, Memcached indicators): Detecting the presence of specific caching layers.

---

## VIII - Advanced Authentication & Authorization Bypasses

### A - SSO, OAuth, & JWT Deep Dives

- [ ] OAuth PKCE (Proof Key for Code Exchange) Downgrade: Exploiting implementations that fail to enforce PKCE properly.
- [ ] OAuth State Parameter Misuse (CSRF Bypass): Detecting scenarios where the OAuth state parameter isn't properly validated against CSRF.
- [ ] JWT Algorithm Confusion (e.g., HS256 to RS256 bypass): Exploiting JWT signature verification flaws.
- [ ] JWT Header Injection (e.g., jku, x5u for key material injection): Exploiting injection flaws in JWT header parameters.
- [ ] JWT Weak Secret Detection (Brute-Force/Dictionary Attack): Attempting to brute-force weak JWT secrets.
- [ ] SSO Logout Functionality Bypass: Detecting if logging out of the application doesn't properly invalidate the SSO session.
- [ ] OAuth Client ID/Secret Misuse (for unauthorized token generation): Exploiting exposed or weak OAuth client credentials.
- [ ] SAML Assertion Signature Bypass (e.g., XML signature wrapping): Detecting advanced SAML vulnerabilities.
- [ ] OpenID Connect ID Token Validation Bypass: Exploiting flaws in ID token validation (e.g., nonce replay).

### B - MFA & Session Management Nuances

- [ ] MFA Bypass via Recovery Code Replay: Exploiting recovery codes that can be reused multiple times.
- [ ] MFA Bypass via "Remember Me" Token Impersonation: If MFA doesn't apply to "remember me" tokens.
- [ ] MFA Bypass via Insufficient Rate Limiting on Code Entry: Brute-forcing MFA codes.
- [ ] Session Cookie Cross-Site Leakage (via subdomains or permissive domain attribute): Detecting session cookies visible to other subdomains.
- [ ] Session Management via URL Rewriting (cookie-less sessions): Identifying and testing cookie-less session management for fixation or prediction.
- [ ] Session Fixation through Predictable Session ID Generation (after unauthenticated action): Detecting weak session ID generation during unauthenticated phases.
- [ ] Session Invalidation Flaws (e.g., after password change, still active): Detecting sessions that remain valid after a password change.

### C - Access Control Bypasses (Contextual & Logic-Based)

- [ ] Broken Access Control via HTTP Headers (e.g., X-Original-URL, X-Rewrite-URL): Manipulating request headers to bypass access controls.
- [ ] Access Control Bypass via HTTP Method/Verb Tampering (e.g., POST instead of GET on admin functions): Testing different HTTP methods on restricted endpoints.
- [ ] Broken Object Level Authorization (BOLA) in Batch/Bulk Endpoints: Exploiting BOLA when multiple objects can be requested in a single call.
- [ ] BOLA via Nested Objects/Complex IDs: Exploiting BOLA in deeply nested JSON structures or using complex UUIDs/hashes.
- [ ] BOLA via Parameter Pollution (e.g., id=1&id=2): Using parameter pollution to access unauthorized objects.
- [ ] Context-Dependent Authorization Bypass (e.g., function accessible via specific referrer): Access control that depends on the context of the request (e.g., Referer header).
- [ ] Role Manipulation via Client-Side Storage (e.g., localStorage, sessionStorage): Attempting to change user roles stored client-side.
- [ ] Privilege Escalation via User Impersonation (e.g., by changing a user ID in the request): Attempting to impersonate other users by modifying user IDs.
- [ ] Access Control Bypass via Insecure Redirects (e.g., redirecting to privileged pages): Leveraging open redirects to bypass access controls.
- [ ] Directory Traversal for Authorization Bypass (e.g., accessing sibling directories for sensitive content): Using directory traversal not just for LFI, but to bypass authorization.

---

## IX - Advanced Business Logic & Race Conditions

### A - Deeper Business Logic Flaws

- [ ] Price Manipulation via Client-Side Parameters (hidden inputs, JS manipulation): Modifying prices or quantities in client-side parameters.
- [ ] Discount Code Abuse (e.g., reuse, stacking, invalid codes): Exploiting flaws in discount code validation.
- [ ] Inventory Manipulation/Over-Purchase: Exploiting logic flaws to purchase more items than available or intended.
- [ ] Gift Card/Voucher Code Brute-Force/Prediction: Attempting to guess or predict valid gift card codes.
- [ ] Refund/Credit Abuse: Exploiting flaws in refund or credit issuance mechanisms.
- [ ] Voting/Polling System Abuse (e.g., multiple votes from one user, vote manipulation): Bypassing controls in voting systems.
- [ ] User Registration/Account Creation Logic Flaws (e.g., creating admin accounts, bypassing email verification): Exploiting weaknesses in account creation.
- [ ] Feature Flag Bypass/Abuse: Gaining access to unreleased or restricted features by manipulating feature flags.
- [ ] Referral Program Abuse (e.g., self-referral for credits): Exploiting referral programs for illicit gains.
- [ ] Subscription Downgrade/Upgrade Bypass: Changing subscription tiers without proper validation.
- [ ] Loyalty Program/Points Manipulation: Exploiting flaws in loyalty points systems.
- [ ] Account Recovery Process Abuse (e.g., bypassing security questions): Exploiting weaknesses in account recovery.
- [ ] Payment Gateway Integration Flaws (e.g., skipping payment step, manipulating callback): Identifying flaws in payment gateway integrations.
- [ ] Cross-User Data Manipulation via Shared References: If an object ID refers to data shared between users, exploiting logic to manipulate another user's data.

### B - Sophisticated Race Conditions

- [ ] Race Condition in Session Token Generation: Exploiting a race condition where multiple login attempts could yield the same session token.
- [ ] Race Condition for Unauthorized File Overwrite: Exploiting a race to overwrite a file before permissions are applied.
- [ ] Race Condition in Resource Allocation (e.g., limited seats, unique IDs): Exploiting race conditions on limited resources.
- [ ] Race Condition in Password Reset Token Generation/Validation: Exploiting timing windows in password reset flows.
- [ ] Race Condition in Account Deletion/Dormancy: Exploiting race conditions during account state changes.
- [ ] Race Condition in API Rate Limiting Enforcement: Sending bursts of requests to bypass eventual consistency rate limits.
- [ ] Race Condition in Financial Transaction Confirmation: Exploiting timing between payment initiation and confirmation.

---

## X - Advanced Web Server & Configuration Vulnerabilities

### A - Web Server & Reverse Proxy Deep Misconfigurations

- [ ] Nginx/Apache Alias Traversal: Exploiting misconfigured aliases that allow directory traversal.
- [ ] Nginx/Apache Proxy Pass Misconfigurations (e.g., proxy_pass to internal IPs): Detecting proxy_pass directives pointing to internal services.
- [ ] CORS Misconfigurations (complex scenarios like multiple Access-Control-Allow-Origin headers): Detecting intricate CORS policy flaws.
- [ ] HTTP Request Smuggling (Advanced Transfer-Encoding/Content-Length combinations): More complex request smuggling techniques.
- [ ] Web Cache Deception with Authentication Bypass: Tricking caching mechanisms to serve authenticated content to unauthenticated users.
- [ ] Web Cache Poisoning with Header Splitting: Injecting malicious headers to poison the cache for other users.
- [ ] CRLF Injection in Response Headers for Cache Poisoning: Injecting CRLF into user-controlled input to manipulate HTTP response headers.
- [ ] HTTP Host Header Attacks (Password Reset Poisoning via crafted Host header): Exploiting Host header for password reset poisoning.
- [ ] DNS Rebinding Attacks (Server-Side for internal network access): Exploiting DNS rebinding in server-side contexts for internal network access.
- [ ] Web Server Specific Default Pages/Files (e.g., IIS default pages, Apache test pages): Detecting default installations that provide information.
- [ ] Exposed Configuration Files (e.g., nginx.conf, httpd.conf, haproxy.cfg if exposed): Finding web server configuration files that disclose sensitive information.
- [ ] Server Status Page Exposure (e.g., Apache mod_status, Nginx stub_status): Detecting exposed server status pages.

### B - Certificate & TLS/SSL Misconfigurations

- [ ] Expired/Self-Signed SSL Certificates (with clear warnings): Detecting improperly configured SSL certificates.
- [ ] Weak SSL/TLS Cipher Suites (e.g., RC4, 3DES): Identifying the use of weak cryptographic cipher suites.
- [ ] Missing Strict-Transport-Security (HSTS) Header: Detecting the absence of HSTS for secure connections.
- [ ] SSL/TLS Heartbleed/CCS Injection (if older versions detected): Detecting historical but critical SSL/TLS vulnerabilities.
- [ ] Client-Side Certificate Validation Bypass: If client certificates are used, detecting flaws in their validation.
- [ ] Wildcard Certificate Misuse (e.g., covering unintended subdomains): Identifying wildcard certs used for overly broad coverage.

---

## XI - Advanced Input Validation & Encoding Bypass

- [ ] Double Encoding Bypass: Testing payloads that require multiple layers of URL encoding to bypass filters.
- [ ] Unicode Encoding Bypass: Using Unicode characters to bypass input validation filters.
- [ ] Null Byte Injection (%00) for Path/Extension Bypass: Injecting null bytes to terminate strings and bypass filename or path checks.
- [ ] Padding Oracle Attack Vulnerabilities (if applicable to encryption scheme): Detecting vulnerabilities in padding schemes used for encryption.
- [ ] Blind XSS with Delayed OOB Interaction (e.g., via image loading or script tags in logs): Using OOB interactions to confirm blind XSS.
- [ ] XSS in PDF Generators (if converting user input to PDF): Injecting XSS into PDF generation processes.
- [ ] Header Injection in Backend Calls (e.g., for SSRF, SQLi): Injecting malicious headers into backend HTTP calls.
- [ ] HTML Entity Encoding Bypass (e.g., &#xNN; vs. &lt;): Using various HTML entity encoding forms to bypass XSS filters.
- [ ] Polyglot Payloads (e.g., combining SQLi and XSS in one input): Crafting payloads that work across multiple injection types.
- [ ] Input Fuzzing with Character Set Mutations: Fuzzing inputs with unusual character sets to trigger parsing errors.
- [ ] Length Limit Bypass (e.g., using different encodings to shorten payload): Crafting payloads that appear shorter than they are to bypass length limits.
- [ ] Bypassing Regex Filters with Edge Cases: Crafting inputs that exploit the edge cases or misconfigurations of regular expressions.
- [ ] URL Parser Differentials (between web server, WAF, application): Exploiting inconsistencies in how different components parse URLs.

---

## XII - Advanced Application Logic & Edge Cases

- [ ] Cross-Site Request Forgery (CSRF) on JSON Endpoints with specific headers (e.g., custom Content-Type): Exploiting CSRF where Content-Type might be less strictly validated.
- [ ] CSRF with SameSite Cookie Attribute Bypass (e.g., None without Secure): Identifying misconfigurations of the SameSite attribute.
- [ ] Cross-Site Tracing (XST) enabled (TRACE method): Detecting if the TRACE HTTP method is enabled, which can aid XSS.
- [ ] Cookie Bombing/Session Exhaustion: Sending excessive or malformed cookies to trigger DoS or session invalidation.
- [ ] Cache Miss Exploitation (e.g., forcing a cache miss to expose sensitive data): Manipulating requests to bypass caching and hit the origin server.
- [ ] Cache Invalidation Issues (e.g., old data served after update): Detecting if cached data isn't properly invalidated after changes.
- [ ] Time-Based Information Disclosure (e.g., different response times for valid/invalid inputs): Using subtle timing differences to infer sensitive information.
- [ ] Resource Exhaustion via Complex Query/Input (e.g., nested XML/JSON with deep recursion): Crafting inputs that cause resource exhaustion.
- [ ] Denial of Service (DoS) via Thread Exhaustion: Sending requests that cause the application to consume all available threads.
- [ ] DoS via File Descriptor Exhaustion: Triggering a large number of file operations to exhaust file descriptors.
- [ ] DoS via Memory Exhaustion (e.g., large file uploads, infinite loops): Causing the application to consume excessive memory.
- [ ] DoS via CPU Exhaustion (e.g., complex regex, cryptographic operations): Sending inputs that trigger CPU-intensive operations.
- [ ] Insecure Random Number Generation: Identifying indicators of weak random number generation for tokens or IDs.
- [ ] Weak Entropy in Cryptographic Keys/IDs: Detecting if cryptographic keys or IDs are easily predictable.
- [ ] Predictable URLs/Filenames for Sensitive Resources: Guessing paths to sensitive files or pages.
- [ ] Improper Handling of UTF-8/Unicode Characters: Exploiting how the application handles different Unicode representations.
- [ ] Broken Link Hijacking on JavaScript Imports: If external JS imports are broken, attempting to hijack them.
- [ ] Dangling DNS Records: Finding old DNS records that point to non-existent resources.
- [ ] Subdomain Takeover via SaaS Service Records: Identifying dangling DNS records that can be taken over on SaaS platforms.
- [ ] Reflected File Download (RFD) vulnerabilities: Tricking browsers into downloading files with malicious content based on URL parameters.
- [ ] URL Redirection Chain Attacks: Exploiting multiple redirects to reach a malicious destination or bypass filters.
- [ ] XML Bomb (Billion Laughs Attack) for DoS: Sending a specially crafted XML document to consume server resources.
- [ ] ZIP Bomb for DoS: If file uploads are allowed, attempting to upload a ZIP bomb.
- [ ] Regex Denial of Service (ReDoS): Supplying input that causes inefficient regular expressions to consume excessive CPU.
- [ ] Server-Side Request Smuggling (Advanced HTTP/2, WebSockets): Smuggling requests over HTTP/2 or WebSockets.
- [ ] Client-Side Request Smuggling for XSS/Cache Poisoning: Exploiting differences in client-side vs. server-side interpretation of requests.
- [ ] Web Scraping/Data Harvesting Bypass: Identifying and bypassing anti-scraping measures.
- [ ] Browser Fingerprinting Evasion Techniques: Techniques to bypass browser fingerprinting.
- [ ] Device Fingerprinting Bypass: Bypassing device-based authentication or tracking.
- [ ] Broken Anti-Bot Measures (e.g., easy bypass of honeypots, CAPTCHA): Identifying and bypassing anti-bot measures.
- [ ] User Enumeration via Registration/Login Timing Differences: Subtle timing differences revealing if a username exists.
- [ ] Sensitive Data in JavaScript Console (runtime exposure): Detecting sensitive data logged to the browser console during runtime.
- [ ] Session Hijacking via Network Sniffing (if not using HTTPS): Basic but critical, checking for lack of HTTPS.
- [ ] Brute-Force Protection Bypass via IP Rotation/Header Spoofing: Bypassing brute-force protections.
- [ ] File Inclusion/Path Traversal (non-standard delimiters, wrappers): Using less common delimiters or PHP wrappers for file inclusion.
- [ ] Log Poisoning for RCE (via LFI to logs): Injecting malicious commands into logs that are later included and executed.
- [ ] XML External Entity (XXE) to Local File Write (if applicable): Exploiting XXE to write files to the server.
- [ ] Server-Side Template Injection (SSTI) in Email Templates: Injecting into email templates processed server-side.
- [ ] SSTI with Class Loader Manipulation (Java): Advanced SSTI leading to manipulation of class loaders for RCE.
- [ ] Deserialization via Image/File Uploads (e.g., Java ObjectInputStream): Uploading crafted serialized objects within file formats.
- [ ] Deserialization via Custom Data Formats: Exploiting deserialization in custom, proprietary data formats.
- [ ] GraphQL SQL Injection: Injecting SQL payloads into GraphQL queries.
- [ ] GraphQL NoSQL Injection: Injecting NoSQL payloads into GraphQL queries.
- [ ] GraphQL Command Injection: Injecting OS commands into GraphQL queries.
- [ ] GraphQL Sensitive Field Exposure (via query depth/alias): Querying deeply or using aliases to expose sensitive fields.
- [ ] GraphQL CSRF: Exploiting CSRF on GraphQL endpoints.
- [ ] GraphQL IDOR: Exploiting IDOR through GraphQL queries.
- [ ] GraphQL Rate Limit Bypass (complex queries): Bypassing rate limits by crafting complex GraphQL queries.
- [ ] WebSocket Protocol Downgrade: Forcing WebSockets to downgrade to a less secure communication method.
- [ ] WebSocket Message Flooding for DoS: Sending high volume of WebSocket messages to cause DoS.
- [ ] WebSocket Origin Bypass: Connecting to WebSockets from unauthorized origins.
- [ ] WebSocket Authentication Bypass: Bypassing authentication on WebSocket connections.
- [ ] WebTransport Header Injection: Injecting headers into WebTransport frames.
- [ ] WebTransport Data Exfiltration: Using WebTransport to exfiltrate data.
- [ ] WebTransport Session Hijacking: Hijacking WebTransport sessions.
- [ ] WebWorker SharedArrayBuffer Misuse: Exploiting SharedArrayBuffer vulnerabilities in WebWorkers.
- [ ] WebWorker DoS (e.g., infinite loops): Causing DoS by creating infinite loops in WebWorkers.
- [ ] Server-Sent Events (SSE) Cross-Origin Leakage: Sensitive data leakage via SSE due to lax CORS.
- [ ] HTTP/3 (QUIC) Protocol Smuggling: Smuggling requests over QUIC if enabled.
- [ ] HTTP/3 (QUIC) Cache Poisoning: Poisoning caches via HTTP/3.
- [ ] HTTP/3 (QUIC) DoS: DoS attacks specific to the QUIC protocol.
- [ ] HTTP TE: trailers Header Smuggling: Exploiting TE: trailers header for request smuggling.
- [ ] Content-Disposition Header Injection (for filename spoofing): Manipulating Content-Disposition for malicious file downloads.
- [ ] Strict-Transport-Security (HSTS) Bypass (e.g., DNS record manipulation): Exploiting HSTS bypass techniques.
- [ ] Cross-Origin Read Forbidden (CORF) bypasses: Bypassing CORF protections to read sensitive data.
- [ ] TLS Certificate Pinning Bypass Indicators: Detecting if an application uses certificate pinning and if there are potential bypasses.
- [ ] Application-Specific Custom Header Injection: Injecting custom headers unique to the application to bypass logic.
