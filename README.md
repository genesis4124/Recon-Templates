# Recon-Templates
Recon Templates
 Template Categories & Advanced Checklist
Below is a comprehensive list of the advanced web application vulnerabilities and attack vectors that our Nuclei templates target. This serves as a live checklist of our current capabilities and a roadmap for ongoing development!

Next-Gen Server-Side Vulnerabilities & Bypass Techniques
I. Next-Gen Server-Side Vulnerabilities & Bypass Techniques
A. Advanced Server-Side Request Forgery (SSRF) & Internal Network Exposure
[ ] SSRF with Multi-Level Redirection Bypasses: Templates that meticulously follow and analyze multiple HTTP redirects (e.g., 302 -> 301 -> 307) to reach internal services, bypassing simple redirect filters.

[ ] SSRF via DNS Rebinding: Exploiting DNS rebinding techniques to circumvent IP-based SSRF filters, demonstrating access to restricted internal IPs.

[ ] SSRF to Cloud Metadata Endpoints (obscure paths): Targeting less common cloud metadata endpoints (e.g., Azure, GCP, Alibaba Cloud) beyond the standard AWS 169.254.169.254, identifying sensitive cloud configuration.

[ ] SSRF to Internal K8s API Servers: Detecting unauthorized access to Kubernetes API servers (e.g., /api/v1/namespaces/kube-system/secrets) for potential cluster compromise.

[ ] SSRF with URL Scheme Confusion: Leveraging unusual URL schemes like dict://, gopher://, file:// to access internal resources or execute arbitrary code on the backend.

[ ] SSRF to Internal NoSQL Databases (e.g., MongoDB, Redis): Probing for default NoSQL ports and identifying exposed instances that could lead to data exfiltration or manipulation.

[ ] SSRF to Internal Message Queues (e.g., RabbitMQ, Kafka): Probing for administrative interfaces or exposed queues that might contain sensitive data.

[ ] SSRF to Internal Monitoring/Telemetry Services (e.g., Prometheus, Grafana): Identifying sensitive internal metrics or dashboards often running on internal networks.

[ ] SSRF with HTTP Parameter Pollution (HPP) in Query/Body: Crafting requests that exploit HPP to manipulate internal SSRF logic and bypass filters.

[ ] SSRF to Internal Git Repositories: Attempting to access .git directories or internal Git servers via SSRF for source code disclosure.

[ ] SSRF with Authentication Bypass (e.g., default creds): Identifying internal services that use common default credentials accessible via SSRF.

[ ] SSRF with Host Header Forgery: Manipulating the Host header in conjunction with SSRF to target specific internal services or bypass WAFs.

[ ] SSRF via Image/File Upload Processors: Exploiting vulnerabilities in image or file processing libraries that fetch external resources, leading to SSRF.

[ ] SSRF via PDF/Document Converters: Detecting SSRF opportunities in services that convert URLs to PDF or other document formats.

[ ] SSRF through Server-Side Template Engines (SSTI) with External Resource Loading: Chaining SSTI with external resource loading capabilities to achieve SSRF and read sensitive files.

B. Advanced Template Injection (SSTI) & Deserialization
[ ] SSTI in Obscure Template Engines: Beyond common engines like Jinja2 or Twig, targeting less popular or custom template engines that often lack robust sanitization.

[ ] SSTI with Gadget Chain Discovery (Java/Python): Identifying specific "gadgets" in an application's dependencies that, when combined with SSTI or deserialization, can lead to Remote Code Execution (RCE).

[ ] SSTI with Sandbox Escapes (specific versions): Exploiting known sandbox bypasses in older or misconfigured template engine versions to gain RCE.

[ ] SSTI via XML External Entity (XXE) to Local File Read: Combining SSTI with XXE for sophisticated local file read vulnerabilities.

[ ] Deserialization Vulnerabilities in Less Common Formats: Beyond Java/PHP, focusing on Python Pickle, .NET, or Ruby YAML deserialization, often missed by generic scanners.

[ ] Deserialization with Custom Object Injection: Identifying and exploiting custom classes that are deserialized insecurely, leading to RCE or other impacts.

[ ] SSTI/Deserialization in CI/CD Webhooks: Targeting webhooks used for CI/CD pipelines that might be vulnerable to injection, potentially leading to build system compromise.

[ ] SSTI in Email Template Rendering Services: Exploiting vulnerabilities in services that generate dynamic email content, leading to internal data exposure or spam.

C. Emerging API Security Flaws (beyond OWASP API Top 10)
[ ] Excessive Data Exposure via GraphQL Type Introspection (with filtering bypasses): Crafting specific GraphQL queries that reveal more than intended, even with basic filtering, by understanding the schema's deeper relationships.

[ ] GraphQL Query Complexity Attacks (Denial of Service): Generating overly complex or deeply nested GraphQL queries designed to trigger DoS by overwhelming server resources.

[ ] GraphQL Batching Abuse for Rate Limit Bypass: Exploiting GraphQL's batching feature to circumvent rate limiting on individual API calls.

[ ] Broken Function Level Authorization (BFLA) in Microservices/Internal APIs: Identifying granular authorization flaws when different services communicate internally, often exposing unintended functionality.

[ ] Mass Assignment/Parameter Tampering in API Endpoints (nested objects): Exploiting vulnerabilities where attackers can inject or overwrite unexpected parameters, especially within complex nested JSON/object structures, leading to data manipulation.

[ ] API Rate Limiting Bypasses (e.g., via IP rotation, header manipulation): Crafting requests that circumvent typical rate limiting mechanisms.

[ ] Unauthenticated/Weakly Authenticated Internal API Exposure: Discovering internal-only APIs that are exposed to the internet or have weak authentication, providing direct access to backend services.

[ ] API Security Misconfigurations (e.g., verbose error messages, exposed debug endpoints): Identifying endpoints that reveal sensitive information or debugging interfaces.

[ ] API Key Reuse/Hardcoded Keys in Client-Side Code: Detecting hardcoded API keys in JavaScript or client-side bundles that could be abused.

[ ] API-Specific Injection Flaws (e.g., NoSQL Injection in API parameters): Beyond SQL injection, targeting NoSQL databases via API inputs.

[ ] Insecure Direct Object Reference (IDOR) with Encoding/Hashing Bypasses: Exploiting IDORs where object IDs are encoded or hashed, but the scheme is guessable or breakable.

[ ] Client-Side API Key Exploitation (e.g., Google Maps API key abuse): Identifying exposed API keys and demonstrating potential abuse (e.g., excessive usage, sensitive data access).

[ ] GraphQL Schema Stitching Vulnerabilities: Identifying vulnerabilities where stitching multiple GraphQL schemas introduces new attack surfaces or information disclosure.

[ ] API Gateway Misconfigurations (e.g., improper routing, unauthorized access): Exploiting misconfigurations in API gateways that lead to bypassing security controls.

D. Advanced XXE (XML External Entity)
[ ] XXE to Remote Code Execution (via JAR/PHAR deserialization): Chaining XXE with deserialization gadgets for RCE.

[ ] XXE with Out-of-Band (OOB) Data Exfiltration (DNS/HTTP): Using OOB techniques to exfiltrate sensitive data via XXE.

[ ] XXE in Non-XML Parsers (e.g., certain image parsers, document processors): Identifying XXE in unexpected file formats or processing stages.

[ ] XXE via DTD File Upload: Exploiting applications that allow DTD file uploads to trigger XXE.

[ ] XXE with Blind Out-of-Band Interaction: Detecting blind XXE vulnerabilities through delayed OOB interactions.

E. Modern SSRF & Internal Service Interaction
[ ] SSRF to internal database connections strings (e.g., jdbc:mysql://): Identifying if error messages disclose internal database connection strings via SSRF.

[ ] SSRF via data: URI scheme to bypass WAFs: Using data: URIs to smuggle content past WAFs or content filters.

[ ] SSRF to identify and interact with internal container registries: Probing for exposed Docker registries or other container image repositories.

[ ] SSRF to access internal environment variables via file paths: Attempting to read /proc/self/environ or similar sensitive paths via SSRF.

[ ] SSRF to internal message bus systems (e.g., Kafka, RabbitMQ APIs): Interacting with internal messaging systems for data exfiltration or manipulation.

[ ] SSRF to internal cloud service control planes (e.g., private APIs for AWS, GCP, Azure management): Exploiting lesser-known internal control plane APIs accessible via SSRF.

II. Sophisticated Client-Side Attacks
A. Prototype Pollution & XSS Gadget Chaining
[ ] Client-Side Prototype Pollution via URL Hash/Query Parameters: Detecting prototype pollution vulnerabilities from URL parameters.

[ ] Prototype Pollution to XSS Gadget Chaining (Framework-Specific): Identifying and exploiting known gadget chains in popular JavaScript frameworks (React, Angular, Vue) to achieve XSS via prototype pollution.

[ ] Prototype Pollution leading to DOM Clobbering for XSS/Bypass: Exploiting prototype pollution to perform DOM clobbering attacks to manipulate page content or bypass security controls.

[ ] Prototype Pollution via JSON/Object Merging Functions: Targeting vulnerabilities in libraries or custom code that merge JavaScript objects insecurely.

[ ] Prototype Pollution in WebSockets/Event Listeners: Detecting prototype pollution vulnerabilities through WebSocket messages or client-side event listeners.

[ ] Prototype Pollution with CSRF Token Bypass: Exploiting prototype pollution to nullify or manipulate CSRF tokens client-side, enabling CSRF attacks.

B. Advanced Cross-Site Scripting (XSS) & Bypass Techniques
[ ] Mutation XSS (mXSS) in DOM Manipulation: Exploiting mXSS vulnerabilities where the browser re-parses modified DOM elements, leading to XSS after initial sanitization.

[ ] CSP Bypass via JSONP Endpoints: Identifying misconfigured JSONP endpoints that can bypass Content Security Policies.

[ ] CSP Bypass via dangling markup/response header injection: Crafting payloads that leverage incomplete HTML tags or injected headers to bypass CSP.

[ ] Reflected XSS in HTTP Request Headers: Injecting XSS payloads into less common HTTP headers (e.g., User-Agent, Referer, X-Forwarded-For).

[ ] Stored XSS in Markdown/Rich Text Editors (with complex filters): Bypassing sophisticated sanitization filters in modern rich text editors.

[ ] Universal XSS (UXSS) in specific browser versions (if applicable): While rare, identifying browser-specific XSS vulnerabilities.

[ ] XSS via SVG/Image Uploads (embedded scripts): Exploiting image parsing vulnerabilities that allow embedded JavaScript execution within SVG or other image formats.

[ ] XSS via WebSockets (message injection): Injecting and executing XSS payloads through WebSocket communication.

[ ] XSS via Client-Side Template Injection (CSTI): Exploiting client-side template engines for XSS.

[ ] XSS with DOM Clobbering for Sensitive Data Exfiltration: Using DOM Clobbering to steal sensitive data by manipulating form fields or other DOM elements.

[ ] XSS via PostMessage Vulnerabilities (cross-origin): Exploiting insecure postMessage implementations for cross-origin communication vulnerabilities.

[ ] XSS in JavaScript Libraries (known CVEs, often missed): Detecting older versions of JavaScript libraries with known XSS vulnerabilities that might be missed by generic scanners.

C. Client-Side Desync Attacks
[ ] HTTP/2 Desync Attacks: Exploiting nuances in HTTP/2 protocol parsing for desync attacks, leading to request smuggling or cache poisoning.

[ ] HTTP/1.1 to HTTP/2 Downgrade Desync: Detecting vulnerabilities arising from discrepancies when traffic is downgraded between protocols.

[ ] Client-Side HTTP Request Smuggling via "Content-Length" / "Transfer-Encoding" ambiguities: Identifying subtle differences in how proxies/servers interpret HTTP headers leading to request smuggling.

[ ] Web Cache Deception with Authentication Token Leakage: Tricking caching mechanisms to cache sensitive authenticated responses for other users.

[ ] Web Cache Poisoning via Header Injection: Injecting malicious headers to poison web caches, leading to reflected XSS or redirects for other users.

III. Business Logic & Authentication/Authorization Flaws
A. Advanced Authentication & Session Management
[ ] Broken Authentication via Password Reset Logic Flaws (e.g., race conditions, token leakage): Exploiting subtle flaws in password reset mechanisms.

[ ] Authentication Bypass via OAuth/SSO Misconfigurations: Identifying misconfigurations in OAuth2 or OpenID Connect implementations (e.g., improper redirect URIs, weak token validation).

[ ] Session Fixation with Anti-CSRF Token Bypass: Demonstrating session fixation vulnerabilities and how they can be chained with CSRF token bypasses.

[ ] Insecure Session Management via Predictable Session IDs: Detecting weak entropy in session ID generation, allowing for session prediction.

[ ] Multi-Factor Authentication (MFA) Bypass via Backup Codes/Recovery Flows: Exploiting flaws in MFA recovery or backup code mechanisms.

[ ] Horizontal Privilege Escalation with IDOR on User Objects (non-numeric IDs): Exploiting IDORs on user accounts with non-sequential or complex IDs.

[ ] Vertical Privilege Escalation by Role Manipulation (header/cookie): Attempting to elevate privileges by tampering with role-related parameters in HTTP headers or cookies.

[ ] Session Hijacking via Cross-Site Scripting (XSS) with HTTPOnly Bypass (if applicable): If HTTPOnly is not set or bypassed, demonstrate cookie theft.

B. Business Logic Abuse & Race Conditions
[ ] Race Conditions in Financial Transactions: Exploiting race conditions to double spend or gain unauthorized credits.

[ ] Race Conditions in Account Creation/Deletion: Demonstrating how race conditions can lead to account enumeration or unauthorized account creation.

[ ] Business Logic Flaws in Shopping Carts/Pricing: Manipulating pricing, quantities, or discounts via business logic flaws.

[ ] Abuse of "Remember Me" Functionality: Detecting vulnerabilities in persistent login mechanisms, allowing for session replay.

[ ] Workflow Bypass (e.g., skipping payment steps): Identifying ways to bypass intended application workflows.

[ ] Excessive API Calls for Resource Exhaustion (DoS): Generating specific patterns of API calls that lead to resource exhaustion without triggering typical rate limits.

[ ] Brute-Forcing Obscure Login Parameters: Attempting to brute-force less common login parameters (e.g., tenant IDs, client secrets).

[ ] Improper Access Control based on HTTP Method/Content-Type: Exploiting cases where access controls are only applied to specific HTTP methods or content types.

[ ] Logic Bugs in Feature Flags/A/B Testing: Exploiting misconfigurations or flaws in how feature flags are managed, granting unauthorized access to features.

IV. Modern Infrastructure & Supply Chain Attacks
A. Cloud-Native & Container Security
[ ] Exposed Docker API Endpoints: Detecting exposed Docker daemon API endpoints.

[ ] Insecure Kubernetes API Server Exposure: Identifying publicly accessible or weakly authenticated Kubernetes API servers.

[ ] Sensitive Data in Kubernetes ConfigMaps/Secrets (exposed via web): If a web application exposes sensitive data from ConfigMaps or Secrets.

[ ] Container Escape via Web Application (if privileged containers): Though difficult to detect with external scanning, a template could look for indicators of vulnerable container setups.

[ ] Serverless Function (Lambda, Azure Functions) Misconfigurations: Identifying overly permissive serverless function policies or exposed invocation endpoints.

[ ] Cloud Storage Misconfigurations (e.g., S3 bucket misconfigurations with specific policies): Beyond basic open S3 buckets, looking for nuanced policy misconfigurations.

[ ] API Gateway (e.g., AWS API Gateway, Azure API Management) Misconfigurations: Exploiting misconfigured API gateways that expose internal services or bypass authentication.

B. Software Supply Chain Vulnerabilities
[ ] Vulnerable JavaScript Libraries (specific CVEs, not just general checks): Identifying particular versions of widely used JS libraries with known RCE/XSS vulnerabilities.

[ ] Exposed .git or .svn repositories (with sensitive data): Detecting version control repositories accessible via the web, especially if they contain credentials or sensitive config.

[ ] Exposed .env files (with sensitive environment variables): Detecting .env files exposing application secrets.

[ ] Dependency Confusion (Package Managers): While harder to scan externally, a Nuclei template could look for indicators of vulnerable dependency resolution.

[ ] Exposed Source Maps (.map files) revealing original source code: Finding JavaScript source maps that reveal unminified and potentially sensitive source code.

[ ] Compromised CI/CD Artifacts (detectable if served insecurely): If an application serves build artifacts directly that might contain signs of compromise.

[ ] Vulnerable Build Tools/Frameworks (e.g., outdated webpack, npm): Detecting the presence of specific outdated build tools through exposed metadata.

C. Advanced Misconfigurations & Information Leakage
[ ] Verbose Error Messages Revealing Internal System Details (stack traces with specific frameworks): Identifying detailed error messages that disclose technology stack, file paths, or database errors.

[ ] Exposed Debug/Profiling Endpoints (e.g., _profiler, debugbar): Finding debugging tools that expose sensitive application state or configuration.

[ ] Directory Listing with Sensitive Files: Beyond common directory listings, looking for sensitive configurations, backups, or log files.

[ ] Weak SSL/TLS Configurations (outdated protocols, weak ciphers, expired certs): Detecting security misconfigurations in SSL/TLS.

[ ] Exposed Administration Panels with Default Credentials: Finding admin interfaces that use common default usernames and passwords.

[ ] Loose CORS Policies (allowing any origin): Identifying misconfigured Cross-Origin Resource Sharing policies that permit unauthorized cross-domain requests.

[ ] CRLF Injection in HTTP Headers (for response splitting/cache poisoning): Injecting CRLF characters into HTTP headers to manipulate responses.

[ ] Open Redirects for Phishing/SSO Bypass: Detecting open redirect vulnerabilities that can be used for phishing or to bypass SSO mechanisms.

[ ] JWT Misconfigurations (weak secrets, algorithm confusion, no validation): Identifying vulnerabilities in JSON Web Token implementations (e.g., alg:none).

[ ] Web Server Default Pages/Configuration Files (e.g., Apache, Nginx default pages, nginx.conf if exposed): Detecting default server installations or exposed configuration.

[ ] Exposed robots.txt or sitemap.xml revealing sensitive paths: If these files contain paths that should not be publicly accessible.

[ ] Insecure File Uploads (beyond basic executable uploads, e.g., image parsing bypasses): More advanced file upload vulnerabilities that bypass typical sanitization.

V. Advanced Injection Techniques
A. Command Injection & OS Command Injection
[ ] Command Injection in Network Tools (e.g., ping, nslookup functionality): Exploiting web applications that integrate system network utilities.

[ ] Blind Command Injection (via time delays or OOB interactions): Detecting command injection when direct output is not reflected.

[ ] Command Injection via Environmental Variables: Injecting commands by manipulating environment variables.

[ ] Command Injection via Image Processing Libraries (e.g., ImageMagick): Exploiting known vulnerabilities in image processing software.

B. SQL Injection & NoSQL Injection
[ ] Second-Order SQL Injection: Detecting vulnerabilities where injected data is processed later by a different query.

[ ] Time-Based Blind SQL Injection (DBMS-specific delays): Exploiting time-based delays for blind SQL injection, tailored to different database systems.

[ ] NoSQL Injection in MongoDB/Cassandra Query Language: Crafting specific NoSQL injection payloads.

[ ] SQL Injection in HTTP Request Headers (e.g., User-Agent): Injecting SQL payloads into less common HTTP headers.

[ ] Out-of-Band SQL Injection (DNS/HTTP exfiltration): Using OOB techniques to exfiltrate data from SQL injection.

[ ] SQL Injection via XML/JSON Payloads: Exploiting SQL injection through XML or JSON input structures.

C. LDAP/XPath Injection
[ ] LDAP Injection for Authentication Bypass/Information Disclosure: Exploiting applications that use LDAP for authentication or data retrieval.

[ ] Blind LDAP Injection (time-based): Detecting blind LDAP injection vulnerabilities.

[ ] XPath Injection for XML Data Extraction: Exploiting XPath injection to extract data from XML documents.

VI. Niche & Emerging Attack Vectors
A. WebAssembly (Wasm) Security
[ ] Wasm Module Information Leakage: Identifying Wasm modules that expose sensitive internal logic or data.

[ ] Wasm Module Reverse Engineering Indicators: Detecting if a Wasm module is easily de-obfuscated or contains clear function names.

[ ] Wasm Sandbox Escape Potential (if relevant to specific versions): Looking for patterns that could indicate potential sandbox escape vulnerabilities, though actual exploitation would be complex.

B. AI/ML Model Injection (Web-facing components)
[ ] Prompt Injection in Web-Facing AI Chatbots/Generative AI: Crafting specific prompts that manipulate the AI's behavior or extract sensitive data.

[ ] Model Poisoning Indicators (if a web app allows user model uploads): While hard to scan externally, looking for functionalities that might indicate model poisoning risks if not properly validated.

[ ] Side-Channel Information Leakage from AI Model Responses: Analyzing AI responses for subtle clues that might reveal internal model architecture or training data.

[ ] AI-Driven Decision Logic Bypass: Identifying web applications where AI-driven decisions can be influenced or bypassed through specific input patterns.

C. Server-Side Rendering (SSR) & Next.js/Nuxt.js Specifics
[ ] SSR Hydration Mismatch XSS: Exploiting discrepancies between server-rendered and client-side hydrated content for XSS.

[ ] Next.js/Nuxt.js API Route Vulnerabilities: Targeting specific API routes or serverless functions within these frameworks for common vulnerabilities.

[ ] Data Fetching Vulnerabilities in SSR (e.g., getServerSideProps in Next.js revealing sensitive data): Identifying if server-side data fetching functions accidentally expose secrets.

D. Web3 / Blockchain-Enabled Web Apps
[ ] Smart Contract Interaction Vulnerabilities via Web Interface: If the web app interacts with smart contracts, scanning for misconfigurations that could lead to unintended smart contract calls.

[ ] Wallet Connection Phishing (if the web app handles wallet connections insecurely): Detecting scenarios where a malicious actor could trick users into connecting to a fake wallet.

[ ] Decentralized Storage (e.g., IPFS) Misconfigurations: Identifying insecurely exposed or configured decentralized storage through the web app.

VII. Advanced Reconnaissance & Enumeration
A. Fingerprinting & Information Gathering (Deep Dives)
[ ] Deep Framework Version Detection (specific patch levels): Beyond just "React," identifying exact React, Angular, Vue, etc., versions and patch levels to identify known vulnerabilities.

[ ] Backend Language/Framework Version Detection (e.g., specific Python, PHP, Ruby, Node.js versions): Identifying the exact backend versions that might have known vulnerabilities.

[ ] Hidden Parameters/Endpoints Discovery (via wordlists, JS analysis, historical data): Using advanced wordlists and JS analysis to uncover undocumented parameters or endpoints.

[ ] Third-Party Service Fingerprinting (e.g., analytics, CDN, payment gateways): Identifying specific third-party services and checking for common misconfigurations or vulnerabilities associated with them.

[ ] Comment/Metadata Analysis for Sensitive Info: Extracting sensitive information from HTML comments, EXIF data in images, or other metadata.

[ ] Favicon Hashing for Component Identification: Using favicon hashes to identify underlying technologies and versions.

[ ] Error Message Profiling for Infrastructure Guessing: Analyzing different error message responses to infer underlying infrastructure (e.g., specific load balancers, WAFs).

[ ] WAF/CDN Bypass Technique Identification: Identifying common WAFs/CDNs and attempting known bypass techniques.

B. Content Discovery (Beyond Basic)
[ ] Recursive Content Discovery for Subdomains/Subdirectories: Continuously discovering new subdomains and subdirectories based on discovered content.

[ ] JavaScript File Analysis for Endpoint/Parameter Discovery: Parsing JavaScript files for hardcoded API endpoints, parameters, and sensitive strings.

[ ] Wayback Machine/Archive.org Integration for Old Endpoints: Leveraging historical data to find forgotten or deprecated vulnerable endpoints.

[ ] Broken Link Hijacking Opportunities: Identifying broken links to external resources that could be hijacked.

[ ] Virtual Host Discovery (Host header bruteforcing): Enumerating virtual hosts on a single IP address.

[ ] CSS/JS Map File Analysis for Source Code Disclosure: Identifying and parsing source map files to recover original source code.

VIII. Advanced Access Control Bypasses
[ ] Broken Object Level Authorization (BOLA) with Array/Batch Processing: Exploiting BOLA when APIs allow processing of multiple objects in a single request.

[ ] Path Traversal/LFI Bypasses (encoding, null bytes, double encoding): Advanced techniques to bypass path traversal filters.

[ ] Authentication Bypass with HTTP Smuggling (Content-Length/Transfer-Encoding desync): Using HTTP request smuggling to bypass authentication or access controls.

[ ] Authorization Bypass via Referer/Origin Header Manipulation: Attempting to bypass authorization checks by modifying Referer or Origin headers.

[ ] Insecure Direct Object Reference (IDOR) on Non-Numeric IDs: Exploiting IDORs on UUIDs, hashes, or other non-sequential identifiers if their generation or validation is flawed.

[ ] Broken Authentication by Insecure JWT Token Management: Exploiting issues like weak secrets, algorithm confusion, or lack of signature verification in JWTs.

[ ] Horizontal Privilege Escalation with Session Token Swapping: Attempting to swap session tokens between different user types to gain unauthorized access.

[ ] Vertical Privilege Escalation via Parameter Tampering (e.g., isAdmin=true): Exploiting simple parameter manipulation to gain administrative access.

[ ] Access Control Bypass via HTTP Method Override Headers (e.g., X-HTTP-Method-Override): Using these headers to bypass method-based access controls.

IX. Unique Attack Surface & Specific Technologies
[ ] WebRTC Security Vulnerabilities (e.g., IP disclosure, denial of service): If the web app uses WebRTC, looking for exposed IPs or other vulnerabilities.

[ ] WebSocket Protocol Injection (e.g., XSS over WebSockets, command injection): Injecting malicious data into WebSocket communication.

[ ] Server-Sent Events (SSE) Injection: Exploiting applications that use Server-Sent Events for injection.

[ ] Web Push API Abuse (e.g., sending malicious notifications): If the application uses Web Push, checking for vulnerabilities allowing unauthorized notification sending.

[ ] Web Component Shadow DOM XSS (if applicable): Exploiting XSS in the Shadow DOM for complex web components.

[ ] Service Worker Hijacking/Bypass: Exploiting misconfigured or vulnerable service workers to intercept requests or deliver malicious content.

[ ] GraphQL Subscriptions for Information Disclosure: Exploiting GraphQL subscriptions to receive unauthorized sensitive data.

[ ] gRPC-Web Protocol Vulnerabilities: If the web app uses gRPC-Web, looking for specific protocol-level vulnerabilities.

[ ] Web Transport API Misuse/Vulnerabilities: If leveraging Web Transport, checking for misuse or flaws.

[ ] Web Worker Security Vulnerabilities: Exploiting security flaws in web workers that could lead to XSS or data leakage.

[ ] WebAssembly Component Model Security (emerging): As the component model evolves, looking for vulnerabilities in its implementation.

[ ] Cross-Origin Resource Sharing (CORS) with Credential Abuse: If CORS is too permissive and allows credentials, this could lead to data theft.

[ ] DNS Rebinding Attacks (Client-Side): Exploiting DNS rebinding for client-side attacks (e.g., same-origin policy bypass).

[ ] OAuth Implicit Grant Flow Vulnerabilities (redirect URI manipulation): Exploiting insecure implementations of the OAuth implicit grant flow.

[ ] CORS Misconfigurations on Subdomains: Identifying permissive CORS policies on less obvious subdomains.

[ ] Host Header Injection (Web Cache Poisoning, Password Reset Poisoning): Exploiting host header vulnerabilities for various attacks.

[ ] Clickjacking (specific UI elements, with complex overlays): Crafting sophisticated clickjacking attacks that target specific UI elements.

[ ] HTML/CSS Injection (for defacement or partial XSS): Injecting HTML/CSS to alter the page appearance or enable partial XSS.

[ ] Insecure Client-Side Storage (Local Storage, Session Storage, IndexedDB): Identifying sensitive data stored insecurely client-side.

X. Advanced Logic & Behavioral Analysis
[ ] CAPTCHA Bypass (via logical flaws, outdated versions, or OCR): Developing Nuclei templates that can identify and potentially bypass CAPTCHAs.

[ ] Anti-Bot Mechanism Bypasses (via header manipulation, specific user agents): Identifying and bypassing common anti-bot techniques.

[ ] Account Enumeration (via subtle error messages or timing attacks): Identifying valid usernames/emails without brute-forcing passwords.

[ ] Username Enumeration via Password Reset or Registration Forms (time-based): Detecting if a username exists based on timing differences in responses.

[ ] Session Token Prediction/Brute-Forcing: Attempting to guess or brute-force weak session tokens.

[ ] CSRF on JSON Endpoints without Content-Type checks: Exploiting CSRF on JSON endpoints that don't properly validate the Content-Type header.

[ ] Missing SameSite Cookie Attribute (for CSRF): Identifying cookies without the SameSite attribute, making them vulnerable to CSRF in some contexts.

[ ] Race Condition for Unauthorized Access to Sensitive Files/Functions: Exploiting race conditions to briefly gain access before authorization kicks in.

[ ] Referer Leakage of Sensitive Information: Identifying cases where the Referer header leaks sensitive data to third-party sites.

[ ] Sensitive Information in JavaScript Console Logs: Detecting if the application logs sensitive data to the browser's developer console.

[ ] Client-Side Certificate Bypass (if applicable to specific applications): If an application relies on client-side certificates, looking for ways to bypass their validation.

[ ] User Agent String Spoofing for Feature/Access Bypass: Testing if certain user agent strings grant different levels of access or features.

[ ] Timing Attacks on Authentication/Authorization: Detecting subtle timing differences in responses that reveal information about credentials or permissions.

[ ] Insecure Cross-Origin Communication (window.opener vulnerabilities): Exploiting window.opener vulnerabilities for cross-origin attacks.

[ ] Missing Security Headers (e.g., Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options): While basic, demonstrating a thorough check for these.

[ ] Credential Stuffing/Account Takeover via Weak Password Policies: Identifying applications with weak password policies that make credential stuffing easier.

[ ] HTTP Parameter Pollution with Filter Bypass: Using HPP to bypass input validation or WAF rules.

[ ] Response Smuggling with Client-Side Effects: Manipulating HTTP responses to cause client-side effects (e.g., XSS, cache poisoning).
