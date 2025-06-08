🚀 Next-Gen Server-Side Vulnerabilities & Bypass Techniques
This document offers a comprehensive checklist of advanced server-side and client-side vulnerabilities, emerging attack vectors, and sophisticated bypass techniques relevant to modern web applications. Whether you're a red teamer, a security researcher, or a developer aiming to build more resilient applications, this list covers critical areas often overlooked.

When viewed on GitHub, these items will display as interactive checkboxes. You can click them directly within the GitHub interface (e.g., when editing a README or in a pull request description) to mark them as done.

I. Next-Gen Server-Side Vulnerabilities & Bypass Techniques



A. Advanced Server-Side Request Forgery (SSRF) & Internal Network Exposure
[ ] SSRF with Multi-Level Redirection Bypasses: Exploiting SSRF vulnerabilities by meticulously following and analyzing multiple HTTP redirects (e.g., 302 -> 301 -> 307) to reach internal services, effectively bypassing simple redirect filters.

[ ] SSRF via DNS Rebinding: Leveraging DNS rebinding techniques to circumvent IP-based SSRF filters, demonstrating access to restricted internal IPs and services.

[ ] SSRF to Cloud Metadata Endpoints (obscure paths): Targeting less common cloud metadata endpoints (e.g., Azure, GCP, Alibaba Cloud) beyond the widely known AWS 169.254.169.254, identifying sensitive cloud configuration and credentials.

[ ] SSRF to Internal K8s API Servers: Detecting unauthorized access to Kubernetes API servers (e.g., /api/v1/namespaces/kube-system/secrets) for potential cluster compromise and data exfiltration.

[ ] SSRF with URL Scheme Confusion: Leveraging unusual URL schemes like dict://, gopher://, file:// to access internal resources or execute arbitrary code on the backend, bypassing typical URL validation.

[ ] SSRF to Internal NoSQL Databases (e.g., MongoDB, Redis): Probing for default NoSQL ports and identifying exposed instances that could lead to data exfiltration or manipulation within the internal network.

[ ] SSRF to Internal Message Queues (e.g., RabbitMQ, Kafka): Identifying and probing for administrative interfaces or exposed queues that might contain sensitive data or allow for message manipulation.

[ ] SSRF to Internal Monitoring/Telemetry Services (e.g., Prometheus, Grafana): Discovering and accessing sensitive internal metrics or dashboards often running on internal networks, revealing system health and confidential information.

[ ] SSRF with HTTP Parameter Pollution (HPP) in Query/Body: Crafting requests that exploit HPP to manipulate internal SSRF logic and bypass filters, leading to unexpected backend behavior.

[ ] SSRF to Internal Git Repositories: Attempting to access hidden .git directories or internal Git servers via SSRF for source code disclosure and potential sensitive information leakage.

[ ] SSRF with Authentication Bypass (e.g., default creds): Identifying internal services that use common default credentials accessible via SSRF, allowing unauthorized access.

[ ] SSRF with Host Header Forgery: Manipulating the Host header in conjunction with SSRF to target specific internal services or bypass Web Application Firewalls (WAFs).

[ ] SSRF via Image/File Upload Processors: Exploiting vulnerabilities in image or file processing libraries that fetch external resources, leading to SSRF and potentially arbitrary file read.

[ ] SSRF via PDF/Document Converters: Detecting SSRF opportunities in services that convert URLs to PDF or other document formats, which might fetch internal URLs.

[ ] SSRF through Server-Side Template Engines (SSTI) with External Resource Loading: Chaining SSTI with external resource loading capabilities to achieve SSRF and read sensitive files from the server.

B. Advanced Template Injection (SSTI) & Deserialization
[ ] SSTI in Obscure Template Engines: Beyond common engines like Jinja2 or Twig, targeting less popular or custom template engines that often lack robust sanitization, leading to RCE.

[ ] SSTI with Gadget Chain Discovery (Java/Python): Identifying specific "gadgets" in an application's dependencies that, when combined with SSTI or deserialization, can lead to Remote Code Execution (RCE).

[ ] SSTI with Sandbox Escapes (specific versions): Exploiting known sandbox bypasses in older or misconfigured template engine versions to gain RCE, even within supposed secure environments.

[ ] SSTI via XML External Entity (XXE) to Local File Read: Combining SSTI with XXE for sophisticated local file read vulnerabilities, allowing access to arbitrary files on the server.

[ ] Deserialization Vulnerabilities in Less Common Formats: Beyond Java/PHP, focusing on Python Pickle, .NET, or Ruby YAML deserialization, which are often missed by generic scanners and can lead to RCE.

[ ] Deserialization with Custom Object Injection: Identifying and exploiting custom classes that are deserialized insecurely, leading to RCE or other severe impacts like data corruption.

[ ] SSTI/Deserialization in CI/CD Webhooks: Targeting webhooks used for CI/CD pipelines that might be vulnerable to injection, potentially leading to build system compromise and supply chain attacks.

[ ] SSTI in Email Template Rendering Services: Exploiting vulnerabilities in services that generate dynamic email content, leading to internal data exposure, spam, or even XSS.

C. Emerging API Security Flaws (beyond OWASP API Top 10)
[ ] Excessive Data Exposure via GraphQL Type Introspection (with filtering bypasses): Crafting specific GraphQL queries that reveal more than intended, even with basic filtering, by understanding the schema's deeper relationships.

[ ] GraphQL Query Complexity Attacks (Denial of Service): Generating overly complex or deeply nested GraphQL queries designed to trigger DoS by overwhelming server resources, leading to service unavailability.

[ ] GraphQL Batching Abuse for Rate Limit Bypass: Exploiting GraphQL's batching feature to circumvent rate limiting on individual API calls, enabling brute-force or resource exhaustion attacks.

[ ] Broken Function Level Authorization (BFLA) in Microservices/Internal APIs: Identifying granular authorization flaws when different services communicate internally, often exposing unintended functionality to unauthorized users.

[ ] Mass Assignment/Parameter Tampering in API Endpoints (nested objects): Exploiting vulnerabilities where attackers can inject or overwrite unexpected parameters, especially within complex nested JSON/object structures, leading to data manipulation or privilege escalation.

[ ] API Rate Limiting Bypasses (e.g., via IP rotation, header manipulation): Crafting requests that circumvent typical rate limiting mechanisms, enabling brute-force attacks or resource exhaustion.

[ ] Unauthenticated/Weakly Authenticated Internal API Exposure: Discovering internal-only APIs that are exposed to the internet or have weak authentication, providing direct access to backend services and sensitive data.

[ ] API Security Misconfigurations (e.g., verbose error messages, exposed debug endpoints): Identifying endpoints that reveal sensitive information (stack traces, internal IP addresses) or debugging interfaces that should not be publicly accessible.

[ ] API Key Reuse/Hardcoded Keys in Client-Side Code: Detecting hardcoded API keys in JavaScript or client-side bundles that could be abused for unauthorized API access or resource consumption.

[ ] API-Specific Injection Flaws (e.g., NoSQL Injection in API parameters): Beyond traditional SQL injection, targeting NoSQL databases via API inputs with specially crafted payloads.

[ ] Insecure Direct Object Reference (IDOR) with Encoding/Hashing Bypasses: Exploiting IDORs where object IDs are encoded or hashed, but the scheme is guessable or breakable, leading to unauthorized data access.

[ ] Client-Side API Key Exploitation (e.g., Google Maps API key abuse): Identifying exposed API keys and demonstrating potential abuse (e.g., excessive usage, sensitive data access) via client-side manipulation.

[ ] GraphQL Schema Stitching Vulnerabilities: Identifying vulnerabilities where stitching multiple GraphQL schemas introduces new attack surfaces or information disclosure due to unexpected interactions.

[ ] API Gateway Misconfigurations (e.g., improper routing, unauthorized access): Exploiting misconfigurations in API gateways that lead to bypassing security controls, routing to internal services, or unauthorized access to APIs.

D. Advanced XXE (XML External Entity)
[ ] XXE to Remote Code Execution (via JAR/PHAR deserialization): Chaining XXE with deserialization gadgets for RCE, a highly critical impact.

[ ] XXE with Out-of-Band (OOB) Data Exfiltration (DNS/HTTP): Using OOB techniques to exfiltrate sensitive data via XXE, even when direct output is not reflected.

[ ] XXE in Non-XML Parsers (e.g., certain image parsers, document processors): Identifying XXE in unexpected file formats or processing stages that internally use XML parsers.

[ ] XXE via DTD File Upload: Exploiting applications that allow DTD file uploads to trigger XXE, leading to local file read or SSRF.

[ ] XXE with Blind Out-of-Band Interaction: Detecting blind XXE vulnerabilities through delayed OOB interactions (e.g., DNS lookups), confirming the vulnerability without direct response.

E. Modern SSRF & Internal Service Interaction
[ ] SSRF to internal database connections strings (e.g., jdbc:mysql://): Identifying if error messages or verbose responses disclose internal database connection strings via SSRF, aiding further attacks.

[ ] SSRF via data: URI scheme to bypass WAFs: Using data: URIs to smuggle content past WAFs or content filters, allowing internal resource access.

[ ] SSRF to identify and interact with internal container registries: Probing for exposed Docker registries or other container image repositories within the internal network.

[ ] SSRF to access internal environment variables via file paths: Attempting to read /proc/self/environ or similar sensitive paths via SSRF, exposing sensitive configuration.

[ ] SSRF to internal message bus systems (e.g., Kafka, RabbitMQ APIs): Interacting with internal messaging systems for data exfiltration, message manipulation, or triggering internal business logic.

[ ] SSRF to internal cloud service control planes (e.g., private APIs for AWS, GCP, Azure management): Exploiting lesser-known internal control plane APIs accessible via SSRF, potentially leading to cloud resource manipulation.

II. Sophisticated Client-Side Attacks
A. Prototype Pollution & XSS Gadget Chaining
[ ] Client-Side Prototype Pollution via URL Hash/Query Parameters: Detecting prototype pollution vulnerabilities introduced by processing URL parameters, which can affect global JavaScript objects.

[ ] Prototype Pollution to XSS Gadget Chaining (Framework-Specific): Identifying and exploiting known gadget chains in popular JavaScript frameworks (React, Angular, Vue) to achieve XSS via prototype pollution.

[ ] Prototype Pollution leading to DOM Clobbering for XSS/Bypass: Exploiting prototype pollution to perform DOM clobbering attacks to manipulate page content or bypass security controls (e.g., XSS filters).

[ ] Prototype Pollution via JSON/Object Merging Functions: Targeting vulnerabilities in libraries or custom code that merge JavaScript objects insecurely, leading to prototype pollution.

[ ] Prototype Pollution in WebSockets/Event Listeners: Detecting prototype pollution vulnerabilities through WebSocket messages or client-side event listeners that process untrusted data.

[ ] Prototype Pollution with CSRF Token Bypass: Exploiting prototype pollution to nullify or manipulate CSRF tokens client-side, enabling CSRF attacks against authenticated users.

B. Advanced Cross-Site Scripting (XSS) & Bypass Techniques
[ ] Mutation XSS (mXSS) in DOM Manipulation: Exploiting mXSS vulnerabilities where the browser re-parses modified DOM elements, leading to XSS after initial sanitization attempts.

[ ] CSP Bypass via JSONP Endpoints: Identifying misconfigured JSONP endpoints that can bypass Content Security Policies (CSP), allowing unauthorized script execution.

[ ] CSP Bypass via dangling markup/response header injection: Crafting payloads that leverage incomplete HTML tags or injected headers to bypass CSP restrictions.

[ ] Reflected XSS in HTTP Request Headers: Injecting XSS payloads into less common HTTP headers (e.g., User-Agent, Referer, X-Forwarded-For), which might be reflected insecurely.

[ ] Stored XSS in Markdown/Rich Text Editors (with complex filters): Bypassing sophisticated sanitization filters in modern rich text editors by crafting complex payloads.

[ ] Universal XSS (UXSS) in specific browser versions (if applicable): While rare, identifying browser-specific XSS vulnerabilities that can affect all websites visited by a vulnerable browser.

[ ] XSS via SVG/Image Uploads (embedded scripts): Exploiting image parsing vulnerabilities that allow embedded JavaScript execution within SVG or other image formats.

[ ] XSS via WebSockets (message injection): Injecting and executing XSS payloads through WebSocket communication, leading to persistent or reflected XSS.

[ ] XSS via Client-Side Template Injection (CSTI): Exploiting client-side template engines for XSS by injecting malicious templates that execute JavaScript.

[ ] XSS with DOM Clobbering for Sensitive Data Exfiltration: Using DOM Clobbering in conjunction with XSS to steal sensitive data by manipulating form fields or other DOM elements.

[ ] XSS via PostMessage Vulnerabilities (cross-origin): Exploiting insecure postMessage implementations for cross-origin communication vulnerabilities, leading to data theft or XSS.

[ ] XSS in JavaScript Libraries (known CVEs, often missed): Detecting older versions of JavaScript libraries with known XSS vulnerabilities that might be missed by generic scanners.

C. Client-Side Desync Attacks
[ ] HTTP/2 Desync Attacks: Exploiting nuances in HTTP/2 protocol parsing for desync attacks, leading to request smuggling or cache poisoning.

[ ] HTTP/1.1 to HTTP/2 Downgrade Desync: Detecting vulnerabilities arising from discrepancies when traffic is downgraded between protocols, enabling request smuggling.

[ ] Client-Side HTTP Request Smuggling via "Content-Length" / "Transfer-Encoding" ambiguities: Identifying subtle differences in how proxies/servers interpret HTTP headers leading to request smuggling and cache poisoning.

[ ] Web Cache Deception with Authentication Token Leakage: Tricking caching mechanisms to cache sensitive authenticated responses for other users, leading to token leakage.

[ ] Web Cache Poisoning via Header Injection: Injecting malicious headers to poison web caches, leading to reflected XSS or redirects for other users.

III. Business Logic & Authentication/Authorization Flaws
A. Advanced Authentication & Session Management
[ ] Broken Authentication via Password Reset Logic Flaws (e.g., race conditions, token leakage): Exploiting subtle flaws in password reset mechanisms, such as race conditions or predictable token generation.

[ ] Authentication Bypass via OAuth/SSO Misconfigurations: Identifying misconfigurations in OAuth2 or OpenID Connect implementations (e.g., improper redirect URIs, weak token validation) leading to bypass.

[ ] Session Fixation with Anti-CSRF Token Bypass: Demonstrating session fixation vulnerabilities and how they can be chained with CSRF token bypasses for complete session hijacking.

[ ] Insecure Session Management via Predictable Session IDs: Detecting weak entropy in session ID generation, allowing for session prediction and unauthorized access.

[ ] Multi-Factor Authentication (MFA) Bypass via Backup Codes/Recovery Flows: Exploiting flaws in MFA recovery or backup code mechanisms to bypass the second factor.

[ ] Horizontal Privilege Escalation with IDOR on User Objects (non-numeric IDs): Exploiting IDORs on user accounts with non-sequential or complex IDs, allowing access to other users' data.

[ ] Vertical Privilege Escalation by Role Manipulation (header/cookie): Attempting to elevate privileges by tampering with role-related parameters in HTTP headers or cookies to gain administrative access.

[ ] Session Hijacking via Cross-Site Scripting (XSS) with HTTPOnly Bypass (if applicable): If HTTPOnly is not set or bypassed, demonstrating cookie theft via XSS, leading to session hijacking.

B. Business Logic Abuse & Race Conditions
[ ] Race Conditions in Financial Transactions: Exploiting race conditions to double spend or gain unauthorized credits by submitting multiple requests simultaneously.

[ ] Race Conditions in Account Creation/Deletion: Demonstrating how race conditions can lead to account enumeration, unauthorized account creation, or deletion.

[ ] Business Logic Flaws in Shopping Carts/Pricing: Manipulating pricing, quantities, or discounts via business logic flaws to purchase items at an unintended price.

[ ] Abuse of "Remember Me" Functionality: Detecting vulnerabilities in persistent login mechanisms, allowing for session replay or extended unauthorized access.

[ ] Workflow Bypass (e.g., skipping payment steps): Identifying ways to bypass intended application workflows, such as skipping payment steps in an e-commerce application.

[ ] Excessive API Calls for Resource Exhaustion (DoS): Generating specific patterns of API calls that lead to resource exhaustion without triggering typical rate limits, causing Denial of Service.

[ ] Brute-Forcing Obscure Login Parameters: Attempting to brute-force less common login parameters (e.g., tenant IDs, client secrets) that are not typically protected by strong rate limits.

[ ] Improper Access Control based on HTTP Method/Content-Type: Exploiting cases where access controls are only applied to specific HTTP methods or content types, allowing bypass.

[ ] Logic Bugs in Feature Flags/A/B Testing: Exploiting misconfigurations or flaws in how feature flags are managed, granting unauthorized access to features or content.

IV. Modern Infrastructure & Supply Chain Attacks
A. Cloud-Native & Container Security
[ ] Exposed Docker API Endpoints: Detecting publicly exposed Docker daemon API endpoints, which can lead to container escape and host compromise.

[ ] Insecure Kubernetes API Server Exposure: Identifying publicly accessible or weakly authenticated Kubernetes API servers, allowing cluster manipulation.

[ ] Sensitive Data in Kubernetes ConfigMaps/Secrets (exposed via web): If a web application exposes sensitive data from ConfigMaps or Secrets, leading to information disclosure.

[ ] Container Escape via Web Application (if privileged containers): Though difficult to detect with external scanning, a template could look for indicators of vulnerable container setups that allow escape.

[ ] Serverless Function (Lambda, Azure Functions) Misconfigurations: Identifying overly permissive serverless function policies or exposed invocation endpoints, leading to unauthorized function execution.

[ ] Cloud Storage Misconfigurations (e.g., S3 bucket misconfigurations with specific policies): Beyond basic open S3 buckets, looking for nuanced policy misconfigurations that allow unintended access.

[ ] API Gateway (e.g., AWS API Gateway, Azure API Management) Misconfigurations: Exploiting misconfigured API gateways that expose internal services, bypass authentication, or allow unauthorized routing.

B. Software Supply Chain Vulnerabilities
[ ] Vulnerable JavaScript Libraries (specific CVEs, not just general checks): Identifying particular versions of widely used JS libraries with known RCE/XSS vulnerabilities that can be exploited client-side.

[ ] Exposed .git or .svn repositories (with sensitive data): Detecting version control repositories accessible via the web, especially if they contain credentials or sensitive configuration files.

[ ] Exposed .env files (with sensitive environment variables): Detecting .env files exposing application secrets, database credentials, or API keys.

[ ] Dependency Confusion (Package Managers): While harder to scan externally, a Nuclei template could look for indicators of vulnerable dependency resolution, leading to arbitrary code execution.

[ ] Exposed Source Maps (.map files) revealing original source code: Finding JavaScript source maps that reveal unminified and potentially sensitive source code, aiding in vulnerability discovery.

[ ] Compromised CI/CD Artifacts (detectable if served insecurely): If an application serves build artifacts directly that might contain signs of compromise or sensitive information.

[ ] Vulnerable Build Tools/Frameworks (e.g., outdated webpack, npm): Detecting the presence of specific outdated build tools through exposed metadata, which might have known vulnerabilities.

C. Advanced Misconfigurations & Information Leakage
[ ] Verbose Error Messages Revealing Internal System Details (stack traces with specific frameworks): Identifying detailed error messages that disclose technology stack, file paths, or database errors, aiding attackers in reconnaissance.

[ ] Exposed Debug/Profiling Endpoints (e.g., _profiler, debugbar): Finding debugging or profiling tools that expose sensitive application state or configuration, which should not be publicly accessible.

[ ] Directory Listing with Sensitive Files: Beyond common directory listings, looking for sensitive configurations, backups, or log files exposed through directory listings.

[ ] Weak SSL/TLS Configurations (outdated protocols, weak ciphers, expired certs): Detecting security misconfigurations in SSL/TLS (e.g., SSLv3, weak ciphers), making communication vulnerable to eavesdropping.

[ ] Exposed Administration Panels with Default Credentials: Finding admin interfaces that use common default usernames and passwords, leading to easy compromise.

[ ] Loose CORS Policies (allowing any origin): Identifying misconfigured Cross-Origin Resource Sharing policies that permit unauthorized cross-domain requests, leading to data theft.

[ ] CRLF Injection in HTTP Headers (for response splitting/cache poisoning): Injecting CRLF characters into HTTP headers to manipulate responses, leading to response splitting or cache poisoning.

[ ] Open Redirects for Phishing/SSO Bypass: Detecting open redirect vulnerabilities that can be used for phishing attacks or to bypass Single Sign-On (SSO) mechanisms.

[ ] JWT Misconfigurations (weak secrets, algorithm confusion, no validation): Identifying vulnerabilities in JSON Web Token implementations (e.g., alg:none attacks, weak secrets) leading to authentication bypass.

[ ] Web Server Default Pages/Configuration Files (e.g., Apache, Nginx default pages, nginx.conf if exposed): Detecting default server installations or exposed configuration files, which often contain sensitive information.

[ ] Exposed robots.txt or sitemap.xml revealing sensitive paths: If these files contain paths that should not be publicly accessible, potentially exposing hidden endpoints.

[ ] Insecure File Uploads (beyond basic executable uploads, e.g., image parsing bypasses): More advanced file upload vulnerabilities that bypass typical sanitization, allowing arbitrary file upload and execution.

V. Advanced Injection Techniques
A. Command Injection & OS Command Injection
[ ] Command Injection in Network Tools (e.g., ping, nslookup functionality): Exploiting web applications that integrate system network utilities (ping, nslookup), allowing OS command execution.

[ ] Blind Command Injection (via time delays or OOB interactions): Detecting command injection when direct output is not reflected, relying on time-based delays or out-of-band interactions.

[ ] Command Injection via Environmental Variables: Injecting commands by manipulating environment variables passed to executed commands.

[ ] Command Injection via Image Processing Libraries (e.g., ImageMagick): Exploiting known vulnerabilities in image processing software that can lead to command injection upon image upload.

B. SQL Injection & NoSQL Injection
[ ] Second-Order SQL Injection: Detecting vulnerabilities where injected data is processed later by a different query, making it harder to detect.

[ ] Time-Based Blind SQL Injection (DBMS-specific delays): Exploiting time-based delays for blind SQL injection, tailored to different database systems (e.g., MySQL, PostgreSQL, MSSQL).

[ ] NoSQL Injection in MongoDB/Cassandra Query Language: Crafting specific NoSQL injection payloads that manipulate queries in MongoDB, Cassandra, or other NoSQL databases.

[ ] SQL Injection in HTTP Request Headers (e.g., User-Agent): Injecting SQL payloads into less common HTTP headers (e.g., User-Agent, Referer) that are used in database queries.

[ ] Out-of-Band SQL Injection (DNS/HTTP exfiltration): Using OOB techniques (e.g., DNS lookups, HTTP requests) to exfiltrate data from SQL injection when direct output is not possible.

[ ] SQL Injection via XML/JSON Payloads: Exploiting SQL injection through XML or JSON input structures when the application processes these formats for database queries.

C. LDAP/XPath Injection
[ ] LDAP Injection for Authentication Bypass/Information Disclosure: Exploiting applications that use LDAP for authentication or data retrieval, allowing for authentication bypass or directory enumeration.

[ ] Blind LDAP Injection (time-based): Detecting blind LDAP injection vulnerabilities through time-based delays when direct output is not reflected.

[ ] XPath Injection for XML Data Extraction: Exploiting XPath injection to extract data from XML documents, potentially revealing sensitive information.

VI. Niche & Emerging Attack Vectors
A. WebAssembly (Wasm) Security
[ ] Wasm Module Information Leakage: Identifying Wasm modules that expose sensitive internal logic or data, which can be reverse-engineered.

[ ] Wasm Module Reverse Engineering Indicators: Detecting if a Wasm module is easily de-obfuscated or contains clear function names, making it easier for attackers to understand its logic.

[ ] Wasm Sandbox Escape Potential (if relevant to specific versions): Looking for patterns that could indicate potential sandbox escape vulnerabilities in Wasm runtimes, though actual exploitation would be complex.

B. AI/ML Model Injection (Web-facing components)
[ ] Prompt Injection in Web-Facing AI Chatbots/Generative AI: Crafting specific prompts that manipulate the AI's behavior, extract sensitive data from its training set, or make it generate malicious content.

[ ] Model Poisoning Indicators (if a web app allows user model uploads): While hard to scan externally, looking for functionalities that might indicate model poisoning risks if not properly validated.

[ ] Side-Channel Information Leakage from AI Model Responses: Analyzing AI responses for subtle clues that might reveal internal model architecture or training data, leading to intellectual property theft.

[ ] AI-Driven Decision Logic Bypass: Identifying web applications where AI-driven decisions (e.g., fraud detection, content moderation) can be influenced or bypassed through specific input patterns.

C. Server-Side Rendering (SSR) & Next.js/Nuxt.js Specifics
[ ] SSR Hydration Mismatch XSS: Exploiting discrepancies between server-rendered and client-side hydrated content for XSS, due to differences in parsing or sanitization.

[ ] Next.js/Nuxt.js API Route Vulnerabilities: Targeting specific API routes or serverless functions within these frameworks for common vulnerabilities like injection or improper access control.

[ ] Data Fetching Vulnerabilities in SSR (e.g., getServerSideProps in Next.js revealing sensitive data): Identifying if server-side data fetching functions accidentally expose secrets, database queries, or internal logic.

D. Web3 / Blockchain-Enabled Web Apps
[ ] Smart Contract Interaction Vulnerabilities via Web Interface: If the web app interacts with smart contracts, scanning for misconfigurations that could lead to unintended smart contract calls or token drainage.

[ ] Wallet Connection Phishing (if the web app handles wallet connections insecurely): Detecting scenarios where a malicious actor could trick users into connecting to a fake wallet or authorizing malicious transactions.

[ ] Decentralized Storage (e.g., IPFS) Misconfigurations: Identifying insecurely exposed or configured decentralized storage through the web app, leading to data exposure or manipulation.

VII. Advanced Reconnaissance & Enumeration
A. Fingerprinting & Information Gathering (Deep Dives)
[ ] Deep Framework Version Detection (specific patch levels): Beyond just "React," identifying exact React, Angular, Vue, etc., versions and patch levels to identify known vulnerabilities.

[ ] Backend Language/Framework Version Detection (e.g., specific Python, PHP, Ruby, Node.js versions): Identifying the exact backend versions that might have known vulnerabilities, aiding in targeted exploits.

[ ] Hidden Parameters/Endpoints Discovery (via wordlists, JS analysis, historical data): Using advanced wordlists and JavaScript analysis to uncover undocumented parameters or endpoints.

[ ] Third-Party Service Fingerprinting (e.g., analytics, CDN, payment gateways): Identifying specific third-party services and checking for common misconfigurations or vulnerabilities associated with them.

[ ] Comment/Metadata Analysis for Sensitive Info: Extracting sensitive information from HTML comments, EXIF data in images, or other metadata embedded in publicly accessible files.

[ ] Favicon Hashing for Component Identification: Using favicon hashes to identify underlying technologies and versions, aiding in rapid component identification.

[ ] Error Message Profiling for Infrastructure Guessing: Analyzing different error message responses to infer underlying infrastructure (e.g., specific load balancers, WAFs, databases).

[ ] WAF/CDN Bypass Technique Identification: Identifying common WAFs/CDNs and attempting known bypass techniques to circumvent security controls.

B. Content Discovery (Beyond Basic)
[ ] Recursive Content Discovery for Subdomains/Subdirectories: Continuously discovering new subdomains and subdirectories based on discovered content and common naming conventions.

[ ] JavaScript File Analysis for Endpoint/Parameter Discovery: Parsing JavaScript files for hardcoded API endpoints, parameters, and sensitive strings that might reveal hidden functionality.

[ ] Wayback Machine/Archive.org Integration for Old Endpoints: Leveraging historical data from web archives to find forgotten or deprecated vulnerable endpoints that are still active.

[ ] Broken Link Hijacking Opportunities: Identifying broken links to external resources that could be hijacked to serve malicious content or phishing pages.

[ ] Virtual Host Discovery (Host header bruteforcing): Enumerating virtual hosts on a single IP address by bruteforcing Host headers.

[ ] CSS/JS Map File Analysis for Source Code Disclosure: Identifying and parsing source map files to recover original source code, revealing internal logic and potential vulnerabilities.

VIII. Advanced Access Control Bypasses
[ ] Broken Object Level Authorization (BOLA) with Array/Batch Processing: Exploiting BOLA when APIs allow processing of multiple objects in a single request, enabling unauthorized access to multiple resources.

[ ] Path Traversal/LFI Bypasses (encoding, null bytes, double encoding): Advanced techniques to bypass path traversal filters, such as using various encoding schemes, null bytes, or double encoding.

[ ] Authentication Bypass with HTTP Smuggling (Content-Length/Transfer-Encoding desync): Using HTTP request smuggling to bypass authentication or access controls by manipulating how proxies/servers interpret requests.

[ ] Authorization Bypass via Referer/Origin Header Manipulation: Attempting to bypass authorization checks by modifying Referer or Origin headers, tricking the application into granting access.

[ ] Insecure Direct Object Reference (IDOR) on Non-Numeric IDs: Exploiting IDORs on UUIDs, hashes, or other non-sequential identifiers if their generation or validation is flawed.

[ ] Broken Authentication by Insecure JWT Token Management: Exploiting issues like weak secrets, algorithm confusion (alg:none), or lack of signature verification in JWTs, leading to authentication bypass.

[ ] Horizontal Privilege Escalation with Session Token Swapping: Attempting to swap session tokens between different user types to gain unauthorized access to another user's account.

[ ] Vertical Privilege Escalation via Parameter Tampering (e.g., isAdmin=true): Exploiting simple parameter manipulation (e.g., changing a boolean flag) to gain administrative access.

[ ] Access Control Bypass via HTTP Method Override Headers (e.g., X-HTTP-Method-Override): Using these headers to bypass method-based access controls, for example, changing a GET request to a POST to access a restricted endpoint.

IX. Unique Attack Surface & Specific Technologies
[ ] WebRTC Security Vulnerabilities (e.g., IP disclosure, denial of service): If the web app uses WebRTC, looking for exposed IPs, internal network scanning, or denial-of-service opportunities.

[ ] WebSocket Protocol Injection (e.g., XSS over WebSockets, command injection): Injecting malicious data into WebSocket communication, leading to XSS, command injection, or other impacts.

[ ] Server-Sent Events (SSE) Injection: Exploiting applications that use Server-Sent Events for injection, leading to XSS or data leakage.

[ ] Web Push API Abuse (e.g., sending malicious notifications): If the application uses Web Push, checking for vulnerabilities allowing unauthorized notification sending to users.

[ ] Web Component Shadow DOM XSS (if applicable): Exploiting XSS in the Shadow DOM for complex web components, bypassing traditional DOM-based XSS detection.

[ ] Service Worker Hijacking/Bypass: Exploiting misconfigured or vulnerable service workers to intercept requests, deliver malicious content, or gain offline access.

[ ] GraphQL Subscriptions for Information Disclosure: Exploiting GraphQL subscriptions to receive unauthorized sensitive data in real-time.

[ ] gRPC-Web Protocol Vulnerabilities: If the web app uses gRPC-Web, looking for specific protocol-level vulnerabilities or misconfigurations.

[ ] Web Transport API Misuse/Vulnerabilities: If leveraging Web Transport, checking for misuse or flaws that could lead to data exposure or unauthorized communication.

[ ] Web Worker Security Vulnerabilities: Exploiting security flaws in web workers that could lead to XSS, data leakage, or resource exhaustion.

[ ] WebAssembly Component Model Security (emerging): As the component model evolves, looking for vulnerabilities in its implementation that could affect interoperability and security.

[ ] Cross-Origin Resource Sharing (CORS) with Credential Abuse: If CORS is too permissive and allows credentials, this could lead to data theft by malicious origins.

[ ] DNS Rebinding Attacks (Client-Side): Exploiting DNS rebinding for client-side attacks (e.g., same-origin policy bypass) by making a browser rebind a domain to an internal IP.

[ ] OAuth Implicit Grant Flow Vulnerabilities (redirect URI manipulation): Exploiting insecure implementations of the OAuth implicit grant flow, such as redirect URI manipulation, for authentication bypass.

[ ] CORS Misconfigurations on Subdomains: Identifying permissive CORS policies on less obvious subdomains that might be overlooked, enabling cross-domain attacks.

[ ] Host Header Injection (Web Cache Poisoning, Password Reset Poisoning): Exploiting host header vulnerabilities for various attacks, including web cache poisoning and password reset poisoning.

[ ] Clickjacking (specific UI elements, with complex overlays): Crafting sophisticated clickjacking attacks that target specific UI elements by overlaying malicious content.

[ ] HTML/CSS Injection (for defacement or partial XSS): Injecting HTML/CSS to alter the page appearance, deface content, or enable partial XSS vulnerabilities.

[ ] Insecure Client-Side Storage (Local Storage, Session Storage, IndexedDB): Identifying sensitive data stored insecurely client-side, which can be accessed by XSS or malicious extensions.

X. Advanced Logic & Behavioral Analysis
[ ] CAPTCHA Bypass (via logical flaws, outdated versions, or OCR): Developing Nuclei templates that can identify and potentially bypass CAPTCHAs through logical flaws, exploiting outdated versions, or using OCR.

[ ] Anti-Bot Mechanism Bypasses (via header manipulation, specific user agents): Identifying and bypassing common anti-bot techniques by manipulating HTTP headers or using specific user agents.

[ ] Account Enumeration (via subtle error messages or timing attacks): Identifying valid usernames/emails without brute-forcing passwords, based on subtle differences in error messages or response times.

[ ] Username Enumeration via Password Reset or Registration Forms (time-based): Detecting if a username exists based on timing differences in responses from password reset or registration forms.

[ ] Session Token Prediction/Brute-Forcing: Attempting to guess or brute-force weak session tokens due to insufficient entropy or predictable patterns.

[ ] CSRF on JSON Endpoints without Content-Type checks: Exploiting CSRF on JSON endpoints that don't properly validate the Content-Type header, allowing cross-site requests.

[ ] Missing SameSite Cookie Attribute (for CSRF): Identifying cookies without the SameSite attribute, making them vulnerable to CSRF in some contexts (e.g., None with Secure).

[ ] Race Condition for Unauthorized Access to Sensitive Files/Functions: Exploiting race conditions to briefly gain access to sensitive files or functions before authorization checks fully kick in.

[ ] Referer Leakage of Sensitive Information: Identifying cases where the Referer header leaks sensitive data to third-party sites, compromising user privacy.

[ ] Sensitive Information in JavaScript Console Logs: Detecting if the application logs sensitive data (e.g., API keys, user IDs) to the browser's developer console.

[ ] Client-Side Certificate Bypass (if applicable to specific applications): If an application relies on client-side certificates for authentication, looking for ways to bypass their validation.

[ ] User Agent String Spoofing for Feature/Access Bypass: Testing if certain user agent strings grant different levels of access or features, bypassing restrictions.

[ ] Timing Attacks on Authentication/Authorization: Detecting subtle timing differences in responses that reveal information about credentials or permissions, aiding in brute-force attacks.

[ ] Insecure Cross-Origin Communication (window.opener vulnerabilities): Exploiting window.opener vulnerabilities for cross-origin attacks, allowing control over the originating window.

[ ] Missing Security Headers (e.g., Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options): While basic, demonstrating a thorough check for these crucial security headers to improve client-side protection.

[ ] Credential Stuffing/Account Takeover via Weak Password Policies: Identifying applications with weak password policies that make credential stuffing easier, leading to account takeover.

[ ] HTTP Parameter Pollution with Filter Bypass: Using HPP to bypass input validation or WAF rules by manipulating how parameters are parsed on the backend.

[ ] Response Smuggling with Client-Side Effects: Manipulating HTTP responses to cause client-side effects (e.g., XSS, cache poisoning) by sending partial or malformed responses.


Got it! You're looking for an even more exhaustive list of advanced, unique, and client-appreciated web application scanner scenarios for Nuclei. The focus remains on "builderable" templates that demonstrate capabilities beyond standard scanners.

Here are 300 additional advanced and unique web application scanner ideas, categorized for clarity. These go deeper into specific technologies, bypass techniques, and subtle logic flaws that clients would value seeing detected.

Next-Gen Server-Side Vulnerabilities & Bypass Techniques
This document offers a comprehensive checklist of advanced server-side and client-side vulnerabilities, emerging attack vectors, and sophisticated bypass techniques relevant to modern web applications. Whether you're a red teamer, a security researcher, or a developer aiming to build more resilient applications, this list covers critical areas often overlooked.

When viewed on GitHub, these items will display as interactive checkboxes. You can click them directly within the GitHub interface (e.g., when editing a README or in a pull request description) to mark them as done.

I. Next-Gen Server-Side Vulnerabilities & Bypass Techniques
A. Advanced Server-Side Request Forgery (SSRF) & Internal Network Exposure
[ ] SSRF with Multi-Level Redirection Bypasses: Exploiting SSRF vulnerabilities by meticulously following and analyzing multiple HTTP redirects (e.g., 302 -> 301 -> 307) to reach internal services, effectively bypassing simple redirect filters.

[ ] SSRF via DNS Rebinding: Leveraging DNS rebinding techniques to circumvent IP-based SSRF filters, demonstrating access to restricted internal IPs and services.

[ ] SSRF to Cloud Metadata Endpoints (obscure paths): Targeting less common cloud metadata endpoints (e.g., Azure, GCP, Alibaba Cloud) beyond the widely known AWS 169.254.169.254, identifying sensitive cloud configuration and credentials.

[ ] SSRF to Internal K8s API Servers: Detecting unauthorized access to Kubernetes API servers (e.g., /api/v1/namespaces/kube-system/secrets) for potential cluster compromise and data exfiltration.

[ ] SSRF with URL Scheme Confusion: Leveraging unusual URL schemes like dict://, gopher://, file:// to access internal resources or execute arbitrary code on the backend, bypassing typical URL validation.

[ ] SSRF to Internal NoSQL Databases (e.g., MongoDB, Redis): Probing for default NoSQL ports and identifying exposed instances that could lead to data exfiltration or manipulation within the internal network.

[ ] SSRF to Internal Message Queues (e.g., RabbitMQ, Kafka): Identifying and probing for administrative interfaces or exposed queues that might contain sensitive data or allow for message manipulation.

[ ] SSRF to Internal Monitoring/Telemetry Services (e.g., Prometheus, Grafana): Discovering and accessing sensitive internal metrics or dashboards often running on internal networks, revealing system health and confidential information.

[ ] SSRF with HTTP Parameter Pollution (HPP) in Query/Body: Crafting requests that exploit HPP to manipulate internal SSRF logic and bypass filters, leading to unexpected backend behavior.

[ ] SSRF to Internal Git Repositories: Attempting to access hidden .git directories or internal Git servers via SSRF for source code disclosure and potential sensitive information leakage.

[ ] SSRF with Authentication Bypass (e.g., default creds): Identifying internal services that use common default credentials accessible via SSRF, allowing unauthorized access.

[ ] SSRF with Host Header Forgery: Manipulating the Host header in conjunction with SSRF to target specific internal services or bypass Web Application Firewalls (WAFs).

[ ] SSRF via Image/File Upload Processors: Exploiting vulnerabilities in image or file processing libraries that fetch external resources, leading to SSRF and potentially arbitrary file read.

[ ] SSRF via PDF/Document Converters: Detecting SSRF opportunities in services that convert URLs to PDF or other document formats, which might fetch internal URLs.

[ ] SSRF through Server-Side Template Engines (SSTI) with External Resource Loading: Chaining SSTI with external resource loading capabilities to achieve SSRF and read sensitive files from the server.

B. Advanced Template Injection (SSTI) & Deserialization
[ ] SSTI in Obscure Template Engines: Beyond common engines like Jinja2 or Twig, targeting less popular or custom template engines that often lack robust sanitization, leading to RCE.

[ ] SSTI with Gadget Chain Discovery (Java/Python): Identifying specific "gadgets" in an application's dependencies that, when combined with SSTI or deserialization, can lead to Remote Code Execution (RCE).

[ ] SSTI with Sandbox Escapes (specific versions): Exploiting known sandbox bypasses in older or misconfigured template engine versions to gain RCE, even within supposed secure environments.

[ ] SSTI via XML External Entity (XXE) to Local File Read: Combining SSTI with XXE for sophisticated local file read vulnerabilities, allowing access to arbitrary files on the server.

[ ] Deserialization Vulnerabilities in Less Common Formats: Beyond Java/PHP, focusing on Python Pickle, .NET, or Ruby YAML deserialization, which are often missed by generic scanners and can lead to RCE.

[ ] Deserialization with Custom Object Injection: Identifying and exploiting custom classes that are deserialized insecurely, leading to RCE or other severe impacts like data corruption.

[ ] SSTI/Deserialization in CI/CD Webhooks: Targeting webhooks used for CI/CD pipelines that might be vulnerable to injection, potentially leading to build system compromise and supply chain attacks.

[ ] SSTI in Email Template Rendering Services: Exploiting vulnerabilities in services that generate dynamic email content, leading to internal data exposure, spam, or even XSS.

C. Emerging API Security Flaws (beyond OWASP API Top 10)
[ ] Excessive Data Exposure via GraphQL Type Introspection (with filtering bypasses): Crafting specific GraphQL queries that reveal more than intended, even with basic filtering, by understanding the schema's deeper relationships.

[ ] GraphQL Query Complexity Attacks (Denial of Service): Generating overly complex or deeply nested GraphQL queries designed to trigger DoS by overwhelming server resources, leading to service unavailability.

[ ] GraphQL Batching Abuse for Rate Limit Bypass: Exploiting GraphQL's batching feature to circumvent rate limiting on individual API calls, enabling brute-force or resource exhaustion attacks.

[ ] Broken Function Level Authorization (BFLA) in Microservices/Internal APIs: Identifying granular authorization flaws when different services communicate internally, often exposing unintended functionality to unauthorized users.

[ ] Mass Assignment/Parameter Tampering in API Endpoints (nested objects): Exploiting vulnerabilities where attackers can inject or overwrite unexpected parameters, especially within complex nested JSON/object structures, leading to data manipulation or privilege escalation.

[ ] API Rate Limiting Bypasses (e.g., via IP rotation, header manipulation): Crafting requests that circumvent typical rate limiting mechanisms, enabling brute-force attacks or resource exhaustion.

[ ] Unauthenticated/Weakly Authenticated Internal API Exposure: Discovering internal-only APIs that are exposed to the internet or have weak authentication, providing direct access to backend services and sensitive data.

[ ] API Security Misconfigurations (e.g., verbose error messages, exposed debug endpoints): Identifying endpoints that reveal sensitive information (stack traces, internal IP addresses) or debugging interfaces that should not be publicly accessible.

[ ] API Key Reuse/Hardcoded Keys in Client-Side Code: Detecting hardcoded API keys in JavaScript or client-side bundles that could be abused for unauthorized API access or resource consumption.

[ ] API-Specific Injection Flaws (e.g., NoSQL Injection in API parameters): Beyond traditional SQL injection, targeting NoSQL databases via API inputs with specially crafted payloads.

[ ] Insecure Direct Object Reference (IDOR) with Encoding/Hashing Bypasses: Exploiting IDORs where object IDs are encoded or hashed, but the scheme is guessable or breakable, leading to unauthorized data access.

[ ] Client-Side API Key Exploitation (e.g., Google Maps API key abuse): Identifying exposed API keys and demonstrating potential abuse (e.g., excessive usage, sensitive data access) via client-side manipulation.

[ ] GraphQL Schema Stitching Vulnerabilities: Identifying vulnerabilities where stitching multiple GraphQL schemas introduces new attack surfaces or information disclosure due to unexpected interactions.

[ ] API Gateway Misconfigurations (e.g., improper routing, unauthorized access): Exploiting misconfigurations in API gateways that lead to bypassing security controls, routing to internal services, or unauthorized access to APIs.

D. Advanced XXE (XML External Entity)
[ ] XXE to Remote Code Execution (via JAR/PHAR deserialization): Chaining XXE with deserialization gadgets for RCE, a highly critical impact.

[ ] XXE with Out-of-Band (OOB) Data Exfiltration (DNS/HTTP): Using OOB techniques to exfiltrate sensitive data via XXE, even when direct output is not reflected.

[ ] XXE in Non-XML Parsers (e.g., certain image parsers, document processors): Identifying XXE in unexpected file formats or processing stages that internally use XML parsers.

[ ] XXE via DTD File Upload: Exploiting applications that allow DTD file uploads to trigger XXE, leading to local file read or SSRF.

[ ] XXE with Blind Out-of-Band Interaction: Detecting blind XXE vulnerabilities through delayed OOB interactions (e.g., DNS lookups), confirming the vulnerability without direct response.

E. Modern SSRF & Internal Service Interaction
[ ] SSRF to internal database connections strings (e.g., jdbc:mysql://): Identifying if error messages or verbose responses disclose internal database connection strings via SSRF, aiding further attacks.

[ ] SSRF via data: URI scheme to bypass WAFs: Using data: URIs to smuggle content past WAFs or content filters, allowing internal resource access.

[ ] SSRF to identify and interact with internal container registries: Probing for exposed Docker registries or other container image repositories within the internal network.

[ ] SSRF to access internal environment variables via file paths: Attempting to read /proc/self/environ or similar sensitive paths via SSRF, exposing sensitive configuration.

[ ] SSRF to internal message bus systems (e.g., Kafka, RabbitMQ APIs): Interacting with internal messaging systems for data exfiltration, message manipulation, or triggering internal business logic.

[ ] SSRF to internal cloud service control planes (e.g., private APIs for AWS, GCP, Azure management): Exploiting lesser-known internal control plane APIs accessible via SSRF, potentially leading to cloud resource manipulation.

II. Sophisticated Client-Side Attacks
A. Prototype Pollution & XSS Gadget Chaining
[ ] Client-Side Prototype Pollution via URL Hash/Query Parameters: Detecting prototype pollution vulnerabilities introduced by processing URL parameters, which can affect global JavaScript objects.

[ ] Prototype Pollution to XSS Gadget Chaining (Framework-Specific): Identifying and exploiting known gadget chains in popular JavaScript frameworks (React, Angular, Vue) to achieve XSS via prototype pollution.

[ ] Prototype Pollution leading to DOM Clobbering for XSS/Bypass: Exploiting prototype pollution to perform DOM clobbering attacks to manipulate page content or bypass security controls (e.g., XSS filters).

[ ] Prototype Pollution via JSON/Object Merging Functions: Targeting vulnerabilities in libraries or custom code that merge JavaScript objects insecurely, leading to prototype pollution.

[ ] Prototype Pollution in WebSockets/Event Listeners: Detecting prototype pollution vulnerabilities through WebSocket messages or client-side event listeners that process untrusted data.

[ ] Prototype Pollution with CSRF Token Bypass: Exploiting prototype pollution to nullify or manipulate CSRF tokens client-side, enabling CSRF attacks against authenticated users.

B. Advanced Cross-Site Scripting (XSS) & Bypass Techniques
[ ] Mutation XSS (mXSS) in DOM Manipulation: Exploiting mXSS vulnerabilities where the browser re-parses modified DOM elements, leading to XSS after initial sanitization attempts.

[ ] CSP Bypass via JSONP Endpoints: Identifying misconfigured JSONP endpoints that can bypass Content Security Policies (CSP), allowing unauthorized script execution.

[ ] CSP Bypass via dangling markup/response header injection: Crafting payloads that leverage incomplete HTML tags or injected headers to bypass CSP restrictions.

[ ] Reflected XSS in HTTP Request Headers: Injecting XSS payloads into less common HTTP headers (e.g., User-Agent, Referer, X-Forwarded-For), which might be reflected insecurely.

[ ] Stored XSS in Markdown/Rich Text Editors (with complex filters): Bypassing sophisticated sanitization filters in modern rich text editors by crafting complex payloads.

[ ] Universal XSS (UXSS) in specific browser versions (if applicable): While rare, identifying browser-specific XSS vulnerabilities that can affect all websites visited by a vulnerable browser.

[ ] XSS via SVG/Image Uploads (embedded scripts): Exploiting image parsing vulnerabilities that allow embedded JavaScript execution within SVG or other image formats.

[ ] XSS via WebSockets (message injection): Injecting and executing XSS payloads through WebSocket communication, leading to persistent or reflected XSS.

[ ] XSS via Client-Side Template Injection (CSTI): Exploiting client-side template engines for XSS by injecting malicious templates that execute JavaScript.

[ ] XSS with DOM Clobbering for Sensitive Data Exfiltration: Using DOM Clobbering in conjunction with XSS to steal sensitive data by manipulating form fields or other DOM elements.

[ ] XSS via PostMessage Vulnerabilities (cross-origin): Exploiting insecure postMessage implementations for cross-origin communication vulnerabilities, leading to data theft or XSS.

[ ] XSS in JavaScript Libraries (known CVEs, often missed): Detecting older versions of JavaScript libraries with known XSS vulnerabilities that might be missed by generic scanners.

C. Client-Side Desync Attacks
[ ] HTTP/2 Desync Attacks: Exploiting nuances in HTTP/2 protocol parsing for desync attacks, leading to request smuggling or cache poisoning.

[ ] HTTP/1.1 to HTTP/2 Downgrade Desync: Detecting vulnerabilities arising from discrepancies when traffic is downgraded between protocols, enabling request smuggling.

[ ] Client-Side HTTP Request Smuggling via "Content-Length" / "Transfer-Encoding" ambiguities: Identifying subtle differences in how proxies/servers interpret HTTP headers leading to request smuggling and cache poisoning.

[ ] Web Cache Deception with Authentication Token Leakage: Tricking caching mechanisms to cache sensitive authenticated responses for other users, leading to token leakage.

[ ] Web Cache Poisoning via Header Injection: Injecting malicious headers to poison web caches, leading to reflected XSS or redirects for other users.

III. Business Logic & Authentication/Authorization Flaws
A. Advanced Authentication & Session Management
[ ] Broken Authentication via Password Reset Logic Flaws (e.g., race conditions, token leakage): Exploiting subtle flaws in password reset mechanisms, such as race conditions or predictable token generation.

[ ] Authentication Bypass via OAuth/SSO Misconfigurations: Identifying misconfigurations in OAuth2 or OpenID Connect implementations (e.g., improper redirect URIs, weak token validation) leading to bypass.

[ ] Session Fixation with Anti-CSRF Token Bypass: Demonstrating session fixation vulnerabilities and how they can be chained with CSRF token bypasses for complete session hijacking.

[ ] Insecure Session Management via Predictable Session IDs: Detecting weak entropy in session ID generation, allowing for session prediction and unauthorized access.

[ ] Multi-Factor Authentication (MFA) Bypass via Backup Codes/Recovery Flows: Exploiting flaws in MFA recovery or backup code mechanisms to bypass the second factor.

[ ] Horizontal Privilege Escalation with IDOR on User Objects (non-numeric IDs): Exploiting IDORs on user accounts with non-sequential or complex IDs, allowing access to other users' data.

[ ] Vertical Privilege Escalation by Role Manipulation (header/cookie): Attempting to elevate privileges by tampering with role-related parameters in HTTP headers or cookies to gain administrative access.

[ ] Session Hijacking via Cross-Site Scripting (XSS) with HTTPOnly Bypass (if applicable): If HTTPOnly is not set or bypassed, demonstrating cookie theft via XSS, leading to session hijacking.

B. Business Logic Abuse & Race Conditions
[ ] Race Conditions in Financial Transactions: Exploiting race conditions to double spend or gain unauthorized credits by submitting multiple requests simultaneously.

[ ] Race Conditions in Account Creation/Deletion: Demonstrating how race conditions can lead to account enumeration, unauthorized account creation, or deletion.

[ ] Business Logic Flaws in Shopping Carts/Pricing: Manipulating pricing, quantities, or discounts via business logic flaws to purchase items at an unintended price.

[ ] Abuse of "Remember Me" Functionality: Detecting vulnerabilities in persistent login mechanisms, allowing for session replay or extended unauthorized access.

[ ] Workflow Bypass (e.g., skipping payment steps): Identifying ways to bypass intended application workflows, such as skipping payment steps in an e-commerce application.

[ ] Excessive API Calls for Resource Exhaustion (DoS): Generating specific patterns of API calls that lead to resource exhaustion without triggering typical rate limits, causing Denial of Service.

[ ] Brute-Forcing Obscure Login Parameters: Attempting to brute-force less common login parameters (e.g., tenant IDs, client secrets) that are not typically protected by strong rate limits.

[ ] Improper Access Control based on HTTP Method/Content-Type: Exploiting cases where access controls are only applied to specific HTTP methods or content types, allowing bypass.

[ ] Logic Bugs in Feature Flags/A/B Testing: Exploiting misconfigurations or flaws in how feature flags are managed, granting unauthorized access to features or content.

IV. Modern Infrastructure & Supply Chain Attacks
A. Cloud-Native & Container Security
[ ] Exposed Docker API Endpoints: Detecting publicly exposed Docker daemon API endpoints, which can lead to container escape and host compromise.

[ ] Insecure Kubernetes API Server Exposure: Identifying publicly accessible or weakly authenticated Kubernetes API servers, allowing cluster manipulation.

[ ] Sensitive Data in Kubernetes ConfigMaps/Secrets (exposed via web): If a web application exposes sensitive data from ConfigMaps or Secrets, leading to information disclosure.

[ ] Container Escape via Web Application (if privileged containers): Though difficult to detect with external scanning, a template could look for indicators of vulnerable container setups that allow escape.

[ ] Serverless Function (Lambda, Azure Functions) Misconfigurations: Identifying overly permissive serverless function policies or exposed invocation endpoints, leading to unauthorized function execution.

[ ] Cloud Storage Misconfigurations (e.g., S3 bucket misconfigurations with specific policies): Beyond basic open S3 buckets, looking for nuanced policy misconfigurations that allow unintended access.

[ ] API Gateway (e.g., AWS API Gateway, Azure API Management) Misconfigurations: Exploiting misconfigured API gateways that expose internal services, bypass authentication, or allow unauthorized routing.

B. Software Supply Chain Vulnerabilities
[ ] Vulnerable JavaScript Libraries (specific CVEs, not just general checks): Identifying particular versions of widely used JS libraries with known RCE/XSS vulnerabilities that can be exploited client-side.

[ ] Exposed .git or .svn repositories (with sensitive data): Detecting version control repositories accessible via the web, especially if they contain credentials or sensitive configuration files.

[ ] Exposed .env files (with sensitive environment variables): Detecting .env files exposing application secrets, database credentials, or API keys.

[ ] Dependency Confusion (Package Managers): While harder to scan externally, a Nuclei template could look for indicators of vulnerable dependency resolution, leading to arbitrary code execution.

[ ] Exposed Source Maps (.map files) revealing original source code: Finding JavaScript source maps that reveal unminified and potentially sensitive source code, aiding in vulnerability discovery.

[ ] Compromised CI/CD Artifacts (detectable if served insecurely): If an application serves build artifacts directly that might contain signs of compromise or sensitive information.

[ ] Vulnerable Build Tools/Frameworks (e.g., outdated webpack, npm): Detecting the presence of specific outdated build tools through exposed metadata, which might have known vulnerabilities.

C. Advanced Misconfigurations & Information Leakage
[ ] Verbose Error Messages Revealing Internal System Details (stack traces with specific frameworks): Identifying detailed error messages that disclose technology stack, file paths, or database errors, aiding attackers in reconnaissance.

[ ] Exposed Debug/Profiling Endpoints (e.g., _profiler, debugbar): Finding debugging or profiling tools that expose sensitive application state or configuration, which should not be publicly accessible.

[ ] Directory Listing with Sensitive Files: Beyond common directory listings, looking for sensitive configurations, backups, or log files exposed through directory listings.

[ ] Weak SSL/TLS Configurations (outdated protocols, weak ciphers, expired certs): Detecting security misconfigurations in SSL/TLS (e.g., SSLv3, weak ciphers), making communication vulnerable to eavesdropping.

[ ] Exposed Administration Panels with Default Credentials: Finding admin interfaces that use common default usernames and passwords, leading to easy compromise.

[ ] Loose CORS Policies (allowing any origin): Identifying misconfigured Cross-Origin Resource Sharing policies that permit unauthorized cross-domain requests, leading to data theft.

[ ] CRLF Injection in HTTP Headers (for response splitting/cache poisoning): Injecting CRLF characters into HTTP headers to manipulate responses, leading to response splitting or cache poisoning.

[ ] Open Redirects for Phishing/SSO Bypass: Detecting open redirect vulnerabilities that can be used for phishing attacks or to bypass Single Sign-On (SSO) mechanisms.

[ ] JWT Misconfigurations (weak secrets, algorithm confusion, no validation): Identifying vulnerabilities in JSON Web Token implementations (e.g., alg:none attacks, weak secrets) leading to authentication bypass.

[ ] Web Server Default Pages/Configuration Files (e.g., Apache, Nginx default pages, nginx.conf if exposed): Detecting default server installations or exposed configuration files, which often contain sensitive information.

[ ] Exposed robots.txt or sitemap.xml revealing sensitive paths: If these files contain paths that should not be publicly accessible, potentially exposing hidden endpoints.

[ ] Insecure File Uploads (beyond basic executable uploads, e.g., image parsing bypasses): More advanced file upload vulnerabilities that bypass typical sanitization, allowing arbitrary file upload and execution.

V. Advanced Injection Techniques
A. Command Injection & OS Command Injection
[ ] Command Injection in Network Tools (e.g., ping, nslookup functionality): Exploiting web applications that integrate system network utilities (ping, nslookup), allowing OS command execution.

[ ] Blind Command Injection (via time delays or OOB interactions): Detecting command injection when direct output is not reflected, relying on time-based delays or out-of-band interactions.

[ ] Command Injection via Environmental Variables: Injecting commands by manipulating environment variables passed to executed commands.

[ ] Command Injection via Image Processing Libraries (e.g., ImageMagick): Exploiting known vulnerabilities in image processing software that can lead to command injection upon image upload.

B. SQL Injection & NoSQL Injection
[ ] Second-Order SQL Injection: Detecting vulnerabilities where injected data is processed later by a different query, making it harder to detect.

[ ] Time-Based Blind SQL Injection (DBMS-specific delays): Exploiting time-based delays for blind SQL injection, tailored to different database systems (e.g., MySQL, PostgreSQL, MSSQL).

[ ] NoSQL Injection in MongoDB/Cassandra Query Language: Crafting specific NoSQL injection payloads that manipulate queries in MongoDB, Cassandra, or other NoSQL databases.

[ ] SQL Injection in HTTP Request Headers (e.g., User-Agent): Injecting SQL payloads into less common HTTP headers (e.g., User-Agent, Referer) that are used in database queries.

[ ] Out-of-Band SQL Injection (DNS/HTTP exfiltration): Using OOB techniques (e.g., DNS lookups, HTTP requests) to exfiltrate data from SQL injection when direct output is not possible.

[ ] SQL Injection via XML/JSON Payloads: Exploiting SQL injection through XML or JSON input structures when the application processes these formats for database queries.

C. LDAP/XPath Injection
[ ] LDAP Injection for Authentication Bypass/Information Disclosure: Exploiting applications that use LDAP for authentication or data retrieval, allowing for authentication bypass or directory enumeration.

[ ] Blind LDAP Injection (time-based): Detecting blind LDAP injection vulnerabilities through time-based delays when direct output is not reflected.

[ ] XPath Injection for XML Data Extraction: Exploiting XPath injection to extract data from XML documents, potentially revealing sensitive information.

VI. Niche & Emerging Attack Vectors
A. WebAssembly (Wasm) Security
[ ] Wasm Module Information Leakage: Identifying Wasm modules that expose sensitive internal logic or data, which can be reverse-engineered.

[ ] Wasm Module Reverse Engineering Indicators: Detecting if a Wasm module is easily de-obfuscated or contains clear function names, making it easier for attackers to understand its logic.

[ ] Wasm Sandbox Escape Potential (if relevant to specific versions): Looking for patterns that could indicate potential sandbox escape vulnerabilities in Wasm runtimes, though actual exploitation would be complex.

B. AI/ML Model Injection (Web-facing components)
[ ] Prompt Injection in Web-Facing AI Chatbots/Generative AI: Crafting specific prompts that manipulate the AI's behavior, extract sensitive data from its training set, or make it generate malicious content.

[ ] Model Poisoning Indicators (if a web app allows user model uploads): While hard to scan externally, looking for functionalities that might indicate model poisoning risks if not properly validated.

[ ] Side-Channel Information Leakage from AI Model Responses: Analyzing AI responses for subtle clues that might reveal internal model architecture or training data, leading to intellectual property theft.

[ ] AI-Driven Decision Logic Bypass: Identifying web applications where AI-driven decisions (e.g., fraud detection, content moderation) can be influenced or bypassed through specific input patterns.

C. Server-Side Rendering (SSR) & Next.js/Nuxt.js Specifics
[ ] SSR Hydration Mismatch XSS: Exploiting discrepancies between server-rendered and client-side hydrated content for XSS, due to differences in parsing or sanitization.

[ ] Next.js/Nuxt.js API Route Vulnerabilities: Targeting specific API routes or serverless functions within these frameworks for common vulnerabilities like injection or improper access control.

[ ] Data Fetching Vulnerabilities in SSR (e.g., getServerSideProps in Next.js revealing sensitive data): Identifying if server-side data fetching functions accidentally expose secrets, database queries, or internal logic.

D. Web3 / Blockchain-Enabled Web Apps
[ ] Smart Contract Interaction Vulnerabilities via Web Interface: If the web app interacts with smart contracts, scanning for misconfigurations that could lead to unintended smart contract calls or token drainage.

[ ] Wallet Connection Phishing (if the web app handles wallet connections insecurely): Detecting scenarios where a malicious actor could trick users into connecting to a fake wallet or authorizing malicious transactions.

[ ] Decentralized Storage (e.g., IPFS) Misconfigurations: Identifying insecurely exposed or configured decentralized storage through the web app, leading to data exposure or manipulation.

VII. Advanced Reconnaissance & Enumeration
A. Fingerprinting & Information Gathering (Deep Dives)
[ ] Deep Framework Version Detection (specific patch levels): Beyond just "React," identifying exact React, Angular, Vue, etc., versions and patch levels to identify known vulnerabilities.

[ ] Backend Language/Framework Version Detection (e.g., specific Python, PHP, Ruby, Node.js versions): Identifying the exact backend versions that might have known vulnerabilities, aiding in targeted exploits.

[ ] Hidden Parameters/Endpoints Discovery (via wordlists, JS analysis, historical data): Using advanced wordlists and JavaScript analysis to uncover undocumented parameters or endpoints.

[ ] Third-Party Service Fingerprinting (e.g., analytics, CDN, payment gateways): Identifying specific third-party services and checking for common misconfigurations or vulnerabilities associated with them.

[ ] Comment/Metadata Analysis for Sensitive Info: Extracting sensitive information from HTML comments, EXIF data in images, or other metadata embedded in publicly accessible files.

[ ] Favicon Hashing for Component Identification: Using favicon hashes to identify underlying technologies and versions, aiding in rapid component identification.

[ ] Error Message Profiling for Infrastructure Guessing: Analyzing different error message responses to infer underlying infrastructure (e.g., specific load balancers, WAFs, databases).

[ ] WAF/CDN Bypass Technique Identification: Identifying common WAFs/CDNs and attempting known bypass techniques to circumvent security controls.

B. Content Discovery (Beyond Basic)
[ ] Recursive Content Discovery for Subdomains/Subdirectories: Continuously discovering new subdomains and subdirectories based on discovered content and common naming conventions.

[ ] JavaScript File Analysis for Endpoint/Parameter Discovery: Parsing JavaScript files for hardcoded API endpoints, parameters, and sensitive strings that might reveal hidden functionality.

[ ] Wayback Machine/Archive.org Integration for Old Endpoints: Leveraging historical data from web archives to find forgotten or deprecated vulnerable endpoints that are still active.

[ ] Broken Link Hijacking Opportunities: Identifying broken links to external resources that could be hijacked to serve malicious content or phishing pages.

[ ] Virtual Host Discovery (Host header bruteforcing): Enumerating virtual hosts on a single IP address by bruteforcing Host headers.

[ ] CSS/JS Map File Analysis for Source Code Disclosure: Identifying and parsing source map files to recover original source code, revealing internal logic and potential vulnerabilities.

VIII. Advanced Access Control Bypasses
[ ] Broken Object Level Authorization (BOLA) with Array/Batch Processing: Exploiting BOLA when APIs allow processing of multiple objects in a single request, enabling unauthorized access to multiple resources.

[ ] Path Traversal/LFI Bypasses (encoding, null bytes, double encoding): Advanced techniques to bypass path traversal filters, such as using various encoding schemes, null bytes, or double encoding.

[ ] Authentication Bypass with HTTP Smuggling (Content-Length/Transfer-Encoding desync): Using HTTP request smuggling to bypass authentication or access controls by manipulating how proxies/servers interpret requests.

[ ] Authorization Bypass via Referer/Origin Header Manipulation: Attempting to bypass authorization checks by modifying Referer or Origin headers, tricking the application into granting access.

[ ] Insecure Direct Object Reference (IDOR) on Non-Numeric IDs: Exploiting IDORs on UUIDs, hashes, or other non-sequential identifiers if their generation or validation is flawed.

[ ] Broken Authentication by Insecure JWT Token Management: Exploiting issues like weak secrets, algorithm confusion (alg:none), or lack of signature verification in JWTs, leading to authentication bypass.

[ ] Horizontal Privilege Escalation with Session Token Swapping: Attempting to swap session tokens between different user types to gain unauthorized access to another user's account.

[ ] Vertical Privilege Escalation via Parameter Tampering (e.g., isAdmin=true): Exploiting simple parameter manipulation (e.g., changing a boolean flag) to gain administrative access.

[ ] Access Control Bypass via HTTP Method Override Headers (e.g., X-HTTP-Method-Override): Using these headers to bypass method-based access controls, for example, changing a GET request to a POST to access a restricted endpoint.

IX. Unique Attack Surface & Specific Technologies
[ ] WebRTC Security Vulnerabilities (e.g., IP disclosure, denial of service): If the web app uses WebRTC, looking for exposed IPs, internal network scanning, or denial-of-service opportunities.

[ ] WebSocket Protocol Injection (e.g., XSS over WebSockets, command injection): Injecting malicious data into WebSocket communication, leading to XSS, command injection, or other impacts.

[ ] Server-Sent Events (SSE) Injection: Exploiting applications that use Server-Sent Events for injection, leading to XSS or data leakage.

[ ] Web Push API Abuse (e.g., sending malicious notifications): If the application uses Web Push, checking for vulnerabilities allowing unauthorized notification sending to users.

[ ] Web Component Shadow DOM XSS (if applicable): Exploiting XSS in the Shadow DOM for complex web components, bypassing traditional DOM-based XSS detection.

[ ] Service Worker Hijacking/Bypass: Exploiting misconfigured or vulnerable service workers to intercept requests, deliver malicious content, or gain offline access.

[ ] GraphQL Subscriptions for Information Disclosure: Exploiting GraphQL subscriptions to receive unauthorized sensitive data in real-time.

[ ] gRPC-Web Protocol Vulnerabilities: If the web app uses gRPC-Web, looking for specific protocol-level vulnerabilities or misconfigurations.

[ ] Web Transport API Misuse/Vulnerabilities: If leveraging Web Transport, checking for misuse or flaws that could lead to data exposure or unauthorized communication.

[ ] Web Worker Security Vulnerabilities: Exploiting security flaws in web workers that could lead to XSS, data leakage, or resource exhaustion.

[ ] WebAssembly Component Model Security (emerging): As the component model evolves, looking for vulnerabilities in its implementation that could affect interoperability and security.

[ ] Cross-Origin Resource Sharing (CORS) with Credential Abuse: If CORS is too permissive and allows credentials, this could lead to data theft by malicious origins.

[ ] DNS Rebinding Attacks (Client-Side): Exploiting DNS rebinding for client-side attacks (e.g., same-origin policy bypass) by making a browser rebind a domain to an internal IP.

[ ] OAuth Implicit Grant Flow Vulnerabilities (redirect URI manipulation): Exploiting insecure implementations of the OAuth implicit grant flow, such as redirect URI manipulation, for authentication bypass.

[ ] CORS Misconfigurations on Subdomains: Identifying permissive CORS policies on less obvious subdomains that might be overlooked, enabling cross-domain attacks.

[ ] Host Header Injection (Web Cache Poisoning, Password Reset Poisoning): Exploiting host header vulnerabilities for various attacks, including web cache poisoning and password reset poisoning.

[ ] Clickjacking (specific UI elements, with complex overlays): Crafting sophisticated clickjacking attacks that target specific UI elements by overlaying malicious content.

[ ] HTML/CSS Injection (for defacement or partial XSS): Injecting HTML/CSS to alter the page appearance, deface content, or enable partial XSS vulnerabilities.

[ ] Insecure Client-Side Storage (Local Storage, Session Storage, IndexedDB): Identifying sensitive data stored insecurely client-side, which can be accessed by XSS or malicious extensions.

X. Advanced Logic & Behavioral Analysis
[ ] CAPTCHA Bypass (via logical flaws, outdated versions, or OCR): Developing Nuclei templates that can identify and potentially bypass CAPTCHAs through logical flaws, exploiting outdated versions, or using OCR.

[ ] Anti-Bot Mechanism Bypasses (via header manipulation, specific user agents): Identifying and bypassing common anti-bot techniques by manipulating HTTP headers or using specific user agents.

[ ] Account Enumeration (via subtle error messages or timing attacks): Identifying valid usernames/emails without brute-forcing passwords, based on subtle differences in error messages or response times.

[ ] Username Enumeration via Password Reset or Registration Forms (time-based): Detecting if a username exists based on timing differences in responses from password reset or registration forms.

[ ] Session Token Prediction/Brute-Forcing: Attempting to guess or brute-force weak session tokens due to insufficient entropy or predictable patterns.

[ ] CSRF on JSON Endpoints without Content-Type checks: Exploiting CSRF on JSON endpoints that don't properly validate the Content-Type header, allowing cross-site requests.

[ ] Missing SameSite Cookie Attribute (for CSRF): Identifying cookies without the SameSite attribute, making them vulnerable to CSRF in some contexts (e.g., None with Secure).

[ ] Race Condition for Unauthorized Access to Sensitive Files/Functions: Exploiting race conditions to briefly gain access to sensitive files or functions before authorization checks fully kick in.

[ ] Referer Leakage of Sensitive Information: Identifying cases where the Referer header leaks sensitive data to third-party sites, compromising user privacy.

[ ] Sensitive Information in JavaScript Console Logs: Detecting if the application logs sensitive data (e.g., API keys, user IDs) to the browser's developer console.

[ ] Client-Side Certificate Bypass (if applicable to specific applications): If an application relies on client-side certificates for authentication, looking for ways to bypass their validation.

[ ] User Agent String Spoofing for Feature/Access Bypass: Testing if certain user agent strings grant different levels of access or features, bypassing restrictions.

[ ] Timing Attacks on Authentication/Authorization: Detecting subtle timing differences in responses that reveal information about credentials or permissions, aiding in brute-force attacks.

[ ] Insecure Cross-Origin Communication (window.opener vulnerabilities): Exploiting window.opener vulnerabilities for cross-origin attacks, allowing control over the originating window.

[ ] Missing Security Headers (e.g., Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options): While basic, demonstrating a thorough check for these crucial security headers to improve client-side protection.

[ ] Credential Stuffing/Account Takeover via Weak Password Policies: Identifying applications with weak password policies that make credential stuffing easier, leading to account takeover.

[ ] HTTP Parameter Pollution with Filter Bypass: Using HPP to bypass input validation or WAF rules by manipulating how parameters are parsed on the backend.

[ ] Response Smuggling with Client-Side Effects: Manipulating HTTP responses to cause client-side effects (e.g., XSS, cache poisoning) by sending partial or malformed responses.

XI. Advanced Input Validation & Encoding Bypass
[ ] Double Encoding Bypass: Testing payloads that require multiple layers of URL encoding to bypass filters.

[ ] Unicode Encoding Bypass: Using Unicode characters to bypass input validation filters.

[ ] Null Byte Injection (%00) for Path/Extension Bypass: Injecting null bytes to terminate strings and bypass filename or path checks.

[ ] Padding Oracle Attack Vulnerabilities (if applicable to encryption scheme): Detecting vulnerabilities in padding schemes used for encryption.

[ ] Blind XSS with Delayed OOB Interaction (e.g., via image loading or script tags in logs): Using OOB interactions to confirm blind XSS.

[ ] XSS in PDF Generators (if converting user input to PDF): Injecting XSS into PDF generation processes.

[ ] Header Injection in Backend Calls (e.g., for SSRF, SQLi): Injecting malicious headers into backend HTTP calls.

[ ] HTML Entity Encoding Bypass (e.g., &#xNN; vs. <): Using various HTML entity encoding forms to bypass XSS filters.

[ ] Polyglot Payloads (e.g., combining SQLi and XSS in one input): Crafting payloads that work across multiple injection types.

[ ] Input Fuzzing with Character Set Mutations: Fuzzing inputs with unusual character sets to trigger parsing errors.

[ ] Length Limit Bypass (e.g., using different encodings to shorten payload): Crafting payloads that appear shorter than they are to bypass length limits.

[ ] Bypassing Regex Filters with Edge Cases: Crafting inputs that exploit the edge cases or misconfigurations of regular expressions.

[ ] URL Parser Differentials (between web server, WAF, application): Exploiting inconsistencies in how different components parse URLs.

XII. Advanced Application Logic & Edge Cases
[ ] Cross-Site Request Forgery (CSRF) on JSON Endpoints with specific headers (e.g., custom Content-Type): Exploiting CSRF where Content-Type might be less strictly validated.

[ ] CSRF with SameSite Cookie Attribute Bypass (e.g., None without Secure): Identifying misconfigurations of the SameSite attribute.

[ ] Cross-Site Tracing (XST) enabled (TRACE method): Detecting if the TRACE HTTP method is enabled, which can aid XSS.

[ ] Cookie Bombing/Session Exhaustion: Sending excessive or malformed cookies to trigger DoS or session invalidation.

[ ] Cache Miss Exploitation (e.g., forcing a cache miss to expose sensitive data): Manipulating requests to bypass caching and hit the origin server.

[ ] Cache Invalidation Issues (e.g., old data served after update): Detecting if cached data isn't properly invalidated after changes.

[ ] Time-Based Information Disclosure (e.g., different response times for valid/invalid inputs): Using subtle timing differences to infer sensitive information.

[ ] Resource Exhaustion via Complex Query/Input (e.g., nested XML/JSON with deep recursion): Crafting inputs that cause resource exhaustion.

[ ] Denial of Service (DoS) via Thread Exhaustion: Sending requests that cause the application to consume all available threads.

[ ] DoS via File Descriptor Exhaustion: Triggering a large number of file operations to exhaust file descriptors.

[ ] DoS via Memory Exhaustion (e.g., large file uploads, infinite loops): Causing the application to consume excessive memory.

[ ] DoS via CPU Exhaustion (e.g., complex regex, cryptographic operations): Sending inputs that trigger CPU-intensive operations.

[ ] Insecure Random Number Generation: Identifying indicators of weak random number generation for tokens or IDs.

[ ] Weak Entropy in Cryptographic Keys/IDs: Detecting if cryptographic keys or IDs are easily predictable.

[ ] Predictable URLs/Filenames for Sensitive Resources: Guessing paths to sensitive files or pages.

[ ] Improper Handling of UTF-8/Unicode Characters: Exploiting how the application handles different Unicode representations.

[ ] Broken Link Hijacking on JavaScript Imports: If external JS imports are broken, attempting to hijack them.

[ ] Dangling DNS Records: Finding old DNS records that point to non-existent resources.

[ ] Subdomain Takeover via SaaS Service Records: Identifying dangling DNS records that can be taken over on SaaS platforms.

[ ] Reflected File Download (RFD) vulnerabilities: Tricking browsers into downloading files with malicious content based on URL parameters.

[ ] URL Redirection Chain Attacks: Exploiting multiple redirects to reach a malicious destination or bypass filters.

[ ] XML Bomb (Billion Laughs Attack) for DoS: Sending a specially crafted XML document to consume server resources.

[ ] ZIP Bomb for DoS: If file uploads are allowed, attempting to upload a ZIP bomb.

[ ] Regex Denial of Service (ReDoS): Supplying input that causes inefficient regular expressions to consume excessive CPU.

[ ] Server-Side Request Smuggling (Advanced HTTP/2, WebSockets): Smuggling requests over HTTP/2 or WebSockets.

[ ] Client-Side Request Smuggling for XSS/Cache Poisoning: Exploiting differences in client-side vs. server-side interpretation of requests.

[ ] Web Scraping/Data Harvesting Bypass: Identifying and bypassing anti-scraping measures.

[ ] Browser Fingerprinting Evasion Techniques: Techniques to bypass browser fingerprinting.

[ ] Device Fingerprinting Bypass: Bypassing device-based authentication or tracking.

[ ] Broken Anti-Bot Measures (e.g., easy bypass of honeypots, CAPTCHA): Identifying and bypassing anti-bot measures.

[ ] User Enumeration via Registration/Login Timing Differences: Subtle timing differences revealing if a username exists.

[ ] Sensitive Data in JavaScript Console (runtime exposure): Detecting sensitive data logged to the browser console during runtime.

[ ] Session Hijacking via Network Sniffing (if not using HTTPS): Basic but critical, checking for lack of HTTPS.

[ ] Brute-Force Protection Bypass via IP Rotation/Header Spoofing: Bypassing brute-force protections.

[ ] File Inclusion/Path Traversal (non-standard delimiters, wrappers): Using less common delimiters or PHP wrappers for file inclusion.

[ ] Log Poisoning for RCE (via LFI to logs): Injecting malicious commands into logs that are later included and executed.

[ ] XML External Entity (XXE) to Local File Write (if applicable): Exploiting XXE to write files to the server.

[ ] Server-Side Template Injection (SSTI) in Email Templates: Injecting into email templates processed server-side.

[ ] SSTI with Class Loader Manipulation (Java): Advanced SSTI leading to manipulation of class loaders for RCE.

[ ] Deserialization via Image/File Uploads (e.g., Java ObjectInputStream): Uploading crafted serialized objects within file formats.

[ ] Deserialization via Custom Data Formats: Exploiting deserialization in custom, proprietary data formats.

[ ] GraphQL SQL Injection: Injecting SQL payloads into GraphQL queries.

[ ] GraphQL NoSQL Injection: Injecting NoSQL payloads into GraphQL queries.

[ ] GraphQL Command Injection: Injecting OS commands into GraphQL queries.

[ ] GraphQL Sensitive Field Exposure (via query depth/alias): Querying deeply or using aliases to expose sensitive fields.

[ ] GraphQL CSRF: Exploiting CSRF on GraphQL endpoints.

[ ] GraphQL IDOR: Exploiting IDOR through GraphQL queries.

[ ] GraphQL Rate Limit Bypass (complex queries): Bypassing rate limits by crafting complex GraphQL queries.

[ ] WebSocket Protocol Downgrade: Forcing WebSockets to downgrade to a less secure communication method.

[ ] WebSocket Message Flooding for DoS: Sending high volume of WebSocket messages to cause DoS.

[ ] WebSocket Origin Bypass: Connecting to WebSockets from unauthorized origins.

[ ] WebSocket Authentication Bypass: Bypassing authentication on WebSocket connections.

[ ] WebTransport Header Injection: Injecting headers into WebTransport frames.

[ ] WebTransport Data Exfiltration: Using WebTransport to exfiltrate data.

[ ] WebTransport Session Hijacking: Hijacking WebTransport sessions.

[ ] WebWorker SharedArrayBuffer Misuse: Exploiting SharedArrayBuffer vulnerabilities in WebWorkers.

[ ] WebWorker DoS (e.g., infinite loops): Causing DoS by creating infinite loops in WebWorkers.

[ ] Server-Sent Events (SSE) Cross-Origin Leakage: Sensitive data leakage via SSE due to lax CORS.

[ ] HTTP/3 (QUIC) Protocol Smuggling: Smuggling requests over QUIC if enabled.

[ ] HTTP/3 (QUIC) Cache Poisoning: Poisoning caches via HTTP/3.

[ ] HTTP/3 (QUIC) DoS: DoS attacks specific to the QUIC protocol.

[ ] HTTP TE: trailers Header Smuggling: Exploiting TE: trailers header for request smuggling.

[ ] Content-Disposition Header Injection (for filename spoofing): Manipulating Content-Disposition for malicious file downloads.

[ ] Strict-Transport-Security (HSTS) Bypass (e.g., DNS record manipulation): Exploiting HSTS bypass techniques.

[ ] Cross-Origin Read Forbidden (CORF) bypasses: Bypassing CORF protections to read sensitive data.

[ ] TLS Certificate Pinning Bypass Indicators: Detecting if an application uses certificate pinning and if there are potential bypasses.

[ ] Application-Specific Custom Header Injection: Injecting custom headers unique to the application to bypass logic.
