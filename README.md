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

🚀 Expanding Our Arsenal: 300 More Advanced Web App Scanner Scenarios for Nuclei
This expansion to our Nuclei template collection focuses on even more granular, cutting-edge, and often niche vulnerabilities that clients are eager to see detected. These scenarios are designed to showcase sophisticated scanning capabilities, emphasizing detection of flaws that evade common tools and require intricate understanding of modern web application stacks.

✨ Why These Scenarios Matter to Clients
Clients appreciate scanners that:

Find Real-World Impact: Detect vulnerabilities that directly lead to data breaches, unauthorized access, or significant financial loss.
Go Beyond Basic Checks: Identify complex, multi-stage, or application-specific flaws.
Cover Modern Tech: Understand and scan modern frameworks, APIs, and cloud-native environments.
Provide Actionable Intelligence: Deliver clear indications of compromise or misconfiguration.
Demonstrate Proactive Security: Show an ability to anticipate and detect emerging threats.
Our new set of Nuclei templates will continue to prioritize "builderable" design principles: modularity, parameterization, and workflow chaining, enabling you to adapt and extend them for diverse client environments.

I. Advanced API Security & Microservices Exploitation
A. Deeper API Logic & Authentication Bypass
[ ] API Versioning Bypass: Exploiting misconfigurations in API versioning (e.g., v1 vs. v2) to access deprecated or less secure endpoints.
[ ] API Gateway Shadow Endpoints: Discovering and accessing unlisted or internal API endpoints exposed via misconfigured API gateways.
[ ] Bypassing API Rate Limits via Header Manipulation (e.g., X-Forwarded-For, custom headers): Crafting requests to bypass rate limits by manipulating various HTTP headers.
[ ] Weak API Key Rotation/Revocation: Detecting indicators of static or poorly managed API keys that are never rotated.
[ ] API Key Abuse for Account Takeover (shared key for multiple users): Identifying scenarios where a single API key can control multiple user accounts.
[ ] OAuth/OpenID Connect Token Interception/Replay (client-side): Detecting misconfigurations that allow interception or replay of OAuth tokens.
[ ] API JWT Header Injection (e.g., kid manipulation for arbitrary file read/RCE): Exploiting vulnerabilities in kid (key ID) parameter of JWT headers.
[ ] API Parameter Type Juggling: Exploiting weak type checking in API parameters (e.g., sending string instead of integer) to bypass validation.
[ ] API with Insecure Paging/Pagination: Exploiting insecure pagination to access more data than authorized (e.g., limit=0, negative offsets).
[ ] GraphQL API - Batching for Brute-Force/Enumeration: Using GraphQL batching to efficiently enumerate users or brute-force credentials.
[ ] GraphQL API - Information Disclosure via Relay/Apollo Tracing: Detecting exposed tracing information that reveals sensitive query details.
[ ] gRPC API - Reflection Service Exposure: Identifying exposed gRPC reflection services that allow schema introspection.
[ ] REST API with Verbose Error Messages for Internal Data Structures: Detailed error messages revealing backend database schemas or object structures.
[ ] API Endpoint Enumeration via HTTP Method Fuzzing (e.g., GET on /delete): Fuzzing HTTP methods on known paths to find hidden functionalities.
[ ] API with Insecure Object Creation/Update (missing fields/parameters): Creating or updating objects with missing fields to bypass business logic.
B. Microservices & Inter-Service Communication
[ ] Internal Service Discovery Endpoints (e.g., Eureka, Consul, ZooKeeper): Identifying exposed service discovery endpoints that reveal internal network topology.
[ ] Inter-Service Communication with Weak Authentication/No Auth: Detecting exposed internal service APIs that lack proper authentication.
[ ] Event Bus/Message Queue Listener Injection (e.g., Kafka, RabbitMQ): Injecting malicious messages into internal event buses if web app interacts directly.
[ ] Sidecar Proxy (e.g., Envoy, Linkerd) Misconfigurations: Detecting misconfigured sidecar proxies that expose internal services or allow traffic manipulation.
[ ] API Orchestration Layer Vulnerabilities: Exploiting flaws in API gateways or orchestration layers that combine multiple microservices.
[ ] Service Mesh Policy Bypass: Identifying misconfigurations in service mesh policies that allow unauthorized communication.
[ ] Distributed Tracing (e.g., Jaeger, Zipkin) Information Leakage: Detecting exposed tracing endpoints that reveal sensitive request flows.
II. Cloud-Native & Container Exploitation Deep Dive
A. Kubernetes-Specific Attacks
[ ] Kubernetes Insecure Dashboard Exposure (e.g., Kube-Dashboard): Detecting weakly authenticated or exposed Kubernetes dashboards.
[ ] Kubernetes Insecure API Server Access (RBAC misconfigurations): Identifying API server access due to overly permissive RBAC policies.
[ ] Kubernetes kubelet API Exposure: Detecting exposed kubelet API for potential container access.
[ ] Kubernetes etcd Key-Value Store Exposure: Identifying exposed etcd instances that store cluster configuration and secrets.
[ ] Kubernetes ConfigMap/Secret Exposure via /var/run/secrets/kubernetes.io/serviceaccount/ paths: Attempting to access mounted Kubernetes secrets via path traversal.
[ ] Kubernetes Admission Controller Bypass: Identifying misconfigurations in admission controllers that could allow malicious deployments.
[ ] Kubernetes Helm Chart Repository Exposure: Detecting exposed Helm chart repositories that could reveal application configurations.
[ ] Kubernetes Network Policy Misconfigurations: Identifying misconfigured network policies that allow unauthorized pod communication.
B. Serverless & FaaS (Function-as-a-Service)
[ ] Serverless Function (Lambda, Azure Functions) Excessive Permissions: Detecting if a function has overly broad IAM roles or permissions.
[ ] Serverless Function Environment Variable Disclosure: Attempting to read sensitive environment variables within serverless functions.
[ ] Serverless Function URL Enumeration/Fuzzing: Discovering hidden or internal serverless function endpoints.
[ ] Serverless Function Race Conditions (e.g., on inventory updates): Exploiting race conditions in serverless functions triggered by events.
[ ] Serverless Function Cold Start Timing Attacks: Using cold start timings to infer information about functions.
[ ] API Gateway for Lambda/Azure Functions - Insecure Integrations: Detecting misconfigured API Gateway integrations that expose backend functions or data.
C. Cloud Storage & Data Lake Vulnerabilities
[ ] AWS S3 Bucket with Public Write Access (specific content types): Beyond public read, identifying S3 buckets allowing arbitrary uploads for defacement or malicious file hosting.
[ ] Azure Blob Storage Public Write Access: Detecting similar write access on Azure Blob containers.
[ ] Google Cloud Storage Bucket Public Write Access: Identifying public write access on GCS buckets.
[ ] Cloud Storage Bucket Policy Enumeration: Attempting to enumerate bucket policies to find subtle access control flaws.
[ ] CloudFront/Cloudflare (CDN) Misconfigurations (e.g., origin bypass): Detecting CDN misconfigurations that allow direct access to origin servers or bypass WAFs.
[ ] Cloud Storage Data Exfiltration via Publicly Accessible Logs: Identifying publicly accessible cloud storage buckets containing sensitive application logs.
[ ] Cloud Storage Versioning Abuse for Data Recovery/Tampering: If versioning is enabled and misconfigured, exploiting it to retrieve old sensitive files or revert changes.
D. Managed Database Services
[ ] Managed Database (e.g., RDS, Azure SQL DB) Admin Panel Exposure: Detecting exposed admin panels for cloud-managed databases.
[ ] Managed Database Connection String Leakage (via error messages, config files): Identifying exposed connection strings to managed databases.
[ ] NoSQL Database (e.g., DynamoDB, CosmosDB) Access Control Misconfigurations: Exploiting overly permissive IAM policies or access controls for NoSQL databases.
III. Sophisticated Supply Chain & CI/CD Exploitation
A. Advanced Dependency & Build System Attacks
[ ] Dependency Confusion with Private Package Registry: Identifying potential dependency confusion scenarios if the web app pulls from both public and private registries.
[ ] Vulnerable Build Tools/CLI Exposure (e.g., outdated Jenkins CLI, exposed Maven/Gradle repos): Detecting exposed or outdated build tools that could be exploited.
[ ] Compromised NPM/PyPI/Composer Package Indicators: Looking for known indicators of compromised open-source packages embedded in client-side code.
[ ] Software Bill of Materials (SBOM) Exposure: Detecting exposed SBOMs that reveal detailed dependency trees, useful for targeted attacks.
[ ] Package Manager Configuration File Exposure (e.g., .npmrc, pip.conf): Identifying exposed configuration files for package managers that might contain credentials.
[ ] Docker Compose/Kubernetes Manifest File Exposure: Detecting exposed docker-compose.yml or Kubernetes manifest files with sensitive configurations.
[ ] Source Code Disclosure via Git/SVN Dumps (.git/HEAD, .svn/entries): Deeper enumeration of Git/SVN directories to reconstruct source code.
[ ] Web Application Firewall (WAF) Bypass via Encoding/Obfuscation: Testing advanced encoding, double encoding, or custom obfuscation techniques to bypass WAFs.
[ ] WAF Bypass via HTTP Protocol Downgrade: Attempting to downgrade HTTP/2 to HTTP/1.1 to bypass WAF logic.
[ ] WAF Bypass via Header Order Manipulation: Manipulating the order of HTTP headers to bypass WAF rules.
[ ] WAF Bypass via Content-Type Mismatch: Sending a payload with a conflicting Content-Type to bypass WAF parsing.
[ ] CDN/Reverse Proxy Log File Exposure: Detecting exposed CDN or reverse proxy logs that might contain sensitive request data.
[ ] Sensitive Data in Webpack Bundles/Source Maps: Deep analysis of bundled JavaScript for hardcoded API keys, credentials, or sensitive business logic.
[ ] Exposed .DS_Store files: Detecting .DS_Store files which can reveal directory structures and file names on macOS.
[ ] Exposed .vscode directories: Revealing configuration and extensions used in VS Code projects, potentially exposing sensitive settings.
B. CI/CD Pipeline Vulnerabilities (Web-Exposed)
[ ] Jenkins/GitLab/GitHub Actions Webhook Abuse for RCE/SSRF: Exploiting insecure webhooks for CI/CD systems to trigger commands or SSRF.
[ ] CI/CD Build Log Exposure (sensitive data in logs): Detecting exposed build logs that contain credentials, secrets, or internal server details.
[ ] CI/CD Artifact Repository Exposure (e.g., Nexus, Artifactory): Identifying exposed artifact repositories with weak authentication.
[ ] CI/CD Agent/Runner API Exposure: Detecting exposed APIs of CI/CD agents that could be used to execute arbitrary commands.
IV. Advanced Injection & Data Exfiltration
A. Next-Gen SQL/NoSQL Injection & Bypass
[ ] Second-Order NoSQL Injection: Exploiting situations where user-controlled input, stored in one query, is later used insecurely in another NoSQL query.
[ ] NoSQL Injection with Array/JSON Operators: Crafting advanced NoSQL injection payloads leveraging specific operators (e.g., MongoDB $where, $regex).
[ ] Blind NoSQL Injection (time-based/error-based): Detecting blind NoSQL injection vulnerabilities through timing delays or unique error messages.
[ ] SQL Injection in JSON/XML/YAML Input Fields: Exploiting SQL injection within structured data inputs like JSON, XML, or YAML.
[ ] SQL Injection via HTTP Query Parameters (nested/complex): Injecting SQL into complex or deeply nested query parameters.
[ ] Time-Based Blind SQLi in Less Common DBs (e.g., SQLite, PostgreSQL specific functions): Tailoring time-based payloads for non-MySQL/MSSQL databases.
[ ] SQL Injection with Side-Channel Attacks (e.g., CPU/memory usage): Detecting subtle changes in server resource consumption indicative of successful injection.
[ ] NoSQL Injection through Template Injection (SSTI to NoSQL): Chaining SSTI vulnerabilities to achieve NoSQL injection.
B. Command Injection with Obfuscation & Evasion
[ ] Command Injection via Environmental Variables (Advanced): Exploiting cases where environment variables can be manipulated for command injection.
[ ] Command Injection with Path/Input Validation Bypass (e.g., using $ in filenames): Crafting payloads that bypass filename or path validation for command injection.
[ ] Command Injection through Arbitrary File Upload (e.g., in image metadata, custom file types): Injecting commands into file content that gets executed by a backend process.
[ ] Command Injection in Document Processors (e.g., LibreOffice, ImageMagick CVEs): Targeting specific CVEs in document or image processing libraries that lead to command injection.
[ ] Command Injection in eval()/exec() calls (dynamic code execution): Identifying and exploiting insecure use of dynamic code execution functions.
C. Data Exfiltration & Sensitive Information Leakage
[ ] Credential Leakage via Error Pages with Specific Stack Traces: Identifying detailed error pages that include database credentials or API keys in stack traces.
[ ] Unintended Debugging Mode Exposure: Detecting applications running in debug mode that expose sensitive internal information.
[ ] Log File Injection & Exposure (e.g., injecting sensitive data into logs, then viewing logs): Injecting sensitive data into application logs which are later exposed via a web interface.
[ ] Arbitrary File Download via Path Traversal with Encoding/Filtering Bypass: Advanced path traversal techniques to download sensitive files.
[ ] Exposed Sensitive Environment Variables (e.g., cloud provider credentials): Checking for exposed environment variables in JavaScript, error messages, or internal endpoints.
[ ] Database Backup File Exposure (e.g., .sql, .bak files): Detecting inadvertently exposed database backup files.
[ ] Password Policy Weakness (detecting guessable/common passwords, length limits): Identifying weak password policies that make brute-force or dictionary attacks feasible.
[ ] Information Disclosure via HTTP Headers (e.g., custom X-Powered-By, Server details): Extracting sensitive version or technology information from non-standard HTTP headers.
[ ] Sensitive Data in XML/JSON/YAML Comments: Discovering sensitive data hidden in comments within configuration files or API responses.
[ ] Client-Side Information Disclosure via Browser Developer Tools: Indicators that sensitive data is logged to the console or stored in localStorage insecurely.
V. Advanced Client-Side Vulnerabilities & Browser Exploitation
A. Deep XSS & DOM Manipulation
[ ] DOM XSS via postMessage Listener Injection: Exploiting insecure postMessage event listeners for DOM XSS.
[ ] DOM XSS in Client-Side Routers/URL Parsers: Identifying XSS vulnerabilities in how client-side routing libraries handle URL parameters.
[ ] Client-Side Template Injection (CSTI) in JavaScript Frameworks (e.g., Angular, Vue.js): Exploiting client-side template engines for XSS.
[ ] Mutation XSS (mXSS) in SVG/HTML srcset or data: attributes: Crafting complex mXSS payloads that leverage attribute parsing quirks.
[ ] XSS in WebSockets (complex message types, nested JSON): Injecting XSS payloads into sophisticated WebSocket message structures.
[ ] XSS via Blob/File URI Scheme Injection: Using blob: or file: URIs to bypass content-type restrictions and achieve XSS.
[ ] CSS Injection for Data Exfiltration (e.g., via attribute selectors and CSS properties): Exploiting CSS injection to exfiltrate sensitive data.
[ ] Content Security Policy (CSP) Bypass via eval()/setTimeout() with nonces: Identifying CSP bypasses when nonces are not properly implemented or are predictable.
[ ] CSP Bypass via Trusted Types Misconfigurations: Exploiting insecure configurations of Trusted Types.
[ ] XSS via window.name property manipulation: Exploiting vulnerabilities where window.name is used insecurely.
[ ] Client-Side Prototype Pollution Leading to CSRF Bypass: Using prototype pollution to manipulate CSRF tokens or origin checks.
[ ] Clickjacking with Scroll-Based Obfuscation: Crafting clickjacking attacks that use scroll positioning to hide malicious elements.
[ ] Clickjacking with X-Frame-Options Bypass (e.g., data: URI, SVG): Using unconventional methods to bypass X-Frame-Options.
[ ] UI Redressing (e.g., Login Overlay Attacks): Detecting scenarios where UI elements can be maliciously overlaid.
B. Advanced Browser & Web API Attacks
[ ] Web Messaging (postMessage) Vulnerabilities (Target Origin Bypass): Exploiting postMessage vulnerabilities due to incorrect target origin validation.
[ ] Service Worker Cross-Site Scripting (SW-XSS): Injecting malicious code into a service worker, leading to persistent XSS.
[ ] Service Worker Cache Poisoning: Manipulating service worker caches to deliver malicious content.
[ ] Web Push Notification Abuse (unauthorized sending): If the web app uses Web Push, checking for vulnerabilities allowing unauthorized notification sending.
[ ] WebAuthn (FIDO2) API Bypass/Misconfiguration: Detecting flaws in WebAuthn implementations that could lead to authentication bypass.
[ ] WebRTC IP Leakage (even with VPN/Proxy): Identifying configurations that allow WebRTC to leak real IP addresses.
[ ] Web Sockets with Insufficient Origin Validation: Detecting WebSockets that accept connections from any origin, making them vulnerable to cross-site attacks.
[ ] Browser Extension Vulnerabilities (if specific extensions required): While external, patterns could detect if a web app relies on a vulnerable extension.
[ ] Content Security Policy (CSP) Bypass via JSONP with Callback Manipulation: Specific JSONP callback manipulation to bypass CSP.
[ ] Client-Side Cache Poisoning (e.g., via Vary header abuse): Causing a client's browser cache to store malicious content.
[ ] Client-Side HTTP Request Smuggling (Browser-to-Proxy): Detecting subtle differences in how browsers and proxies interpret HTTP requests.
[ ] HTML Injection with Script Gadgets (using benign tags to trigger XSS): Injecting HTML that, while not directly XSS, contains elements that can be exploited by existing scripts.
[ ] Client-Side Deserialization Vulnerabilities (e.g., localStorage objects): If client-side code deserializes user-controlled data from localStorage or sessionStorage insecurely.
VI. Niche Protocol & Emerging Technology Exploitation
A. Web3 / Blockchain Interactions
[ ] Front-End Smart Contract Interaction Logic Flaws: Analyzing how the web app builds smart contract transactions for manipulation.
[ ] Decentralized Identity (DID) Misconfigurations: If using DIDs, checking for insecure implementations.
[ ] WalletConnect Session Hijacking (misconfigured dapp): Detecting vulnerabilities in WalletConnect integrations that could lead to session hijacking.
[ ] IPFS Gateway Misconfigurations (e.g., path traversal on IPFS hashes): Exploiting insecure IPFS gateway configurations.
[ ] ENS (Ethereum Name Service) Resolution Vulnerabilities: If the app resolves ENS names, checking for injection flaws.
B. GraphQL & Query Language Exploitation
[ ] GraphQL Introspection Limit Bypass: Finding ways to bypass limits on GraphQL introspection queries.
[ ] GraphQL Schema Stitching Vulnerabilities (Advanced): Exploiting complex interactions between stitched GraphQL schemas.
[ ] GraphQL N+1 Query Problem for DoS/Resource Exhaustion: Detecting GraphQL queries that lead to excessive backend database calls.
[ ] GraphQL Mutations with Missing Authorization: Identifying GraphQL mutations that lack proper authorization checks.
[ ] GraphQL Subscription Information Disclosure: Exploiting GraphQL subscriptions to receive unauthorized sensitive data in real-time.
C. Other Niche Protocols & Web Tech
[ ] WebAssembly (Wasm) Memory Corruption (if web app serves vulnerable Wasm): Identifying specific Wasm modules known to have memory corruption vulnerabilities.
[ ] WebTransport API Misuse/Vulnerabilities (e.g., unauthenticated streams): If leveraging Web Transport, checking for misuse or flaws in its implementation.
[ ] QUIC Protocol Downgrade Attacks: Attempting to force a downgrade to a less secure protocol version.
[ ] Server-Sent Events (SSE) Cross-Site Information Disclosure: Exploiting SSE to leak sensitive data across origins.
[ ] WebSockets with Insufficient Rate Limiting: Identifying WebSocket endpoints vulnerable to denial of service via excessive messages.
[ ] WebSockets with Message Replay Attacks: Detecting if WebSocket messages lack sufficient nonces or timestamps to prevent replay.
VII. Advanced Reconnaissance & Information Disclosure
A. Deep OSINT & Footprinting
[ ] Sensitive Data in Git History (exposed .git dir): Analyzing exposed Git repositories for sensitive data in commit history.
[ ] Exposed Kubernetes Kubeconfig Files: Detecting exposed .kube/config files that grant cluster access.
[ ] Internal Network Range Disclosure (e.g., in error messages, verbose logs): Extracting internal IP ranges from various application responses.
[ ] Employee Email/Username Enumeration (e.g., via "Forgot Password" or registration flows): Identifying valid employee accounts.
[ ] Exposed .ssh directories or SSH keys: Detecting exposed SSH configuration or private keys.
[ ] Configuration Management Files (e.g., Ansible, Puppet, Chef) Exposure: Identifying exposed configuration management files that reveal infrastructure details.
[ ] Database Schema Disclosure (e.g., via specific error messages or debug endpoints): Detailed database schema information leaked.
[ ] Hardcoded AWS/Azure/GCP Access Keys/Secrets in JS/Config Files: Actively looking for cloud provider credentials.
[ ] Software Bill of Materials (SBOM) Exposure via /sbom.json or similar paths: Automated detection of SBOMs for deeper dependency analysis.
[ ] Exposed OpenAPI/Swagger/Postman Collection files (sensitive endpoints/params): Finding API documentation files that expose sensitive or internal endpoints.
[ ] Server-Side Rendering (SSR) Context Information Leakage: If SSR, looking for accidentally exposed server-side context data.
[ ] Legacy/Deprecated API Endpoint Discovery: Using wordlists and historical data to find old API versions that might be less secure.
[ ] HTTP Request History Files (e.g., curl_history, wget-log): Detecting inadvertently exposed command history files.
[ ] Exposed .htaccess or web.config files revealing sensitive rewrite rules/auth: Finding web server configuration files that might reveal bypass opportunities.
[ ] Sensitive Data in Application Logs (e.g., usernames, emails, internal IDs): Scanning for directly exposed application logs with PII or other sensitive data.
[ ] Information Disclosure via GraphQL Introspection (filtered but bypassable): Even with introspection filters, finding ways to extract partial schema info.
[ ] Exposed /metrics endpoints (e.g., Prometheus, Grafana, exposing internal metrics): Detecting monitoring endpoints with sensitive system metrics.
[ ] Sensitive Data in CDN Edge Cache (e.g., miscached authenticated content): Checking for sensitive data being inadvertently cached by CDNs.
B. Advanced Fingerprinting & Version Detection
[ ] Component Version Fingerprinting (Nth-degree precision): Detecting specific patch versions of libraries and frameworks to correlate with known CVEs.
[ ] Operating System Fingerprinting (via specific error messages, headers, or file paths): Inferring the underlying OS.
[ ] Database Server Fingerprinting (specific versions/builds): Detailed database version identification.
[ ] Load Balancer/Proxy Fingerprinting (specific vendor/version): Identifying specific load balancer or proxy technologies.
[ ] Container Runtime Fingerprinting (e.g., Docker, Containerd, CRI-O): Inferring the container runtime used.
[ ] Virtualization Technology Fingerprinting (e.g., VMWare, KVM indicators): Detecting virtualization platforms through subtle clues.
[ ] Endpoint Functionality Fingerprinting (e.g., if it's an upload, login, search, etc.): Categorizing endpoints by functionality.
[ ] Language/Framework Specific Default Files/Paths: Detecting common default files/paths for specific languages/frameworks (e.g., struts2-showcase.war).
[ ] Cloud Provider Service Fingerprinting (e.g., specific AWS SQS/SNS endpoints): Identifying explicit cloud service endpoints in use.
[ ] Backend Caching Mechanism Fingerprinting (e.g., Redis, Memcached indicators): Detecting the presence of specific caching layers.
VIII. Advanced Authentication & Authorization Bypasses
A. SSO, OAuth, & JWT Deep Dives
[ ] OAuth PKCE (Proof Key for Code Exchange) Downgrade: Exploiting implementations that fail to enforce PKCE properly.
[ ] OAuth State Parameter Misuse (CSRF Bypass): Detecting scenarios where the OAuth state parameter isn't properly validated against CSRF.
[ ] JWT Algorithm Confusion (e.g., HS256 to RS256 bypass): Exploiting JWT signature verification flaws.
[ ] JWT Header Injection (e.g., jku, x5u for key material injection): Exploiting injection flaws in JWT header parameters.
[ ] JWT Weak Secret Detection (Brute-Force/Dictionary Attack): Attempting to brute-force weak JWT secrets.
[ ] SSO Logout Functionality Bypass: Detecting if logging out of the application doesn't properly invalidate the SSO session.
[ ] OAuth Client ID/Secret Misuse (for unauthorized token generation): Exploiting exposed or weak OAuth client credentials.
[ ] SAML Assertion Signature Bypass (e.g., XML signature wrapping): Detecting advanced SAML vulnerabilities.
[ ] OpenID Connect ID Token Validation Bypass: Exploiting flaws in ID token validation (e.g., nonce replay).
B. MFA & Session Management Nuances
[ ] MFA Bypass via Recovery Code Replay: Exploiting recovery codes that can be reused multiple times.
[ ] MFA Bypass via "Remember Me" Token Impersonation: If MFA doesn't apply to "remember me" tokens.
[ ] MFA Bypass via Insufficient Rate Limiting on Code Entry: Brute-forcing MFA codes.
[ ] Session Cookie Cross-Site Leakage (via subdomains or permissive domain attribute): Detecting session cookies visible to other subdomains.
[ ] Session Management via URL Rewriting (cookie-less sessions): Identifying and testing cookie-less session management for fixation or prediction.
[ ] Session Fixation through Predictable Session ID Generation (after unauthenticated action): Detecting weak session ID generation during unauthenticated phases.
[ ] Session Invalidation Flaws (e.g., after password change, still active): Detecting sessions that remain valid after a password change.
C. Access Control Bypasses (Contextual & Logic-Based)
[ ] Broken Access Control via HTTP Headers (e.g., X-Original-URL, X-Rewrite-URL): Manipulating request headers to bypass access controls.
[ ] Access Control Bypass via HTTP Method/Verb Tampering (e.g., POST instead of GET on admin functions): Testing different HTTP methods on restricted endpoints.
[ ] Broken Object Level Authorization (BOLA) in Batch/Bulk Endpoints: Exploiting BOLA when multiple objects can be requested in a single call.
[ ] BOLA via Nested Objects/Complex IDs: Exploiting BOLA in deeply nested JSON structures or using complex UUIDs/hashes.
[ ] BOLA via Parameter Pollution (e.g., id=1&id=2): Using parameter pollution to access unauthorized objects.
[ ] Context-Dependent Authorization Bypass (e.g., function accessible via specific referrer): Access control that depends on the context of the request (e.g., Referer header).
[ ] Role Manipulation via Client-Side Storage (e.g., localStorage, sessionStorage): Attempting to change user roles stored client-side.
[ ] Privilege Escalation via User Impersonation (e.g., by changing a user ID in the request): Attempting to impersonate other users by modifying user IDs.
[ ] Access Control Bypass via Insecure Redirects (e.g., redirecting to privileged pages): Leveraging open redirects to bypass access controls.
[ ] Directory Traversal for Authorization Bypass (e.g., accessing sibling directories for sensitive content): Using directory traversal not just for LFI, but to bypass authorization.
IX. Advanced Business Logic & Race Conditions
A. Deeper Business Logic Flaws
[ ] Price Manipulation via Client-Side Parameters (hidden inputs, JS manipulation): Modifying prices or quantities in client-side parameters.
[ ] Discount Code Abuse (e.g., reuse, stacking, invalid codes): Exploiting flaws in discount code validation.
[ ] Inventory Manipulation/Over-Purchase: Exploiting logic flaws to purchase more items than available or intended.
[ ] Gift Card/Voucher Code Brute-Force/Prediction: Attempting to guess or predict valid gift card codes.
[ ] Refund/Credit Abuse: Exploiting flaws in refund or credit issuance mechanisms.
[ ] Voting/Polling System Abuse (e.g., multiple votes from one user, vote manipulation): Bypassing controls in voting systems.
[ ] User Registration/Account Creation Logic Flaws (e.g., creating admin accounts, bypassing email verification): Exploiting weaknesses in account creation.
[ ] Feature Flag Bypass/Abuse: Gaining access to unreleased or restricted features by manipulating feature flags.
[ ] Referral Program Abuse (e.g., self-referral for credits): Exploiting referral programs for illicit gains.
[ ] Subscription Downgrade/Upgrade Bypass: Changing subscription tiers without proper validation.
[ ] Loyalty Program/Points Manipulation: Exploiting flaws in loyalty points systems.
[ ] Account Recovery Process Abuse (e.g., bypassing security questions): Exploiting weaknesses in account recovery.
[ ] Payment Gateway Integration Flaws (e.g., skipping payment step, manipulating callback): Identifying flaws in payment gateway integrations.
[ ] Cross-User Data Manipulation via Shared References: If an object ID refers to data shared between users, exploiting logic to manipulate another user's data.
B. Sophisticated Race Conditions
[ ] Race Condition in Session Token Generation: Exploiting a race condition where multiple login attempts could yield the same session token.
[ ] Race Condition for Unauthorized File Overwrite: Exploiting a race to overwrite a file before permissions are applied.
[ ] Race Condition in Resource Allocation (e.g., limited seats, unique IDs): Exploiting race conditions on limited resources.
[ ] Race Condition in Password Reset Token Generation/Validation: Exploiting timing windows in password reset flows.
[ ] Race Condition in Account Deletion/Dormancy: Exploiting race conditions during account state changes.
[ ] Race Condition in API Rate Limiting Enforcement: Sending bursts of requests to bypass eventual consistency rate limits.
[ ] Race Condition in Financial Transaction Confirmation: Exploiting timing between payment initiation and confirmation.
X. Advanced Web Server & Configuration Vulnerabilities
A. Web Server & Reverse Proxy Deep Misconfigurations
[ ] Nginx/Apache Alias Traversal: Exploiting misconfigured aliases that allow directory traversal.
[ ] Nginx/Apache Proxy Pass Misconfigurations (e.g., proxy_pass to internal IPs): Detecting proxy_pass directives pointing to internal services.
[ ] CORS Misconfigurations (complex scenarios like multiple Access-Control-Allow-Origin headers): Detecting intricate CORS policy flaws.
[ ] HTTP Request Smuggling (Advanced Transfer-Encoding/Content-Length combinations): More complex request smuggling techniques.
[ ] Web Cache Deception with Authentication Bypass: Tricking caching mechanisms to serve authenticated content to unauthenticated users.
[ ] Web Cache Poisoning with Header Splitting: Injecting malicious headers to poison the cache for other users.
[ ] CRLF Injection in Response Headers for Cache Poisoning: Injecting CRLF into user-controlled input to manipulate HTTP response headers.
[ ] HTTP Host Header Attacks (Password Reset Poisoning via crafted Host header): Exploiting Host header for password reset poisoning.
[ ] DNS Rebinding Attacks (Server-Side for internal network access): Exploiting DNS rebinding in server-side contexts for internal network access.
[ ] Web Server Specific Default Pages/Files (e.g., IIS default pages, Apache test pages): Detecting default installations that provide information.
[ ] Exposed Configuration Files (e.g., nginx.conf, httpd.conf, haproxy.cfg if exposed): Finding web server configuration files that disclose sensitive information.
[ ] Server Status Page Exposure (e.g., Apache mod_status, Nginx stub_status): Detecting exposed server status pages.
B. Certificate & TLS/SSL Misconfigurations
[ ] Expired/Self-Signed SSL Certificates (with clear warnings): Detecting improperly configured SSL certificates.
[ ] Weak SSL/TLS Cipher Suites (e.g., RC4, 3DES): Identifying the use of weak cryptographic cipher suites.
[ ] Missing Strict-Transport-Security (HSTS) Header: Detecting the absence of HSTS for secure connections.
[ ] SSL/TLS Heartbleed/CCS Injection (if older versions detected): Detecting historical but critical SSL/TLS vulnerabilities.
[ ] Client-Side Certificate Validation Bypass: If client certificates are used, detecting flaws in their validation.
[ ] Wildcard Certificate Misuse (e.g., covering unintended subdomains): Identifying wildcard certs used for overly broad coverage.
XI. Advanced Input Validation & Encoding Bypass
[ ] Double Encoding Bypass: Testing payloads that require multiple layers of URL encoding to bypass filters.
[ ] Unicode Encoding Bypass: Using Unicode characters to bypass input validation filters.
[ ] Null Byte Injection (%00) for Path/Extension Bypass: Injecting null bytes to terminate strings and bypass filename or path checks.
[ ] Padding Oracle Attack Vulnerabilities (if applicable to encryption scheme): Detecting vulnerabilities in padding schemes used for encryption.
[ ] Blind XSS with Delayed OOB Interaction (e.g., via image loading or script tags in logs): Using OOB interactions to confirm blind XSS.
[ ] XSS in PDF Generators (if converting user input to PDF): Injecting XSS into PDF generation processes.
[ ] Header Injection in Backend Calls (e.g., for SSRF, SQLi): Injecting malicious headers into backend HTTP calls.
[ ] HTML Entity Encoding Bypass (e.g., &#xNN; vs. &lt;): Using various HTML entity encoding forms to bypass XSS filters.
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
