# Security Scan Patterns — NPC Chile Project
## Tech Stack: Java 11 · Struts 1.x · EJB 3 · RESTEasy JAX-RS · JWT · Angular 19 · MySQL · Oracle · Maven

---

## HOW GREP PATTERNS WERE DECIDED

```
Tech Stack Detected → Known Vulnerability Surface → Targeted Regex
─────────────────────────────────────────────────────────────────
Java + JDBC          → SQL Injection          → Statement / executeQuery / concat
JAX-RS REST          → Info Disclosure        → setException / printStackTrace / entity
JWT (jjwt)           → Weak Secret            → stringKey / hardcoded secret
AES/PBE Crypto       → Weak Cipher            → PBEWithMD5 / getInstance("DES")
Struts FormFile      → File Upload            → getFileName / extension / size only
CorsFilter (servlet) → CORS misconfig         → Access-Control-Allow-Origin / *
Angular SPA          → XSS / token storage    → localStorage / innerHTML / bypassSecurity
Maven pom.xml        → Outdated components    → struts / axis2 / catalina / xerces
```

---

## PART 1 — GREP PATTERNS (for grep / VS Code Search / rg)

### A01 — Broken Access Control

```
# No role annotations on REST endpoints
grep -rn "@PermitAll\|@RolesAllowed\|@DenyAll" --include="*.java"

# JWT bypass list (unauthenticated URLs)
grep -rn "startsWith\|equals.*getRequestURI\|requestUri" --include="*.java"

# Session not invalidated on logout
grep -rn "invalidate\(\)\|logout\|logoff" --include="*.java"

# Direct object reference using user-supplied IDs
grep -rn "getParameter\|getPortId\|getPortData.*request" --include="*.java"
```

---

### A02 — Cryptographic Failures

```
# Weak hash algorithms
grep -rn "getInstance\(\"MD5\"\)\|getInstance\(\"SHA-1\"\)\|getInstance\(\"SHA1\"\)" --include="*.java"

# Broken symmetric ciphers
grep -rn "getInstance\(\"DES\"\)\|getInstance\(\"RC4\"\)\|PBEWithMD5AndDES" --include="*.java"

# Hardcoded secrets / keys
grep -rn "stringKey\s*=\|private.*key\s*=\s*\"\|private.*KEY\s*=" --include="*.java"

# Static IV (same as key)
grep -rn "IvParameterSpec.*key\.getBytes\|IvParameterSpec.*getBytes" --include="*.java"

# Insecure random
grep -rn "new Random()\|Math\.random()" --include="*.java"

# Cookies missing flags
grep -rn "setHttpOnly\|setSecure\|addCookie\|new Cookie" --include="*.java"

# HTTP not forced
grep -rn "setSecure(false)\|CONFIDENTIAL\|transport-guarantee" --include="*.xml"
```

---

### A03 — Injection

```
# SQL string concatenation (SQLi)
grep -rn "\"SELECT\|\"INSERT\|\"UPDATE\|\"DELETE" --include="*.java" | grep "\+"
grep -rn "String.*sql.*=.*+\|String.*query.*=.*+" --include="*.java"

# Unparameterized statements
grep -rn "createStatement()\|executeQuery(sql)\|executeUpdate(sql)" --include="*.java"

# XXE — XMLInputFactory without disabling external entities
grep -rn "XMLInputFactory\.newInstance()\|DocumentBuilderFactory\.newInstance()" --include="*.java"
grep -rn "IS_SUPPORTING_EXTERNAL_ENTITIES\|FEATURE_SECURE_PROCESSING" --include="*.java"

# LDAP injection (if used)
grep -rn "DirContext\|InitialDirContext\|NamingEnumeration" --include="*.java"

# Command injection
grep -rn "Runtime\.getRuntime()\.exec\|ProcessBuilder\|new ProcessBuilder" --include="*.java"
```

---

### A04 — Insecure Design

```
# No rate limiting / account lockout
grep -rn "failedAttempt\|lockout\|maxAttempts\|rateLim\|throttle" --include="*.java"

# No CSRF token
grep -rn "csrf\|CSRF\|CsrfToken\|_csrf\|X-CSRF" --include="*.java"

# Business logic: file extension from filename string only
grep -rn "replaceAll.*\\\\.\|split.*\"\\.\".*\\[" --include="*.java"
```

---

### A05 — Security Misconfiguration

```
# All security response headers (should be present, flag if missing)
grep -rn "X-Frame-Options\|X-Content-Type-Options\|X-XSS-Protection\|Content-Security-Policy\|Strict-Transport-Security" --include="*.java"

# CORS wildcard
grep -rn "Access-Control-Allow-Origin.*\*\|addHeader.*\*" --include="*.java"

# OPTIONS method returning 202 without checking
grep -rn "OPTIONS\|SC_ACCEPTED" --include="*.java"

# Debug mode / verbose error
grep -rn "printStackTrace\|e\.getMessage()\|ex\.toString()" --include="*.java"

# Axis2 admin services exposed
grep -rn "AdminAgent\|axis2-admin\|services/list" --include="*.xml"
```

---

### A06 — Vulnerable and Outdated Components

```
# In pom.xml — EOL / vulnerable versions
grep -n "struts.*1\.\|catalina.*5\.\|catalina.*6\.\|axis2.*1\.6\|xerces.*2\.[0-8]\|castor-xml\|commons-collections.*3\." pom.xml

# All dependency versions in one pass
grep -n "<version>" NPCParent/pom.xml

# Angular — check package.json for old versions
grep -n "\"@angular/core\"\|\"primeng\"\|\"rxjs\"" NPCParent/NPCAdminGUIApp/package.json
grep -n "\"@angular/core\"\|\"primeng\"\|\"rxjs\"" NPCParent/NPCWebGUIApp/package.json
```

---

### A07 — Identification and Authentication Failures

```
# Hardcoded default credentials
grep -rn "\"npc\"\|\"admin\"\|\"password\"\|\"secret\"\|\"test123\"" --include="*.java"

# Default password fallback in getString()
grep -rn "getString.*password.*\"npc\"\|getProperty.*password.*\"" --include="*.java"

# JWT secret hardcoded
grep -rn "stringKey\s*=\s*\"\|jwtSecret\s*=\s*\"" --include="*.java"

# No session timeout configuration
grep -rn "setMaxInactiveInterval\|session-timeout" --include="*.xml" --include="*.java"

# Password in plaintext log
grep -rn "log.*password\|logger.*password\|print.*password" --include="*.java"
```

---

### A08 — Software and Data Integrity Failures

```
# Insecure deserialization
grep -rn "ObjectInputStream\|readObject()\|enableDefaultTyping" --include="*.java"

# Serializable classes (attack surface for gadget chains)
grep -rn "implements Serializable\|implements java\.io\.Serializable" --include="*.java"

# Jackson default typing (polymorphic deserialization)
grep -rn "enableDefaultTyping\|OBJECT_AND_NON_CONCRETE\|NON_FINAL" --include="*.java"
```

---

### A09 — Security Logging and Monitoring Failures

```
# Exception swallowed silently
grep -rn "catch.*Exception.*{$\|} catch.*{ *}" --include="*.java"

# Exception printed to stdout (not logger)
grep -rn "System\.out\.print\|e\.printStackTrace()" --include="*.java"

# Raw exception sent to client
grep -rn "setException(ex)\|entity.*exception\|setException(e)" --include="*.java"

# SQL error details exposed
grep -rn "getSQLState()\|getErrorCode()\|getVendorCode()" --include="*.java"
```

---

### A10 — SSRF

```
# HTTP client calls with user-controlled URLs
grep -rn "HttpClient\|CloseableHttpClient\|HttpURLConnection\|URL.*open\|new URL(" --include="*.java"

# URL from config / property (check if externally writable)
grep -rn "getProperty.*[Uu]rl\|getProperty.*[Hh]ost\|getProperty.*[Ee]ndpoint" --include="*.java"

# Axis2 client stubs (SOAP endpoint configurable)
grep -rn "ServiceStub\|setTargetEPR\|EndpointReference" --include="*.java"
```

---

### File Upload — No Type Validation

```
# Extension from filename string only (no MIME / magic bytes check)
grep -rn "getFileName().*extension\|replaceAll.*\\\\.\|split.*\"\\.\"\|\.endsWith(\"\." --include="*.java"

# No content-type check on uploaded files
grep -rn "getContentType\|getMimeType\|magic\|tika\|probeContentType" --include="*.java"

# Struts FormFile (legacy upload, no built-in type check)
grep -rn "FormFile\|getInputStream\|getFileData" --include="*.java"

# File stored with original name (path traversal risk)
grep -rn "getFileName()\|tmpFileName\|getTmpFileName" --include="*.java"
```

---

### Angular / Frontend Patterns

```
# XSS — unsafe DOM manipulation
grep -rn "innerHTML\|outerHTML\|document\.write\|bypassSecurityTrust" --include="*.ts" --include="*.html"

# Token stored in localStorage (XSS-accessible)
grep -rn "localStorage\.set\|sessionStorage\.set\|localStorage\[" --include="*.ts"

# Hardcoded API URLs / endpoints
grep -rn "http://\|https://.*localhost\|baseUrl.*=.*'" --include="*.ts"

# No sanitization on user input binding
grep -rn "\[innerHTML\]\|DomSanitizer\|sanitize" --include="*.ts" --include="*.html"
```

---

## PART 2 — SEMGREP RULES

> Run: `semgrep --config semgrep-npc-rules.yaml NPCParent/`

```yaml
rules:

  # ─────────────────────────────────────────────
  # A02 — Hardcoded JWT Secret
  # ─────────────────────────────────────────────
  - id: hardcoded-jwt-secret
    pattern: |
      String $KEY = "...";
      byte[] $ENC = Base64.getEncoder().encode($KEY.getBytes());
      SecretKey $SK = new SecretKeySpec($ENC, 0, $ENC.length, "AES");
    message: "Hardcoded JWT signing key — rotate immediately and load from env/vault"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A02

  # ─────────────────────────────────────────────
  # A02 — Static IV = Key (AES/CBC)
  # ─────────────────────────────────────────────
  - id: static-iv-equals-key
    pattern: |
      private final String $KEY = "...";
      ...
      IvParameterSpec $IV = new IvParameterSpec($KEY.getBytes(...));
      SecretKeySpec $SPEC = new SecretKeySpec($KEY.getBytes(...), "AES");
    message: "IV is identical to key — static IV defeats CBC mode entirely"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A02

  # ─────────────────────────────────────────────
  # A02 — Broken PBEWithMD5AndDES
  # ─────────────────────────────────────────────
  - id: broken-pbe-md5-des
    pattern: SecretKeyFactory.getInstance("PBEWithMD5AndDES")
    message: "PBEWithMD5AndDES uses broken MD5 + DES — use AES-256 with PBKDF2WithHmacSHA256"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A02

  # ─────────────────────────────────────────────
  # A02 — MD5 for hashing
  # ─────────────────────────────────────────────
  - id: weak-hash-md5
    pattern: MessageDigest.getInstance("MD5")
    message: "MD5 is cryptographically broken — use SHA-256 minimum"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A02

  # ─────────────────────────────────────────────
  # A02 — Insecure Random (not SecureRandom)
  # ─────────────────────────────────────────────
  - id: insecure-random
    patterns:
      - pattern: new Random()
      - pattern-not-inside: |
          // ... test ...
    message: "java.util.Random is not cryptographically secure — use SecureRandom"
    languages: [java]
    severity: WARNING
    metadata:
      owasp: A02

  # ─────────────────────────────────────────────
  # A03 — SQL String Concatenation
  # ─────────────────────────────────────────────
  - id: sql-string-concat
    patterns:
      - pattern: |
          String $SQL = "..." + $VAR + "...";
          ...
          $STMT.executeQuery($SQL);
      - pattern: |
          String $SQL = "..." + $VAR + "...";
          ...
          $STMT.execute($SQL);
    message: "SQL built with string concatenation — use PreparedStatement with ? parameters"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A03

  # ─────────────────────────────────────────────
  # A03 — XXE: XMLInputFactory without disabling external entities
  # ─────────────────────────────────────────────
  - id: xxe-xmlinputfactory
    patterns:
      - pattern: XMLInputFactory.newInstance()
      - pattern-not-inside: |
          XMLInputFactory $F = XMLInputFactory.newInstance();
          ...
          $F.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    message: "XMLInputFactory allows external entities by default — set IS_SUPPORTING_EXTERNAL_ENTITIES=false"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A03

  # ─────────────────────────────────────────────
  # A05 — CORS Wildcard in Response
  # ─────────────────────────────────────────────
  - id: cors-wildcard-response
    pattern: |
      Response.ok(...).header("Access-Control-Allow-Origin", "*")...
    message: "Wildcard CORS on authenticated endpoint — specify exact allowed origin"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A05

  # ─────────────────────────────────────────────
  # A05 — Missing Security Headers
  # ─────────────────────────────────────────────
  - id: missing-xframe-options
    patterns:
      - pattern: |
          public void doFilter(...) {
            ...
            chain.doFilter(...);
          }
      - pattern-not: |
          $RESP.addHeader("X-Frame-Options", ...);
    message: "CorsFilter / security filter does not set X-Frame-Options header"
    languages: [java]
    severity: WARNING
    metadata:
      owasp: A05

  # ─────────────────────────────────────────────
  # A07 — Hardcoded Default Password
  # ─────────────────────────────────────────────
  - id: hardcoded-default-password
    pattern: getString("systemPassword", "npc")
    message: "Hardcoded default password 'npc' — remove default value, require explicit config"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A07

  # ─────────────────────────────────────────────
  # A07 — Cookie missing HttpOnly / Secure flags
  # ─────────────────────────────────────────────
  - id: cookie-missing-httponly
    patterns:
      - pattern: |
          Cookie $C = new Cookie(...);
          ...
          $RESP.addCookie($C);
      - pattern-not: |
          $C.setHttpOnly(true);
    message: "Cookie created without setHttpOnly(true) — vulnerable to XSS token theft"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A07

  # ─────────────────────────────────────────────
  # A09 — Exception Object Serialized into REST Response
  # ─────────────────────────────────────────────
  - id: exception-in-rest-response
    pattern: |
      $STATUS.setException($EX);
      ...
      return Response.status(...).entity($STATUS).build();
    message: "Exception object set in response DTO — Jackson will serialize stacktrace into JSON"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A09

  # ─────────────────────────────────────────────
  # A09 — printStackTrace to stdout
  # ─────────────────────────────────────────────
  - id: print-stack-trace
    pattern: $E.printStackTrace()
    message: "printStackTrace() writes to stdout — use logger.error('msg', e) instead"
    languages: [java]
    severity: WARNING
    metadata:
      owasp: A09

  # ─────────────────────────────────────────────
  # Path Traversal — User input into File constructor
  # ─────────────────────────────────────────────
  - id: path-traversal-file-constructor
    patterns:
      - pattern: |
          String $NAME = $OBJ.getLinkName();
          ...
          File $F = new File($NAME);
      - pattern-not: |
          $F.getCanonicalPath()
    message: "User-supplied path used in File() with no canonical path check — path traversal risk"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A01

  # ─────────────────────────────────────────────
  # File Upload — Extension only validation (no MIME/magic)
  # ─────────────────────────────────────────────
  - id: file-upload-extension-only
    pattern: |
      String $EXT = $FILENAME.replaceAll("^.*\\.", "");
      ...
      ProductProperties.getProperty($EXT + ".max_attachments_size");
    message: "File type validated by extension string only — no MIME or magic bytes check"
    languages: [java]
    severity: WARNING
    metadata:
      owasp: A04

  # ─────────────────────────────────────────────
  # A06 — Struts 1.x (EOL)
  # ─────────────────────────────────────────────
  - id: struts1-dependency
    pattern: |
      <artifactId>struts</artifactId>
      <version>1.$VERSION</version>
    message: "Struts 1.x is End-of-Life since 2013 with multiple unpatched CVEs — upgrade to Spring MVC or Struts 2.x+"
    languages: [xml]
    severity: ERROR
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A06 — Catalina 5.x / 6.x (EOL)
  # ─────────────────────────────────────────────
  - id: tomcat-eol-version
    patterns:
      - pattern: |
          <artifactId>catalina</artifactId>
          <version>5.$V</version>
      - pattern: |
          <artifactId>catalina-ant</artifactId>
          <version>6.$V</version>
    message: "Tomcat Catalina 5.x/6.x is End-of-Life — update to Tomcat 10.x+"
    languages: [xml]
    severity: ERROR
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A08 — Serializable class (gadget chain risk with commons-collections)
  # ─────────────────────────────────────────────
  - id: serializable-domain-object
    patterns:
      - pattern: |
          public class $C implements Serializable { ... }
      - pattern-not: |
          private static final long serialVersionUID = ...;
    message: "Serializable domain object without serialVersionUID — review for deserialization gadget chain risk"
    languages: [java]
    severity: INFO
    metadata:
      owasp: A08
```

---

## PART 3 — QUICK REFERENCE: OWASP → GREP → SEMGREP

| OWASP | Finding in This Project | Grep Pattern | Semgrep Rule ID |
|---|---|---|---|
| A01 | Unauthenticated file endpoints | `startsWith.*sgp-support\|ListofReports` | `path-traversal-file-constructor` |
| A02 | Hardcoded JWT key | `stringKey\s*=\s*"` | `hardcoded-jwt-secret` |
| A02 | Static IV = Key | `IvParameterSpec.*key\.getBytes` | `static-iv-equals-key` |
| A02 | PBEWithMD5AndDES | `PBEWithMD5AndDES` | `broken-pbe-md5-des` |
| A02 | MD5 hashing | `getInstance\("MD5"\)` | `weak-hash-md5` |
| A02 | `new Random()` in CAPTCHA | `new Random\(\)\|Math\.random` | `insecure-random` |
| A02 | Cookie no HttpOnly/Secure | `setHttpOnly\|setSecure` | `cookie-missing-httponly` |
| A03 | SQL string concat | `String.*sql.*=.*+` | `sql-string-concat` |
| A03 | XXE XMLInputFactory | `XMLInputFactory\.newInstance\(\)` | `xxe-xmlinputfactory` |
| A04 | No CSRF protection | `csrf\|CsrfToken` (absent) | — |
| A04 | File ext-only validation | `replaceAll.*\\\\.` | `file-upload-extension-only` |
| A05 | CORS wildcard active | `Access-Control-Allow-Origin.*\*` | `cors-wildcard-response` |
| A05 | All security headers off | `X-Frame-Options\|X-XSS` (commented) | `missing-xframe-options` |
| A06 | Struts 1.2.9 | `struts.*1\.` in pom.xml | `struts1-dependency` |
| A06 | Catalina 5.5 / 6.0 | `catalina.*5\.\|catalina.*6\.` | `tomcat-eol-version` |
| A07 | Default password "npc" | `systemPassword.*"npc"` | `hardcoded-default-password` |
| A07 | No login rate limit | `failedAttempt\|lockout` (absent) | — |
| A08 | Serializable + commons-collections | `implements Serializable` | `serializable-domain-object` |
| A09 | Exception in JSON response | `setException\(ex\)` | `exception-in-rest-response` |
| A09 | printStackTrace | `printStackTrace\(\)` | `print-stack-trace` |
| A10 | SSRF via Axis2 stubs | `ServiceStub\|setTargetEPR` | — |

---

## PART 4 — HOW GREP PATTERNS WERE DECIDED (Decision Logic)

```
Java + JDBC detected
  └─► grep: Statement / createStatement / executeQuery + concat → SQLi surface

RESTEasy JAX-RS + Jackson detected
  └─► grep: setException / entity(status) → exception serialization leak
  └─► grep: Response.ok().header("Access-Control") → CORS on REST

JWT (io.jsonwebtoken) detected
  └─► grep: stringKey= / Base64.encode / SecretKeySpec → hardcoded secret check

Crypto (javax.crypto) detected
  └─► grep: getInstance("MD5") / getInstance("DES") / PBEWithMD5 → broken algo check
  └─► grep: IvParameterSpec + same key → static IV check

Struts 1.x FormFile detected
  └─► grep: getFileName / getContentType / extension → upload validation check
  └─► grep: FormFile / getInputStream → no magic bytes

CorsFilter (servlet Filter) detected
  └─► grep: addHeader / Access-Control / X-Frame / setSecure → header audit

Maven pom.xml detected
  └─► grep: version tags for struts/catalina/axis2/xerces/castor → EOL check

Angular (package.json) detected
  └─► grep: innerHTML / localStorage / bypassSecurityTrust → XSS surface

EJB + Serializable detected
  └─► grep: implements Serializable + commons-collections version → gadget chain risk
```

---

*Generated by GitHub Copilot security scan — 2026-08-05*
*Run Semgrep rules: `semgrep --config SECURITY_SCAN_PATTERNS.md NPCParent/`*
