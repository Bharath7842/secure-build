# Security Scan Patterns — NPG Pakistan Project
## Tech Stack: Java 21 · Jakarta EE (EJB 4 · JAX-RS · JAX-WS) · Apache CXF 4 · JBoss/WildFly · Oracle JDBC · Castor XML · Angular 21 · JWT (RSA) · Bucket4j · Maven

---

## HOW GREP PATTERNS WERE DECIDED

```
Tech Stack Detected → Known Vulnerability Surface → Targeted Regex
─────────────────────────────────────────────────────────────────
Java 21 + JDBC (ojdbc10)   → SQL Injection           → sqlString += / prepareStatement verify
Apache CXF 4 SOAP          → SSRF / XXE              → XMLInputFactory / getProperty.*Url / SOAPClient
JAX-RS REST (Jakarta EE)   → Info Disclosure         → setException / printStackTrace / entity
JWT (jjwt RSA keypair)     → Key path traversal      → getSafeKeyPath / JWT_KEY_DIRECTORY
AES-GCM Crypto             → Verify correct use      → AESGCMEncrypter / SecureRandom
java.util.Random           → Weak random             → new Random() in security context
Castor XML 1.4.1           → Deserialization         → Unmarshaller / unmarshal / org.exolab
Runtime.exec               → Command injection       → RecursiveSearch / getRuntime().exec
Angular 21 SPA             → Token storage / XSS    → sessionStorage / localStorage / innerHTML
Inline CORS header         → CORS bypass             → Access-Control-Allow-Origin.*\*  (REST layer)
Maven pom.xml              → Outdated components     → castor / commons-validator / woodstox / wsdl4j
```

---

## PART 1 — GREP PATTERNS (for grep / VS Code Search / rg)

### A01 — Broken Access Control

```
# No role annotations on REST endpoints (Jakarta EE JAX-RS)
grep -rn "@RolesAllowed\|@PermitAll\|@DenyAll" --include="*.java"

# JWT bypass via public-endpoint allow-list — verify list is minimal
grep -rn "publicEndpoints\|DEFAULT_PUBLIC_ENDPOINTS\|jwt_public_endpoints" --include="*.java"

# Inline Access-Control-Allow-Origin: * in REST services BYPASSES CORSFilter
# Confirmed: UserService.java (5 occurrences), WorklistService.java
grep -rn "Access-Control-Allow-Origin.*\*\|header.*Access-Control.*\*" --include="*.java"

# Session token created with java.util.Random (guessable)
# Confirmed: SecurityMgrImpl.java line 553
grep -rn "new Random\(\)\.nextInt\|Integer\.toString.*new Random" --include="*.java"

# Direct object reference via request-supplied IDs
grep -rn "getPortId\|getPortData\|getObjectId\|objectId.*request" --include="*.java"
```

---

### A02 — Cryptographic Failures

```
# Weak hash algorithms
grep -rn "getInstance\(\"MD5\"\)\|getInstance\(\"SHA-1\"\)\|getInstance\(\"SHA1\"\)" --include="*.java"

# Broken symmetric ciphers
grep -rn "getInstance\(\"DES\"\)\|getInstance\(\"RC4\"\)\|PBEWithMD5AndDES" --include="*.java"

# java.util.Random in security-sensitive code (not SecureRandom)
# Confirmed: SecurityMgrImpl.java line 553 (session random string)
grep -rn "new Random()\|Math\.random()" --include="*.java"

# AES-GCM usage — verify SecureRandom IV and key length
# Correct usage found in: AESGCMEncrypter.java, AESEncryptionDecryption.java, DBPasswordEnc.java
grep -rn "AESGCMEncrypter\|GCMParameterSpec\|new SecureRandom" --include="*.java"

# JWT RSA key directory — verify path-traversal safeguard (getSafeKeyPath is present)
grep -rn "JWT_KEY_DIRECTORY\|getSafeKeyPath\|jwt_private_key_path\|jwt_public_key_path" --include="*.java"

# Token stored in sessionStorage (XSS-accessible, but better than localStorage)
grep -rn "sessionStorage\.setItem\|sessionStorage\.getItem\|localStorage\.set" --include="*.ts"

# Cookies missing HttpOnly / Secure flags
grep -rn "setHttpOnly\|setSecure\|addCookie\|new Cookie" --include="*.java"
```

---

### A03 — Injection

```
# SQL string concatenation — xnp/db/* uses sqlString += getDefaultWhere()
# Pattern: sqlString built with append/+= before prepareStatement
grep -rn "sqlString.*+=\|sqlString.*+\s" --include="*.java"
grep -rn "String.*sql.*=.*+\|String.*query.*=.*+" --include="*.java"

# Unparameterized statements
grep -rn "createStatement()\|executeQuery(sql)\|executeQuery(query)\|executeUpdate(sql)" --include="*.java"

# Verify all xnp/db/* statements use prepareStatement (should all pass)
grep -rn "prepareStatement\|setString\|setInt\|setObject" NPGParent/NPG/src/main/java/com/telcordia/xnp/db/

# XXE — DocumentBuilderFactory without disabling external entities
# Confirmed in: NPGRepositorySelector.java (line 61)
grep -rn "DocumentBuilderFactory\.newInstance()" --include="*.java"
grep -rn "FEATURE_SECURE_PROCESSING\|setExpandEntityReferences\|setFeature.*external" --include="*.java"

# XMLInputFactory — verify XXE protection (protected in PartSoapServiceClient, NPCSoapServiceImpl)
grep -rn "XMLInputFactory\.newFactory()\|XMLInputFactory\.newInstance()" --include="*.java"
grep -rn "IS_SUPPORTING_EXTERNAL_ENTITIES\|SUPPORT_DTD" --include="*.java"

# Command injection — Runtime.exec with dynamic string argument
# Confirmed: RecursiveSearch.java line 44
grep -rn "Runtime\.getRuntime()\.exec\|ProcessBuilder\|new ProcessBuilder" --include="*.java"

# Castor XML Unmarshaller — type-confusion deserialization from XML
# Confirmed: InitialLoad.java
grep -rn "Unmarshaller\|unmarshal\|org\.exolab\.castor\.xml" --include="*.java"

# LDAP injection (if used)
grep -rn "DirContext\|InitialDirContext\|NamingEnumeration" --include="*.java"
```

---

### A04 — Insecure Design

```
# Login attempt limit hardcoded initial value = 5 (then overridden from config)
# Confirmed: SecurityMgrImpl.java line 319
grep -rn "loginAttempts\s*=\s*5\|maxLoginAttempts\|maxAttempts" --include="*.java"

# Rate limiting in CORSFilter (Bucket4j) — verify REQUESTS_PER_MINUTE config loaded
grep -rn "Bucket4j\|Bucket\|rateLimitBuckets\|requestsPerMinute\|REQUESTS_PER_MINUTE" --include="*.java"

# CSRF protection — not present in REST/Angular SPA (check if needed or mitigated by JWT)
grep -rn "csrf\|CSRF\|CsrfToken\|X-CSRF" --include="*.java" --include="*.ts"

# File upload validation — extension-only check (if any upload endpoints exist)
grep -rn "getContentType\|getMimeType\|getFileName\|getOriginalFilename\|magic\|tika" --include="*.java"
```

---

### A05 — Security Misconfiguration

```
# Security response headers — set in CORSFilter (verify all are present)
grep -rn "X-Frame-Options\|X-Content-Type-Options\|Content-Security-Policy\|Strict-Transport-Security\|Referrer-Policy\|Permissions-Policy" NPGParent/NPGWebAppController/src/main/java/com/telcordia/web/helper/CORSFilter.java

# CORS bypass — inline wildcard in REST services bypasses CORSFilter origin allow-list
# Confirmed: UserService.java, WorklistService.java
grep -rn "\.header(\"Access-Control-Allow-Origin\",\s*\"\\*\")" --include="*.java"

# HTTP TRACE disabled check (present in CORSFilter)
grep -rn "TRACE.*equalsIgnoreCase\|SC_METHOD_NOT_ALLOWED" --include="*.java"

# CORS origin allow-list loaded from config (cors_allowed_origins property)
grep -rn "cors_allowed_origins\|allowedOrigins" --include="*.java"

# Debug / verbose error to client — exception in REST response body
grep -rn "printStackTrace\|e\.getMessage()\|ex\.toString()" --include="*.java"

# Session timeout configuration
grep -rn "session-timeout\|setMaxInactiveInterval" --include="*.xml" --include="*.java"

# Apache CXF admin endpoint exposed
grep -rn "cxf-servlet\|/cxf\|bus\.getExtension\|CXFServlet" --include="*.xml" --include="*.java"
```

---

### A06 — Vulnerable and Outdated Components

```
# In pom.xml — EOL / vulnerable versions
grep -n "castor-xml\|castor-core\|commons-validator.*1\.\|woodstox-core-asl\|wsdl4j\|xml-resolver\|javacsv\|ironjacamar" NPGParent/pom.xml

# All dependency versions in one pass
grep -n "<version>" NPGParent/pom.xml

# castor-xml 1.4.1 (EOL — multiple unpatched CVEs for deserialization)
grep -n "castor-xml\|castor-core" NPGParent/pom.xml

# commons-validator 1.3.1 (released ~2005 — extremely old)
grep -n "commons-validator" NPGParent/pom.xml

# woodstox-core-asl 4.4.1 (EOL — replaced by woodstox 6.x / com.fasterxml.woodstox)
grep -n "woodstox-core-asl" NPGParent/pom.xml

# wsdl4j 1.6.3 (EOL — last release 2013)
grep -n "wsdl4j" NPGParent/pom.xml

# xml-resolver 1.2 (EOL — last release 2001)
grep -n "xml-resolver" NPGParent/pom.xml

# Angular — check package.json for known-vulnerable versions
grep -n "\"@angular/core\"\|\"primeng\"\|\"rxjs\"\|\"moment\"" NPGParent/NPGWebApplication/package.json
```

---

### A07 — Identification and Authentication Failures

```
# Hardcoded default credentials in properties / code
grep -rn "\"npg\"\|\"admin\"\|\"password\"\|\"secret\"\|\"test123\"\|\"changeme\"" --include="*.java"
grep -rn "getString.*password\|getProperty.*password" --include="*.java"

# Login attempt initial value hardcoded (SecurityMgrImpl.java line 319)
grep -rn "loginAttempts\s*=\s*5\|parseInt.*attempts" --include="*.java"

# Password in log output
grep -rn "log.*password\|logger.*password\|print.*password" --include="*.java"

# Session / JWT invalidation on logout — verify token blacklisting or expiry
grep -rn "logout\|invalidate\|jwtBlacklist\|revokedTokens" NPGParent/NPGWebAppController/src/main/java/com/telcordia/rest/login/LoginService.java

# Session timeout inconsistency
grep -rn "session-timeout" --include="*.xml"

# Apache MINA SSHD host key verification (replaced JSch — verify not disabled)
grep -rn "sshd-common\|ServerKeyVerifier\|AcceptAllServerKeyVerifier\|RejectAllServerKeyVerifier" --include="*.java"
```

---

### A08 — Software and Data Integrity Failures

```
# ObjectInputStream / deserialization
# Confirmed: SecurityMgrTestClient1.java
grep -rn "ObjectInputStream\|readObject()\|defaultReadObject" --include="*.java"

# Serializable classes (potential gadget chain surface)
# Confirmed: jaxb/BulkSyncMessageType, jaxb/NPCData, jaxb/NPCMessageType, jaxb/NumberDataType,
#            jaxb/PortMessageType, jaxb/SubscriberDataType, ComInterface/TimerViolationData,
#            ComInterface/WorkListData, rest/common/SessionVariables, rest/userid/UserRowItems
grep -rn "implements Serializable\|implements java\.io\.Serializable" --include="*.java"

# Castor XML deserialization (Unmarshaller.unmarshal from XML — type-confusion risk)
# Confirmed: InitialLoad.java
grep -rn "Unmarshaller\|unmarshal(" --include="*.java"

# Velocity template engine — verify templates not loaded from user input
grep -rn "velocity\|VelocityEngine\|VelocityContext\|Template.*merge\|evaluate(" --include="*.java"
```

---

### A09 — Security Logging and Monitoring Failures

```
# Exception swallowed silently
grep -rn "catch.*Exception.*{$\|} catch.*{ *}" --include="*.java"

# Exception / stacktrace to stdout (not logger)
# Confirmed in: Decrypter.java, Encrypter.java, CheckNPGResources.java, ProductProperties.java, Trace.java
grep -rn "System\.out\.print\|e\.printStackTrace()" --include="*.java"

# Exception object set in REST response body (Jackson serializes full stacktrace)
# Confirmed: LoginService.java, ChangePasswordService.java, UserService.java,
#            WorklistService.java, PortingService.java, ParticipantsService.java
grep -rn "\.setException(ex)\|\.setException(e)\|\.setException(rej)" --include="*.java"

# e.getMessage() / ex.toString() passed to logger (exposes internal paths / class names)
grep -rn "_logger\.error.*ex\.toString\|logger.*e\.getMessage\(\)" --include="*.java"

# SQL error details exposed
grep -rn "getSQLState()\|getErrorCode()\|getVendorCode()" --include="*.java"
```

---

### A10 — SSRF

```
# SOAP endpoint URLs from ProductProperties (verify source is not user-controlled)
# Confirmed: SOAPClient.java, JmsClient.java, CorbaClient.java
grep -rn "getProperty.*[Uu]rl\|getProperty.*[Hh]ost\|getProperty.*[Ee]ndpoint\|PROVIDER_URL\|URL_PREFIX" --include="*.java"

# Apache CXF stub endpoint (SOAP endpoint from config)
grep -rn "setAddress\|getPort.*Service\|Service\.create\|BindingProvider\|ENDPOINT_ADDRESS_PROPERTY" --include="*.java"

# PartSoapServiceClient / NPCSoapServiceImplService — verify endpoint locked to trusted host
grep -rn "PartSoapServiceClient\|NPCSoapServiceImplService\|NPCSoapServiceImpl" --include="*.java"

# Hardcoded localhost WSDL / URL references
grep -rn "new URL(\"file:/\|new URL(\"http://localhost\|new URL(\"http://127\." --include="*.java"
```

---

### Apache MINA SSHD (SFTP surface — replaced JSch)

```
# Apache MINA SSHD 2.12.1 — verify host key verification is NOT disabled
grep -rn "AcceptAllServerKeyVerifier\|ServerKeyVerifier\|sshd\|SftpClient\|SshClient" --include="*.java"

# Credentials sourced from properties — verify not hardcoded
grep -rn "getProperty.*sftpPass\|getProperty.*sshPass\|setPassword\|setUsername" --include="*.java"

# SSHD version check in pom.xml
grep -n "sshd-common\|sshd-sftp\|apache.*sshd" NPGParent/pom.xml
```

---

### Castor XML (Initial Load surface)

```
# Castor 1.4.1 — EOL, multiple CVEs for XML deserialization
grep -n "castor-xml\|castor-core" NPGParent/pom.xml

# Unmarshaller with untrusted XML input (InitialLoad.java)
grep -rn "Unmarshaller\|unmarshal\|org\.exolab\.castor\.xml" --include="*.java"

# Castor mapping/descriptor files (auto-generated, review for type widening)
grep -rn "PortedNumberType\|PortedNumberTypeDescriptor\|castorgen" --include="*.java"
```

---

### Inline CORS Wildcard in REST Layer (NPG-PAK-specific surface)

```
# CORSFilter correctly validates against allow-list, but REST services bypass it
# with inline Access-Control-Allow-Origin: * headers
# Confirmed: UserService.java (lines 96, 103, 126, 180, 199), WorklistService.java (line 69+)
grep -rn "\.header(\"Access-Control-Allow-Origin\",\s*\"\\*\")" --include="*.java"

# All REST endpoints returning wildcard CORS
grep -rn "Access-Control-Allow-Origin.*\*" NPGParent/NPGWebAppController/src/
```

---

### Angular / Frontend Patterns

```
# Token stored in sessionStorage (XSS-accessible — better than localStorage but not risk-free)
# Confirmed: app.component.ts, token-storage.service.ts
grep -rn "sessionStorage\.setItem\|sessionStorage\.getItem\|sessionStorage\.clear" --include="*.ts"

# XSS — unsafe DOM manipulation
grep -rn "innerHTML\|outerHTML\|document\.write\|bypassSecurityTrust" --include="*.ts" --include="*.html"

# Hardcoded API base URLs
grep -rn "http://\|https://.*localhost\|baseUrl.*=.*'" --include="*.ts"

# No sanitization on user input binding
grep -rn "\[innerHTML\]\|DomSanitizer\|sanitize" --include="*.ts" --include="*.html"
```

---

## PART 2 — SEMGREP RULES

> Run: `semgrep --config semgrep-npg-pak-rules.yaml NPGParent/`

```yaml
rules:

  # ─────────────────────────────────────────────
  # A01 — Inline CORS Wildcard Bypassing CORSFilter
  # ─────────────────────────────────────────────
  - id: inline-cors-wildcard-bypass
    pattern: |
      Response.ok(...).header("Access-Control-Allow-Origin", "*")...
    message: "Inline wildcard CORS bypasses CORSFilter origin allow-list (UserService, WorklistService) — remove and let CORSFilter handle CORS"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A01

  # ─────────────────────────────────────────────
  # A02 — Insecure Random in Security Context
  # ─────────────────────────────────────────────
  - id: insecure-random-security-context
    patterns:
      - pattern: new Random()
      - pattern-not-inside: |
          // ... test ...
    message: "java.util.Random is not cryptographically secure — use SecureRandom (confirmed in SecurityMgrImpl.java session string)"
    languages: [java]
    severity: WARNING
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
  # A03 — Unparameterized createStatement
  # ─────────────────────────────────────────────
  - id: unparameterized-statement
    patterns:
      - pattern: $CONN.createStatement()
    message: "createStatement() found — verify all SQL using this statement is parameterized"
    languages: [java]
    severity: WARNING
    metadata:
      owasp: A03

  # ─────────────────────────────────────────────
  # A03 — XXE: DocumentBuilderFactory without secure processing
  # ─────────────────────────────────────────────
  - id: xxe-document-builder-factory
    patterns:
      - pattern: DocumentBuilderFactory.newInstance()
      - pattern-not-inside: |
          DocumentBuilderFactory $F = DocumentBuilderFactory.newInstance();
          ...
          $F.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    message: "DocumentBuilderFactory without FEATURE_SECURE_PROCESSING — external entities may be parsed (NPGRepositorySelector.java)"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A03

  # ─────────────────────────────────────────────
  # A03 — Command Injection via Runtime.exec
  # ─────────────────────────────────────────────
  - id: command-injection-runtime-exec
    patterns:
      - pattern: Runtime.getRuntime().exec($CMD)
      - pattern-not: |
          Runtime.getRuntime().exec(new String[] {"...", "...", "..."})
    message: "Runtime.exec with string argument — shell metacharacter injection possible (RecursiveSearch.java line 44)"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A03

  # ─────────────────────────────────────────────
  # A04 — Hardcoded Login Attempt Limit
  # ─────────────────────────────────────────────
  - id: hardcoded-login-attempt-limit
    pattern: |
      int $ATT = 5;
    message: "loginAttempts initialized to hardcoded 5 (SecurityMgrImpl.java line 319) — load exclusively from config to allow ops tuning"
    languages: [java]
    severity: INFO
    metadata:
      owasp: A04

  # ─────────────────────────────────────────────
  # A06 — castor-xml 1.4.1 (EOL)
  # ─────────────────────────────────────────────
  - id: castor-xml-eol
    pattern: |
      <artifactId>castor-xml</artifactId>
      <version>1.4.$V</version>
    message: "castor-xml 1.4.1 is EOL with unpatched XML deserialization CVEs — migrate InitialLoad to JAXB"
    languages: [xml]
    severity: ERROR
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A06 — commons-validator 1.3.1 (extremely old)
  # ─────────────────────────────────────────────
  - id: commons-validator-outdated
    pattern: |
      <artifactId>commons-validator</artifactId>
      <version>1.3.$V</version>
    message: "commons-validator 1.3.x was released ~2005 — upgrade to 1.8.0+"
    languages: [xml]
    severity: WARNING
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A06 — woodstox-core-asl 4.x (EOL)
  # ─────────────────────────────────────────────
  - id: woodstox-asl-eol
    pattern: |
      <artifactId>woodstox-core-asl</artifactId>
    message: "woodstox-core-asl 4.x is EOL — migrate to com.fasterxml.woodstox:woodstox-core 6.x"
    languages: [xml]
    severity: WARNING
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A08 — ObjectInputStream deserialization
  # ─────────────────────────────────────────────
  - id: object-input-stream-deserialization
    patterns:
      - pattern: |
          ObjectInputStream $OIS = new ObjectInputStream(...);
          ...
          $OIS.readObject();
    message: "ObjectInputStream.readObject() — review Serializable class graph for gadget chain risk (SecurityMgrTestClient1.java)"
    languages: [java]
    severity: ERROR
    metadata:
      owasp: A08

  # ─────────────────────────────────────────────
  # A08 — Serializable domain object (gadget chain risk)
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

  # ─────────────────────────────────────────────
  # A09 — Exception Object in REST Response
  # ─────────────────────────────────────────────
  - id: exception-in-rest-response
    pattern: |
      $STATUS.setException($EX);
      ...
      return Response.status(...).entity($STATUS).build();
    message: "Exception set in Status DTO — Jackson serializes full stacktrace into JSON response (LoginService, UserService, WorklistService, PortingService, ParticipantsService, ChangePasswordService)"
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
  # A10 — SSRF via SOAP Endpoint from Config
  # ─────────────────────────────────────────────
  - id: ssrf-soap-endpoint-from-config
    pattern: |
      String $URL = $PROPS.getProperty(...);
      ...
      new URL($URL)
    message: "SOAP/HTTP endpoint URL sourced from config — validate URL is within allowed host whitelist to prevent SSRF"
    languages: [java]
    severity: WARNING
    metadata:
      owasp: A10
```

---

## PART 3 — QUICK REFERENCE: OWASP → GREP → SEMGREP

| OWASP | Finding in This Project | Grep Pattern | Semgrep Rule ID |
|---|---|---|---|
| A01 | Inline CORS wildcard in UserService, WorklistService | `header.*Access-Control.*\*` | `inline-cors-wildcard-bypass` |
| A01 | No `@RolesAllowed` on REST endpoints | `@RolesAllowed` (absent) | — |
| A01 | JWT public-endpoint allow-list | `publicEndpoints\|DEFAULT_PUBLIC_ENDPOINTS` | — |
| A02 | `new Random()` in SecurityMgrImpl session string | `new Random\(\)` | `insecure-random-security-context` |
| A02 | JWT stored in sessionStorage (XSS-accessible) | `sessionStorage\.setItem` | — |
| A03 | SQL sqlString += in xnp/db/* before prepareStatement | `sqlString.*+=` | `sql-string-concat` |
| A03 | DocumentBuilderFactory without secure processing | `DocumentBuilderFactory\.newInstance()` | `xxe-document-builder-factory` |
| A03 | Runtime.exec in RecursiveSearch.java line 44 | `getRuntime\(\)\.exec` | `command-injection-runtime-exec` |
| A03 | Castor XML Unmarshaller in InitialLoad.java | `unmarshal\|org\.exolab\.castor` | — |
| A04 | loginAttempts = 5 hardcoded initial value | `loginAttempts\s*=\s*5` | `hardcoded-login-attempt-limit` |
| A04 | Rate limiting active via Bucket4j | `Bucket4j\|REQUESTS_PER_MINUTE` (present) | — |
| A05 | Security headers set in CORSFilter | `X-Frame-Options.*DENY` (present) | — |
| A05 | CORS inline wildcard bypassing CORSFilter | `Access-Control-Allow-Origin.*\*` in REST | `inline-cors-wildcard-bypass` |
| A05 | HTTP TRACE disabled in CORSFilter | `TRACE.*equalsIgnoreCase` (present) | — |
| A06 | castor-xml 1.4.1 (EOL) | `castor-xml\|castor-core` in pom.xml | `castor-xml-eol` |
| A06 | commons-validator 1.3.1 (~2005) | `commons-validator.*1\.3` in pom.xml | `commons-validator-outdated` |
| A06 | woodstox-core-asl 4.4.1 (EOL) | `woodstox-core-asl` in pom.xml | `woodstox-asl-eol` |
| A06 | wsdl4j 1.6.3 (EOL) | `wsdl4j` in pom.xml | — |
| A06 | xml-resolver 1.2 (EOL) | `xml-resolver` in pom.xml | — |
| A07 | loginAttempts initial hardcoded value | `loginAttempts\s*=\s*5` | `hardcoded-login-attempt-limit` |
| A07 | JWT logout — verify token invalidation | `logout.*LoginService` | — |
| A08 | ObjectInputStream in SecurityMgrTestClient1.java | `ObjectInputStream\|readObject\(\)` | `object-input-stream-deserialization` |
| A08 | Serializable: jaxb/*, ComInterface/*, SessionVariables | `implements Serializable` | `serializable-domain-object` |
| A08 | Castor Unmarshaller in InitialLoad.java | `Unmarshaller\|unmarshal` | — |
| A09 | setException(ex) in REST DTOs (6 services) | `\.setException(ex\|e\|rej)` | `exception-in-rest-response` |
| A09 | System.out.print in Decrypter, Encrypter, Trace, etc. | `System\.out\.print` | `print-stack-trace` |
| A10 | SOAP endpoint URL from ProductProperties | `getProperty.*[Uu]rl\|PROVIDER_URL` | `ssrf-soap-endpoint-from-config` |

---

## PART 4 — HOW GREP PATTERNS WERE DECIDED (Decision Logic)

```
Java 21 + JDBC (ojdbc10) detected
  └─► grep: sqlString += getDefaultWhere() in xnp/db/* → SQL build before prepareStatement
  └─► All Xnp_*.java use prepareStatement — verify WHERE clause is parameterized

Jakarta EE JAX-RS (REST) + Jackson detected
  └─► grep: setException / entity(status) → exception DTO serialization to JSON
  └─► grep: Response.ok().header("Access-Control-Allow-Origin", "*") → wildcard CORS bypass

Apache CXF 4 SOAP detected
  └─► grep: setAddress / BindingProvider / getProperty.*Url → SSRF via config endpoint
  └─► PartSoapServiceClient uses XMLInputFactory with XXE disabled (confirmed)
  └─► NPCSoapServiceImpl uses XMLInputFactory with XXE disabled (confirmed)

DocumentBuilderFactory detected
  └─► grep: DocumentBuilderFactory.newInstance() → XXE check
  └─► NPGRepositorySelector.java uses it without confirmed FEATURE_SECURE_PROCESSING

Runtime.exec detected
  └─► grep: getRuntime().exec(cmd) → command injection (RecursiveSearch.java line 44)

castor-xml 1.4.1 + Unmarshaller detected
  └─► grep: unmarshal / Unmarshaller → type-confusion XML deserialization (InitialLoad.java)
  └─► Version is EOL — replace with JAXB (already used elsewhere in project)

java.util.Random detected in SecurityMgrImpl
  └─► grep: new Random().nextInt() → cryptographically weak session string
  └─► Line 553 SecurityMgrImpl — replace with SecureRandom

Inline Access-Control-Allow-Origin: * detected in REST layer
  └─► CORSFilter correctly uses origin allow-list
  └─► UserService.java and WorklistService.java bypass it with inline response headers
  └─► grep: .header("Access-Control-Allow-Origin", "*") → 5 occurrences in UserService, 7 in WorklistService

Angular 21 + sessionStorage detected
  └─► grep: sessionStorage.setItem / getItem → JWT in sessionStorage (XSS-accessible)
  └─► Confirm no localStorage.setItem usage for tokens

Serializable classes + ObjectInputStream detected
  └─► jaxb/* (BulkSyncMessageType, NPCData, NPCMessageType, NumberDataType, PortMessageType)
  └─► ComInterface/* (TimerViolationData, WorkListData)
  └─► rest/* (SessionVariables, UserRowItems)
  └─► grep: implements Serializable → review gadget chain surface
```

---

*Generated by GitHub Copilot security scan — 2026-08-05*
*Run Semgrep rules: `semgrep --config NPG-PAK-SECURITY_SCAN_PATTERNS.md NPGParent/`*
