# Security Patterns Database
## Consolidated OWASP Vulnerability Patterns for SAST Detection

**Purpose:** Single source of truth for detection rules across all scanned projects (NPC/NPG, Spring Boot tutorials, generic vulnerabilities)  
**Last Updated:** 2026-08-06  
**Scope:** Java, TypeScript/Angular, Python, .NET (extensible)

---

## How to Use This File

This database consolidates security patterns from three sources:
1. **NPC-SECURITY_SCAN_PATTERNS.md** — Java/Struts/JAX-RS/JWT specific patterns
2. **OWASP_Vulnerability_Report.md** — Spring Boot + Angular CRUD example vulnerabilities
3. **OWASP_Vulnerability_Report_Bedrock_Enterprise.md** — Detailed Spring Boot analysis

**For SAST Pipeline:**
- Each pattern entry includes: `grep_pattern` (regex), `semgrep_rule` (AST), `tree_sitter_query` (AST), and `llm_verification` hints
- Use `tech_stack_applicability` to filter rules based on detected stack
- Use `requires_llm_verification: true` to route to LLM for taint/context verification

---

## OWASP A01:2021 — Broken Access Control

### A01.1 — No Authentication on Endpoints

**Description:** REST endpoints publicly accessible without authentication or role-based access control.

**Tech Stack Applicability:** Java (Spring, JAX-RS, Struts), Python (Django, Flask), Node.js (Express, Fastify), .NET (ASP.NET)

**Pattern Variants:**

#### Java/Spring
```java
@GetMapping("/tutorials")
@PostMapping("/tutorials")  // No @PreAuthorize, @Secured, or SecurityContext check
@DeleteMapping("/tutorials/{id}")
public ResponseEntity<...> endpoint(...) { ... }
```

**Detection Rules:**

| Method | Pattern | Requires LLM | Notes |
|--------|---------|--------------|-------|
| Grep | `@GetMapping\|@PostMapping\|@DeleteMapping` + NO `@PreAuthorize\|@Secured` | YES | Must confirm no auth in method body |
| Semgrep | `@RestController` with method lacking `@PreAuthorize` | YES | Check for SecurityContext.getContext() |
| Tree-Sitter | `(method_declaration (annotation (identifier) @anno) @method)` where @anno NOT IN ["PreAuthorize", "Secured"] | YES | Requires cross-method symbol lookup |

**LLM Verification Prompt:**
```
The scanner found a REST endpoint without @PreAuthorize annotation:
  File: {file_path}:{line_number}
  Endpoint: {method} {path}
  
Does this endpoint:
  1. Handle sensitive operations (POST, PUT, DELETE)?
  2. Access or return user data?
  3. Modify server state?
  
If yes, this is A01:2021 CRITICAL. If it's a public health check, it's safe.
```

**Severity:** CRITICAL (if modifies data), HIGH (if returns data)  
**CVSS Score:** 9.1  
**Recommendation:** Add `@PreAuthorize("hasRole('USER')")` minimum; verify ownership for resource access

**References:** 
- NPC patterns, OWASP Spring Boot Report Issues #1, #2
- Bedrock Enterprise Issues #1, #2

---

### A01.2 — Resource Enumeration / IDOR (Insecure Direct Object Reference)

**Description:** Sequential numeric IDs allow attackers to enumerate and access resources they don't own.

**Pattern:**
```java
@GetMapping("/tutorials/{id}")
public ResponseEntity<Tutorial> getTutorial(@PathVariable("id") long id) {
    Optional<Tutorial> data = tutorialRepository.findById(id);
    // No ownership verification
    return new ResponseEntity<>(data.get(), HttpStatus.OK);
}
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `@PathVariable.*long id\|@PathVariable.*int id` + NO `getOwner\|getOwnerId\|SecurityContext` |
| Semgrep | `findById($ID)` without subsequent ownership check |
| Tree-Sitter | `(path_param type:"long\|int") + NO (comparison (call_expr method:"getOwner"))` |

**Fix:** Use UUID instead of sequential ID; add `if (!resource.owner.equals(principal.getName())) return 403;`

**Severity:** MEDIUM  
**CVSS Score:** 6.5

**References:** Spring Boot Report Issue #10, Bedrock Issue #4

---

### A01.3 — CORS Wildcard or Overly Permissive Origin

**Description:** `Access-Control-Allow-Origin: *` or hardcoded localhost in production.

**Patterns:**

#### Java/Spring
```java
@CrossOrigin(origins = "http://localhost:8081")  // Hardcoded dev config
@CrossOrigin(origins = "*")                       // Wildcard
@CrossOrigin                                      // Defaults to *
```

#### Configuration
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  // DANGEROUS with *
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `@CrossOrigin.*origins.*\*\|Access-Control-Allow-Origin.*\*` |
| Grep | `@CrossOrigin.*localhost\|@CrossOrigin.*127.0.0.1` (hardcoded dev) |
| Semgrep | `@CrossOrigin(origins = "*")` or `header("Access-Control-Allow-Origin", "*")` |
| Tree-Sitter | `(annotation (call_expr method:"CrossOrigin") (argument (string_literal) @origin))` |

**LLM Verification:**
```
Found CORS origin configuration:
  File: {file_path}
  Config: {cors_value}
  
Is this production code or dev-only? If production, flag as HIGH.
```

**Severity:** HIGH (if wildcard or localhost in prod)  
**CVSS Score:** 7.3  
**Recommendation:** Externalize allowed origins to env vars; explicitly set `allowCredentials=false` for public APIs

**References:** NPC patterns A05, Spring Boot Report Issue #3, Bedrock Issue #4

---

## OWASP A02:2021 — Cryptographic Failures

### A02.1 — Hardcoded Secrets (API Keys, Passwords, JWT Secrets)

**Description:** Secrets stored as string literals in code.

**Patterns:**

#### Java
```java
private final String stringKey = "MySecretKey123";
private static final String API_KEY = "sk_live_...";
String password = "admin123";
String jwtSecret = "my-jwt-secret";
```

#### TypeScript/JavaScript
```typescript
const baseUrl = 'http://localhost:8080';  // Hardcoded URL
const apiKey = 'sk_live_...';
```

#### Python
```python
password = "admin123"
api_key = "sk_live_..."
secret_key = "hardcoded"
```

**Detection Rules:**

| Method | Pattern | Notes |
|--------|---------|-------|
| Grep | `stringKey\s*=\|jwtSecret\s*=\|apiKey\s*=\|password\s*=.*["']` | Universal |
| Grep | `AWS_SECRET\|GITHUB_TOKEN\|DATABASE_PASSWORD` | Environment variable names |
| Semgrep | `String $KEY = "...";` with length > 8 | Catches assigned literals |
| Tree-Sitter | `(assignment (identifier @name) (string_literal @value))` where @name matches secret pattern | Universal |

**LLM Verification:**
```
Found potential hardcoded secret:
  Variable: {var_name}
  Value: {truncated_value}...
  
Is this a real secret (API key, password, token) or a placeholder/comment? 
Only real secrets should be flagged.
```

**Severity:** CRITICAL  
**CVSS Score:** 9.8  
**Recommendation:** Use environment variables, AWS Secrets Manager, or HashiCorp Vault

**References:** NPC A02, Spring Boot Report #8, Bedrock Issue #2

---

### A02.2 — Weak Hash Algorithms (MD5, SHA-1)

**Description:** Using cryptographically broken hashing for passwords or security tokens.

**Pattern:**
```java
MessageDigest.getInstance("MD5")
MessageDigest.getInstance("SHA-1")
Cipher.getInstance("DES")
SecretKeyFactory.getInstance("PBEWithMD5AndDES")
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `getInstance.*MD5\|getInstance.*SHA-1\|getInstance.*DES\|PBEWithMD5` |
| Semgrep | `MessageDigest.getInstance("MD5")` |
| Tree-Sitter | `(call_expr method:"getInstance" (string_literal @algo))` where @algo IN ["MD5", "SHA-1", "DES"] |

**Severity:** CRITICAL (if for passwords), HIGH (if for checksums)  
**CVSS Score:** 8.1  
**Recommendation:** Use SHA-256 minimum, SHA-3 preferred; use bcrypt/Argon2 for passwords

---

### A02.3 — Insecure Random Number Generation

**Description:** Using `java.util.Random` or `Math.random()` instead of `SecureRandom`.

**Pattern:**
```java
new Random()  // Predictable for crypto
Math.random()  // Predictable for crypto
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `new Random()\|Math\.random()` NOT in test classes |
| Semgrep | `new Random()` with pattern-not-inside test |
| Tree-Sitter | `(new_expression (class_name) @cls)` where @cls == "Random" |

**Severity:** HIGH (if for crypto/tokens), LOW (if for non-security RNG)  
**CVSS Score:** 6.5  
**Recommendation:** Use `SecureRandom` or `java.security.SecureRandom`

---

### A02.4 — No HTTPS / Plaintext Communication

**Description:** Using HTTP instead of HTTPS; credentials transmitted unencrypted.

**Patterns:**

#### TypeScript/Angular
```typescript
const baseUrl = 'http://localhost:8080/api';  // HTTP not HTTPS
const apiUrl = 'http://api.example.com';      // Production HTTP
```

#### Spring Config
```properties
# No SSL configuration
# server.ssl.enabled=false (implicit)
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `const.*=.*http://(?!localhost)\|apiBaseUrl.*http://` |
| Grep | `application.properties` missing `server.ssl.enabled=true` in production |
| Semgrep | `"http://"` in baseUrl or apiUrl (exclude localhost) |
| Tree-Sitter | `(string_literal) @url` matching `http://` outside test/dev context |

**Severity:** HIGH  
**CVSS Score:** 8.1  
**Recommendation:** Enforce HTTPS in production; use env-based URL config

**References:** Spring Boot Report #8, Bedrock Issue #2

---

## OWASP A03:2021 — Injection

### A03.1 — SQL String Concatenation (SQL Injection)

**Description:** Building SQL queries via string concatenation instead of parameterized statements.

**Patterns:**

#### Java
```java
String sql = "SELECT * FROM users WHERE id=" + userId;
String query = "INSERT INTO table VALUES('" + userInput + "')";
stmt.executeQuery(sql);
stmt.execute(sql);
```

#### Python
```python
query = f"SELECT * FROM users WHERE id={user_id}"
cursor.execute(query)
```

#### TypeScript
```typescript
const query = `SELECT * FROM users WHERE username='${username}'`;
```

**Detection Rules:**

| Method | Pattern | Requires LLM |
|--------|---------|--------------|
| Grep | `String.*sql.*=.*+\|String.*query.*=.*+` | YES |
| Grep | `executeQuery.*\+\|execute.*\+` | YES |
| Semgrep | `$SQL = "..." + $VAR; ... $STMT.executeQuery($SQL)` | YES |
| Tree-Sitter | `(binary_expression left:(identifier @sql) operator:"+") ... (call_expr method:"executeQuery" (identifier @sql))` | YES |

**LLM Verification Prompt:**
```
Found SQL string concatenation:
  File: {file_path}
  Line: {line_number}
  Code: {code_snippet}

Is this:
  1. A real SQL statement (SELECT, INSERT, UPDATE, DELETE)?
  2. Using string concatenation or interpolation?
  3. Passed to executeQuery/execute/update?

If all yes, this is A03:2021 SQLi. Also verify no parameterized PreparedStatement.
```

**Severity:** CRITICAL  
**CVSS Score:** 8.6  
**Recommendation:** Use PreparedStatement with `?` placeholders; use ORM (JPA, Hibernate)

**References:** NPC A03, Spring Boot Report #4

---

### A03.2 — XXE (XML External Entity) Injection

**Description:** XML parsers configured to process external entities, allowing file read or SSRF.

**Pattern:**
```java
XMLInputFactory factory = XMLInputFactory.newInstance();
// Missing: factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Missing: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `XMLInputFactory.newInstance()\|DocumentBuilderFactory.newInstance()` + NO `IS_SUPPORTING_EXTERNAL_ENTITIES\|disallow-doctype-decl` |
| Semgrep | `XMLInputFactory.newInstance()` without subsequent `setProperty(...false)` |

**Severity:** HIGH  
**CVSS Score:** 8.1  
**Recommendation:** Disable external entities: `factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)`

---

### A03.3 — LDAP Injection

**Description:** User input concatenated into LDAP filters.

**Pattern:**
```java
String ldapFilter = "(&(uid=" + username + ")(password=" + password + "))";
NamingEnumeration results = ctx.search("ou=users,dc=example,dc=com", ldapFilter, null);
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `DirContext\|InitialDirContext\|NamingEnumeration` + concatenation |
| Semgrep | `search(..., ldapFilter)` with concatenation |

**Severity:** HIGH  
**Recommendation:** Use parameterized LDAP queries or escape special characters

---

## OWASP A04:2021 — Insecure Design

### A04.1 — Missing Input Validation

**Description:** No length limits, type validation, or content validation on user input.

**Patterns:**

#### Java/Spring
```java
@PostMapping("/tutorials")
public ResponseEntity<Tutorial> create(@RequestBody Tutorial tutorial) {
    // No @Valid annotation
    // No null checks
    // No length validation
    return new ResponseEntity<>(tutorialRepository.save(tutorial), HttpStatus.CREATED);
}

@GetMapping("/tutorials")
public ResponseEntity<List<Tutorial>> search(@RequestParam String title) {
    // No @Size annotation
    // No max length check
    // No character whitelist
}
```

#### Python/Django
```python
def create_tutorial(request):
    title = request.POST.get('title')  # No validation
    if not title:  # Only null check
        return error()
```

**Detection Rules:**

| Method | Pattern | Requires LLM |
|--------|---------|--------------|
| Grep | `@RequestBody\|@RequestParam` + NO `@Valid\|@Size\|@NotNull` | YES |
| Semgrep | `@RequestBody Tutorial` where Tutorial missing validation annotations | YES |
| Tree-Sitter | `(parameter (annotation*) @annos (identifier) @param_type)` where validation NOT in @annos | YES |

**LLM Verification:**
```
Found parameter without validation annotations:
  Parameter: {param_name}
  Type: {type}
  Location: {method}
  
Is this a user-controlled input? If yes, check if method body has manual validation (length checks, regex, type conversion).
```

**Severity:** HIGH  
**CVSS Score:** 8.3  
**Recommendation:** Add `@Valid`, `@Size`, `@NotBlank`, `@Pattern` annotations; implement input whitelist

**References:** Spring Boot Report #5, Bedrock Issue #6

---

### A04.2 — No CSRF Protection

**Description:** State-changing operations (POST, PUT, DELETE) don't validate CSRF tokens.

**Patterns:**

#### Java/Spring (Missing Configuration)
```java
// No CSRF token validation in SecurityConfig
http.csrf().disable();  // ❌ WRONG
// Should be: http.csrf().csrfTokenRepository(...)
```

#### TypeScript/Angular (Missing Module)
```typescript
// app.module.ts missing HttpClientXsrfModule
@NgModule({
    imports: [HttpClientModule]  // ❌ No XSRF protection
    // Should import: HttpClientXsrfModule.withOptions({...})
})
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `http.csrf().disable()\|csrf.*disable` |
| Grep | `HttpClientModule` + NO `HttpClientXsrfModule` in imports |
| Semgrep | `csrf().disable()` without `csrfTokenRepository` |

**Severity:** MEDIUM  
**CVSS Score:** 6.1  
**Recommendation:** Enable CSRF validation; configure token repository (cookie-based); add XSRF module in Angular

**References:** Spring Boot Report #6, Bedrock Issue #5

---

### A04.3 — No Rate Limiting / Account Lockout

**Description:** No protection against brute force attacks on login or sensitive endpoints.

**Pattern:**
```java
@PostMapping("/login")
public ResponseEntity<...> login(@RequestBody LoginRequest req) {
    // No failedAttempts counter
    // No lockout mechanism
    // No rate limiting
    User user = userRepository.findByUsername(req.getUsername());
    if (user != null && user.getPassword().equals(req.getPassword())) {
        return authorized();
    }
    return unauthorized();  // Attackers can brute force
}
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `@PostMapping.*login\|@PostMapping.*auth` + NO `failedAttempt\|lockout\|rateLim` |
| Semgrep | Login endpoint without rate limiting decorator |

**Severity:** HIGH  
**Recommendation:** Implement account lockout after N failed attempts; use Spring RateLimiter or similar

---

## OWASP A05:2021 — Security Misconfiguration

### A05.1 — H2 Console Enabled in Production

**Description:** H2 database console publicly accessible at `/h2-ui` with default credentials.

**Pattern:**
```properties
spring.h2.console.enabled=true
spring.h2.console.path=/h2-ui
spring.datasource.username=sa
spring.datasource.password=
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `spring.h2.console.enabled=true` |
| Grep | `spring.datasource.password=$` (empty) |
| Semgrep | `h2.console.enabled=true` outside dev profile |

**Severity:** CRITICAL  
**CVSS Score:** 8.9  
**Recommendation:** Disable in `application.properties`; enable only in dev profile via `application-dev.properties`

**References:** Spring Boot Report #2, Bedrock Issue #3

---

### A05.2 — Debug Features Enabled in Production

**Description:** Verbose error messages, SQL logging, or source maps exposed.

**Patterns:**

#### Java/Spring
```properties
spring.jpa.show-sql=true
logging.level.org.springframework.security=DEBUG
```

#### TypeScript
```json
{
  "compilerOptions": {
    "sourceMap": true  // ❌ Exposes source code in production
  }
}
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `show-sql=true\|logging.level.*=DEBUG` |
| Grep | `sourceMap.*true` in tsconfig.json |

**Severity:** HIGH  
**CVSS Score:** 7.5  
**Recommendation:** Disable in production; use separate dev/prod configurations

---

### A05.3 — Missing Security Headers

**Description:** Security headers not set; no protection against clickjacking, XSS, content sniffing.

**Pattern:**
```java
// Missing headers in filter or SecurityConfig
// Should include:
// X-Frame-Options: DENY
// X-Content-Type-Options: nosniff
// X-XSS-Protection: 1; mode=block
// Content-Security-Policy: ...
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `addHeader.*X-Frame-Options\|addHeader.*X-Content-Type` (absent) |
| Semgrep | Response headers missing X-Frame-Options, X-XSS-Protection |

**Severity:** MEDIUM  
**CVSS Score:** 6.5  
**Recommendation:** Configure headers in SecurityConfig or GlobalFilterChain

---

## OWASP A06:2021 — Vulnerable and Outdated Components

### A06.1 — EOL Library Versions

**Description:** Using unsupported or outdated versions with known CVEs.

**Patterns:**

#### Maven pom.xml
```xml
<artifactId>struts</artifactId>
<version>1.2.9</version>  <!-- EOL since 2013 -->

<artifactId>catalina</artifactId>
<version>5.5</version>  <!-- EOL Tomcat 5.x -->

<artifactId>axis2</artifactId>
<version>1.6.0</version>  <!-- Multiple CVEs -->
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `struts.*1\.\|catalina.*[56]\.\|axis2.*1\.6` |
| Grep | `<version>` with regex against EOL version database |

**Severity:** HIGH  
**CVSS Score:** 7.5  
**Recommendation:** Update to latest LTS version; review CVEs for current version

**References:** NPC A06, Spring Boot Report #7

---

### A06.2 — Outdated Framework Versions

**Description:** Old Spring Boot, Angular, Node.js versions with known vulnerabilities.

**Pattern:**
```xml
<!-- Spring Boot -->
<version>3.1.0</version>  <!-- Outdated; current: 3.3.x -->

<!-- Angular in package.json -->
"@angular/core": "^14.0.0"  <!-- Outdated; current: 17+ -->
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `<version>3\.[0-2]\.\|@angular.*[0-9]*` (regex version check) |

**Severity:** MEDIUM  
**Recommendation:** Update within 30 days of patch release; use Dependabot/Snyk for monitoring

---

## OWASP A07:2021 — Identification and Authentication Failures

### A07.1 — Hardcoded Default Credentials

**Description:** Default usernames/passwords embedded in code or properties.

**Patterns:**

#### Java
```java
String password = "admin123";
String defaultPassword = "npc";
String systemPassword = getString("systemPassword", "npc");  // Fallback default
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `password.*=.*["']admin["']\|password.*=.*["']npc["']\|password.*=.*["']test["']` |
| Grep | `getString.*password.*["'].*["']` (default fallback) |
| Semgrep | `getString("password", "...")` with literal default |

**Severity:** CRITICAL  
**CVSS Score:** 9.8  
**Recommendation:** Remove all default credentials; require explicit env-based configuration

---

### A07.2 — Missing Session Timeout

**Description:** Sessions don't expire; allows account hijacking if credentials leaked.

**Pattern:**
```java
// Missing: setMaxInactiveInterval(...)
// Config should set: server.servlet.session.timeout
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `setMaxInactiveInterval\|session-timeout` (absent) in config |

**Severity:** MEDIUM  
**Recommendation:** Set session timeout to 15-30 minutes; configure in `application.properties`

---

### A07.3 — Weak Password Hashing

**Description:** Passwords hashed with weak algorithms (MD5, SHA-1) instead of bcrypt/Argon2.

**Pattern:**
```java
String hash = MD5.digest(password);  // ❌
String hash = SHA1.digest(password);  // ❌
// ✓ Should use bcrypt, Argon2, or PBKDF2
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `MD5.*password\|SHA.*password` |
| Semgrep | `MessageDigest` or `Cipher` for password hashing |

**Severity:** HIGH  
**Recommendation:** Use `BCryptPasswordEncoder` or `Argon2PasswordEncoder`

---

### A07.4 — Cookie Missing HttpOnly / Secure Flags

**Description:** Cookies accessible to JavaScript (XSS), transmitted over HTTP.

**Pattern:**
```java
Cookie cookie = new Cookie("sessionId", token);
// Missing: cookie.setHttpOnly(true);
// Missing: cookie.setSecure(true);
response.addCookie(cookie);
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `new Cookie\|addCookie` + NO `setHttpOnly\|setSecure` |
| Semgrep | `new Cookie(...)` without `setHttpOnly(true)` and `setSecure(true)` |

**Severity:** HIGH  
**CVSS Score:** 7.5  
**Recommendation:** Set `httpOnly=true` and `secure=true`; configure in `application.properties`: `server.servlet.session.cookie.http-only=true`

---

## OWASP A08:2021 — Software and Data Integrity Failures

### A08.1 — Insecure Deserialization

**Description:** Deserializing untrusted data without validation; risk of gadget chain exploitation.

**Patterns:**

#### Java
```java
ObjectInputStream ois = new ObjectInputStream(...);
Object obj = ois.readObject();  // Dangerous without validation

ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // ❌ Dangerous with commons-collections
mapper.readValue(json, Object.class);  // Polymorphic deserialization
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `ObjectInputStream\|readObject\|enableDefaultTyping` |
| Semgrep | `readObject()` or `enableDefaultTyping()` |
| Tree-Sitter | `(call_expr method:"readObject"\|method:"enableDefaultTyping")` |

**Severity:** HIGH  
**CVSS Score:** 8.1  
**Recommendation:** Avoid deserializing untrusted data; use JSON-based formats with type whitelists

---

### A08.2 — Serializable Without serialVersionUID

**Description:** Serializable classes without `serialVersionUID` are vulnerable to gadget chain deserialization.

**Pattern:**
```java
public class Tutorial implements Serializable {
    // Missing: private static final long serialVersionUID = 1L;
    private String title;
    ...
}
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `implements Serializable` + NO `serialVersionUID` |
| Semgrep | `implements Serializable` without `serialVersionUID` field |
| Tree-Sitter | `(class_declaration (implements_clause (identifier "Serializable"))) @class` where NOT `(field_declaration (identifier "serialVersionUID"))` |

**Severity:** MEDIUM  
**CVSS Score:** 6.5  
**Recommendation:** Add `serialVersionUID`; better: avoid Serializable; use JSON

---

## OWASP A09:2021 — Logging and Monitoring Failures

### A09.1 — Exception Disclosed to User

**Description:** Raw exception stack traces returned to client; reveals system architecture and source code.

**Patterns:**

#### Java/Spring
```java
} catch (Exception e) {
    return new ResponseEntity<>(e.toString(), HttpStatus.INTERNAL_SERVER_ERROR);
    // ❌ Exposes exception details to attacker
}

// Or in DTO:
reponseStatus.setException(ex);
return Response.status(200).entity(reponseStatus).build();
// ❌ Jackson serializes Exception fields (message, stackTrace) to JSON
```

**Detection Rules:**

| Method | Pattern | Requires LLM |
|--------|---------|--------------|
| Grep | `e\.toString()\|e\.getMessage()\|setException(ex).*entity` | YES |
| Semgrep | `entity($OBJ).build()` where $OBJ contains Exception field | YES |
| Tree-Sitter | `(call_expr method:"setException" (identifier @ex)) ... (call_expr method:"entity")` | YES |

**LLM Verification:**
```
Found exception serialization:
  File: {file_path}
  Line: {code_snippet}
  
Does this return exception details to HTTP response? If yes, flag as A09 CRITICAL.
Also check if DTO class has Exception field and Jackson is in dependencies.
```

**Severity:** HIGH  
**CVSS Score:** 7.5  
**Recommendation:** Return generic error message to user; log details server-side

**References:** NPC A09, Spring Boot Report #9

---

### A09.2 — printStackTrace() to Stdout

**Description:** Using `printStackTrace()` instead of logger; no structured logging or log aggregation.

**Pattern:**
```java
} catch (Exception e) {
    e.printStackTrace();  // ❌ Goes to stdout, not logger
}
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `\.printStackTrace()` |
| Semgrep | `$E.printStackTrace()` |
| Tree-Sitter | `(call_expr (member_expr (identifier @e) "printStackTrace"))` |

**Severity:** MEDIUM  
**CVSS Score:** 5.3  
**Recommendation:** Use `logger.error("msg", e)` with SLF4J/Logback

---

### A09.3 — No Audit Logging for Security Events

**Description:** Authentication, authorization, and data access events not logged; no forensic capability.

**Pattern:**
```java
@PostMapping("/tutorials")
public ResponseEntity<Tutorial> create(@RequestBody Tutorial tutorial) {
    // No logging of who created what when
    return new ResponseEntity<>(tutorialRepository.save(tutorial), HttpStatus.CREATED);
}
```

**Detection Rules:**

| Method | Pattern | Requires LLM |
|--------|---------|--------------|
| Grep | `@PostMapping\|@DeleteMapping` + NO `logger\.info\|logger\.warn` | YES |
| Semgrep | REST endpoint without security event logging | YES |

**LLM Verification:**
```
Found endpoint without audit logging:
  Method: {method}
  Path: {path}
  
Does this handle sensitive operations (auth, data modification, access control decisions)?
If yes, flag as missing audit logging (A09 MEDIUM).
```

**Severity:** MEDIUM  
**Recommendation:** Log principal, action, resource, timestamp for all sensitive operations

---

## OWASP A10:2021 — SSRF (Server-Side Request Forgery)

### A10.1 — HTTP Client with User-Controlled URL

**Description:** Application makes HTTP requests to user-supplied URLs; risk of internal network access.

**Patterns:**

#### Java
```java
String url = request.getParameter("url");  // User input
HttpClient client = HttpClient.newHttpClient();
HttpRequest httpRequest = HttpRequest.newBuilder().uri(URI.create(url)).build();
// ❌ Could access http://localhost:8080 or http://internal-service
```

#### Python
```python
url = request.args.get('url')
response = requests.get(url)  # ❌ SSRF
```

**Detection Rules:**

| Method | Pattern | Requires LLM |
|--------|---------|--------------|
| Grep | `HttpClient\|CloseableHttpClient\|HttpURLConnection` + `getParameter.*url` | YES |
| Grep | `requests.get.*request\|requests.post.*request` | YES |
| Semgrep | `HttpClient` with user-supplied URL parameter | YES |

**LLM Verification:**
```
Found HTTP client using user input:
  File: {file_path}
  URL source: {param_name}
  
Does this make external HTTP requests? If yes, is URL validated against whitelist?
If no whitelist, flag as SSRF (A10 HIGH).
```

**Severity:** HIGH  
**CVSS Score:** 8.6  
**Recommendation:** Whitelist allowed URLs/domains; validate scheme (HTTPS only); block internal IPs (10.x, 127.x, 169.254.x)

---

## File Upload Vulnerabilities

### File Upload — Extension-Only Validation (No MIME / Magic Bytes)

**Description:** File type validated by extension string only; no MIME type or magic bytes check.

**Pattern:**
```java
String fileName = uploadedFile.getOriginalFilename();
String ext = fileName.substring(fileName.lastIndexOf(".") + 1);  // ❌ Extension only
if (!"jpg".equals(ext) && !"png".equals(ext)) {
    return error();
}
// File could be .exe renamed to .jpg
```

**Detection Rules:**

| Method | Pattern | Requires LLM |
|--------|---------|--------------|
| Grep | `getFileName().*replaceAll\|split.*\"\\.\"` + NO `getContentType\|getMimeType` | YES |
| Semgrep | Extension validation without MIME type check | YES |

**LLM Verification:**
```
Found file upload handling:
  File: {file_path}
  Validation: {validation_code}
  
Does this only check file extension? If yes, is there MIME type or magic bytes validation elsewhere?
If only extension check, flag as A04 MEDIUM.
```

**Severity:** MEDIUM  
**CVSS Score:** 6.5  
**Recommendation:** Validate MIME type and magic bytes; store uploads outside web root; rename files

---

### File Upload — Path Traversal (No Canonicalization)

**Description:** User-supplied filename used directly; risk of writing outside intended directory.

**Pattern:**
```java
String fileName = request.getParameter("filename");  // User input
File file = new File("/uploads/" + fileName);  // ❌ "../../../etc/passwd"
Files.write(file.toPath(), content);
```

**Detection Rules:**

| Method | Pattern | Requires LLM |
|--------|---------|--------------|
| Grep | `getFileName()\|getParameter.*name` + `new File\|Files\.write` | YES |
| Semgrep | User input → File constructor without canonicalization | YES |

**LLM Verification:**
```
Found file path construction from user input:
  File: {file_path}
  Source: {input_source}
  
Does this validate the canonical path? Check for getCanonicalPath().startsWith(uploadDir).
If missing, flag as path traversal (A01 HIGH).
```

**Severity:** HIGH  
**CVSS Score:** 8.1  
**Recommendation:** Use `getCanonicalPath()` and verify startsWith expected directory; use UUIDs for filenames

---

## Frontend / Angular Vulnerabilities

### XSS — innerHTML / bypassSecurityTrustHtml

**Description:** Unsafe DOM manipulation; bypassing Angular's built-in XSS protection.

**Pattern:**
```typescript
// ❌ Unsafe XSS
component.innerHTML = userInput;
this.sanitizer.bypassSecurityTrustHtml(userInput);
document.write(userInput);
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `innerHTML\|bypassSecurityTrust\|document\.write` |
| Semgrep | `innerHTML.*=\|bypassSecurityTrust` in Angular code |

**Severity:** HIGH  
**CVSS Score:** 7.5  
**Recommendation:** Use `{{variable}}` property binding (auto-escaped); sanitize with `DomSanitizer.sanitize()`

---

### XSS — Token Storage in localStorage

**Description:** JWT or session tokens stored in localStorage; accessible to XSS attacks.

**Pattern:**
```typescript
localStorage.setItem('token', jwtToken);
const token = localStorage.getItem('token');
sessionStorage.setItem('token', ...);  // Slightly better but still accessible to XSS
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `localStorage\.setItem.*token\|sessionStorage\.setItem` |
| Semgrep | `localStorage.setItem` with token or auth-related key |

**Severity:** MEDIUM  
**CVSS Score:** 6.5  
**Recommendation:** Store tokens in httpOnly cookies (not accessible to JS); use secure+sameSite flags

---

### XSS — No Input Sanitization in Bindings

**Description:** User input bound directly to template without sanitization.

**Pattern:**
```html
<!-- ❌ Unsafe -->
<div [innerHTML]="userComment"></div>

<!-- ✓ Safe (auto-escaped) -->
<div>{{ userComment }}</div>

<!-- ✓ Safe (sanitized) -->
<div [innerHTML]="sanitizer.sanitize(SecurityContext.HTML, userComment)"></div>
```

**Detection Rules:**

| Method | Pattern |
|--------|---------|
| Grep | `\[innerHTML\].*=.*userInput\|bypassSecurity` |

**Severity:** HIGH  
**CVSS Score:** 7.5  
**Recommendation:** Use text interpolation `{{}}` instead of `[innerHTML]`; use DomSanitizer for HTML

---

## Cross-Cutting Patterns

### Generic Hardcoded Secret Pattern

**Applicable to:** All languages (Java, Python, JavaScript, Go, C#, PHP)

**Pattern:**
```
Variable/constant name matches: password|secret|token|api_key|apiKey|accessKey|privateKey|key
AND value is a string literal matching:
  - 20+ alphanumeric characters (API key-like)
  - Specific patterns: AWS key, GitHub token, JWT, etc.
```

**Detection Rules:**

| Method | Pattern | Notes |
|--------|---------|-------|
| Grep (Universal) | `(password\|secret\|token\|api_?key\|accessKey\|privateKey)\s*=\s*["'][A-Za-z0-9+/]{20,}` | Language-agnostic |
| Semgrep | `$VAR = "...";` where $VAR matches secret pattern and value length > 8 | All languages |
| Tree-Sitter | Assignment with identifier @name matching secret pattern + string_literal value | All languages |

**Severity:** CRITICAL  
**Recommendation:** Use environment variables, vault, or secrets manager

---

## Summary: Pattern-to-Detection Mapping

| OWASP Category | Pattern Name | Grep | Semgrep | Tree-Sitter | Requires LLM |
|---|---|---|---|---|---|
| A01 | No Authentication | ✓ | ✓ | ✓ | YES |
| A01 | IDOR / Resource Enumeration | ✓ | ✓ | ✗ | YES |
| A01 | CORS Wildcard | ✓ | ✓ | ✓ | NO |
| A02 | Hardcoded Secret | ✓ | ✓ | ✓ | NO |
| A02 | Weak Hash (MD5/SHA-1) | ✓ | ✓ | ✓ | NO |
| A02 | Insecure Random | ✓ | ✓ | ✓ | YES |
| A02 | No HTTPS | ✓ | ✓ | ✓ | YES |
| A03 | SQL Concatenation | ✓ | ✓ | ✓ | YES |
| A03 | XXE | ✓ | ✓ | ✓ | YES |
| A04 | Missing Input Validation | ✓ | ✓ | ✓ | YES |
| A04 | No CSRF | ✓ | ✓ | ✓ | NO |
| A04 | No Rate Limiting | ✓ | ✓ | ✗ | YES |
| A05 | H2 Console Enabled | ✓ | ✓ | ✗ | NO |
| A05 | Debug Features On | ✓ | ✓ | ✗ | NO |
| A05 | Missing Security Headers | ✓ | ✓ | ✗ | YES |
| A06 | EOL Libraries | ✓ | ✓ | ✗ | YES |
| A07 | Hardcoded Credentials | ✓ | ✓ | ✓ | NO |
| A07 | Weak Password Hashing | ✓ | ✓ | ✓ | NO |
| A07 | Cookie Missing HttpOnly/Secure | ✓ | ✓ | ✓ | NO |
| A08 | Insecure Deserialization | ✓ | ✓ | ✓ | YES |
| A08 | Serializable w/o serialVersionUID | ✓ | ✓ | ✓ | YES |
| A09 | Exception Disclosure | ✓ | ✓ | ✓ | YES |
| A09 | printStackTrace | ✓ | ✓ | ✓ | NO |
| A09 | Missing Audit Logging | ✓ | ✓ | ✓ | YES |
| A10 | SSRF | ✓ | ✓ | ✓ | YES |
| File Upload | Extension-Only Validation | ✓ | ✓ | ✗ | YES |
| File Upload | Path Traversal | ✓ | ✓ | ✓ | YES |
| XSS | innerHTML / bypassSecurityTrust | ✓ | ✓ | ✓ | NO |
| XSS | Token in localStorage | ✓ | ✓ | ✓ | NO |

---

## Tech Stack Applicability Matrix

| Pattern | Java / Spring | Python / Django | Node.js / Express | .NET / ASP.NET | Angular / TypeScript |
|---------|---|---|---|---|---|
| No Authentication | ✓ | ✓ | ✓ | ✓ | ✓ |
| IDOR | ✓ | ✓ | ✓ | ✓ | N/A |
| CORS Wildcard | ✓ | ✓ | ✓ | ✓ | N/A |
| Hardcoded Secret | ✓ | ✓ | ✓ | ✓ | ✓ |
| Weak Hash | ✓ | ✓ | ✓ | ✓ | N/A |
| SQL Concatenation | ✓ | ✓ | ✓ | ✓ | N/A |
| XXE | ✓ | ✓ | ✓ | ✓ | N/A |
| Missing Input Validation | ✓ | ✓ | ✓ | ✓ | ✓ |
| No HTTPS | ✓ | ✓ | ✓ | ✓ | ✓ |
| innerHTML / XSS | N/A | N/A | N/A | N/A | ✓ |
| Token in localStorage | N/A | N/A | N/A | N/A | ✓ |

---

## How to Use This Database for Your SAST Pipeline

### Step 1: Tech Stack Detection
```
Scan detects: Java + Spring + JWT + JDBC
```

### Step 2: Query Applicable Rules
```sql
SELECT * FROM detection_patterns
WHERE language IN ('java', 'generic')
  AND tech_components ⊇ ['Spring', 'JWT', 'JDBC']
ORDER BY severity DESC
```

### Step 3: For Each CRITICAL File
```
1. Parse with tree-sitter (Java grammar)
2. Run tree-sitter queries for each rule
3. Collect AST node matches (file, line, context)
4. If requires_llm: send to LLM for verification
5. Collect confirmed findings
```

### Step 4: LLM Verification (for rules marked `requires_llm: YES`)
```
Send to LLM:
  - Code snippet
  - Parent/sibling context (class, method, field definitions)
  - Relevant configuration files
  - Specific question (see "LLM Verification Prompt" for each pattern)
```

---

## Data Format for Detection Rules Database

```json
{
  "id": "a01-no-authentication",
  "category": "A01:2021 - Broken Access Control",
  "language": ["java", "python", "nodejs", "csharp"],
  "tech_components": ["Spring", "Django", "Express", "ASP.NET"],
  "severity": "CRITICAL",
  "cvss_score": 9.1,
  "pattern_name": "No Authentication on Endpoints",
  "description": "REST endpoints publicly accessible without auth",
  "detection_methods": {
    "grep": "@GetMapping|@PostMapping + NO @PreAuthorize",
    "semgrep": "@RestController method without @PreAuthorize",
    "tree_sitter": "(method_declaration (annotation*) @annos) where PreAuthorize NOT IN @annos"
  },
  "requires_llm_verification": true,
  "llm_prompt": "...",
  "remediation": "Add @PreAuthorize(\"hasRole('USER')\")"
}
```

---

## Notes & References

- **NPC Patterns:** From `NPC-SECURITY_SCAN_PATTERNS.md` (Struts/EJB/JAX-RS/JWT project)
- **Spring Boot Reports:** From `OWASP_Vulnerability_Report.md` and `OWASP_Vulnerability_Report_Bedrock_Enterprise.md`
- **Sources Consolidated:** 
  - Original 3 files (OWASP reports × 2 + NPC patterns)
  - Deduplicated by OWASP category
  - Organized by pattern name and tech stack applicability
  - Enriched with detection methods (grep, semgrep, tree-sitter)

---

**Last Updated:** 2026-08-06  
**Format Version:** 1.0  
**Maintainer:** SAST Pipeline Team
