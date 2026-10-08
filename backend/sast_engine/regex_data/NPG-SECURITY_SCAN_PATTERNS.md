# Security Scan Patterns — NPG Vodafone Project
## Tech Stack: Java EE 6 · Struts 1.x · EJB 3 · Axis2 SOAP · JBoss · Drools 6 · Oracle JDBC · JSch · Maven

---

## HOW GREP PATTERNS WERE DECIDED

```
Tech Stack Detected → Known Vulnerability Surface → Targeted Regex
─────────────────────────────────────────────────────────────────
Java + JDBC (Oracle)  → SQL Injection          → createStatement / executeQuery / concat
Struts 1.x Actions    → Input handling         → request.getParameter / ActionForm
Axis2 SOAP Stubs      → SSRF / XXE             → XMLInputFactory / EndpointReference / MnpserviceStub
JSch 0.1.38           → Credential exposure    → jsch / StrictHostKeyChecking / password
Drools 6 / Castor     → Deserialization        → ObjectInputStream / readObject
java.util.Random      → Weak random            → new Random() in security contexts
commons-collections   → Gadget chain risk      → implements Serializable
Runtime.exec          → Command injection      → getRuntime().exec / RunUtility
Maven pom.xml         → Outdated components    → struts / axis2 / xerces / castor / jsch / drools
```

---

## PART 1 — GREP PATTERNS (for grep / VS Code Search / rg)

### A01 — Broken Access Control

```
# Session not invalidated on logout (check LogoutAction)
grep -rn "invalidate\(\)\|session\.invalidate\|logoff\|logout" --include="*.java"

# Direct HTTP parameter used in business logic without authorization check
grep -rn "request\.getParameter\|getParameterValues\|getParameterNames" --include="*.java"

# Object access via user-supplied IDs (porting/worklist)
grep -rn "getPortId\|getPortData\|getObjectId\|objectId.*request" --include="*.java"

# Path traversal — getLinkName / file path from user input
grep -rn "getLinkName\(\)\|new File(.*request\|new File(.*param" --include="*.java"
```

---

### A02 — Cryptographic Failures

```
# Weak hash algorithms
grep -rn "getInstance\(\"MD5\"\)\|getInstance\(\"SHA-1\"\)\|getInstance\(\"SHA1\"\)" --include="*.java"

# Broken symmetric ciphers
grep -rn "getInstance\(\"DES\"\)\|getInstance\(\"RC4\"\)\|PBEWithMD5AndDES" --include="*.java"

# Insecure Random used in security-sensitive contexts
# Found: SecurityMgrImpl (session ID), RequestsMgrIn, TcpClient, FTPAbdFiles
grep -rn "new Random()\|Math\.random()" --include="*.java"

# JSch: StrictHostKeyChecking disabled (MITM risk)
grep -rn "StrictHostKeyChecking\|\"no\"\|setConfig.*strict" --include="*.java"

# JSch: password in code / config
grep -rn "jsch\.connect\|session\.setPassword\|setPassword\|jsch.*pass" --include="*.java"

# Cookies missing flags (no setHttpOnly found — verify filter exists)
grep -rn "setHttpOnly\|setSecure\|addCookie\|new Cookie" --include="*.java"

# HTTP transport guarantee not enforced
grep -rn "transport-guarantee\|NONE\|CONFIDENTIAL" --include="*.xml"
```

---

### A03 — Injection

```
# SQL string concatenation (SQLi) — xnp/db/* classes and JDBC utilities
grep -rn "\"SELECT\|\"INSERT\|\"UPDATE\|\"DELETE" --include="*.java" | grep "\+"
grep -rn "String.*sql.*=.*+\|String.*query.*=.*+\|String.*sqlString.*=.*+" --include="*.java"

# Unparameterized statements
grep -rn "createStatement()\|executeQuery(sql)\|executeQuery(query)\|executeUpdate(sql)" --include="*.java"

# XXE — XMLInputFactory without disabling external entities
# Confirmed in: MnpServiceServerImpl, BulkSyncMsgProcessor, MultiThreadBulkSyncMsgProcessor
grep -rn "XMLInputFactory\.newInstance()\|DocumentBuilderFactory\.newInstance()" --include="*.java"
grep -rn "IS_SUPPORTING_EXTERNAL_ENTITIES\|FEATURE_SECURE_PROCESSING" --include="*.java"

# Command injection — Runtime.exec with dynamic paths
# Confirmed in: RecursiveSearch.java, RunUtility.java
grep -rn "Runtime\.getRuntime()\.exec\|ProcessBuilder\|new ProcessBuilder" --include="*.java"

# LDAP injection (if used)
grep -rn "DirContext\|InitialDirContext\|NamingEnumeration" --include="*.java"
```

---

### A04 — Insecure Design

```
# Login attempt limit hardcoded (SecurityMgrImpl loginAttempts = 5)
grep -rn "loginAttempts\s*=\s*5\|maxLoginAttempts\|maxAttempts" --include="*.java"

# CSRF salt: verify ALL ActionForms have csrfPreventionSalt
grep -rn "csrfPreventionSalt\|CSRFPreventionLicence\|LoadSalt" --include="*.java"

# CSRF salt coverage — identify ActionForms missing salt field
grep -rn "extends ActionForm\|extends IValidatorForm\|extends IDispatchAction" --include="*.java"
# Cross-check: forms without csrfPreventionSalt are unprotected

# No rate limiting on SOAP endpoints
grep -rn "rateLim\|throttle\|RateLimiter" --include="*.java"
```

---

### A05 — Security Misconfiguration

```
# Security response headers — none found in codebase; confirm filter exists
grep -rn "X-Frame-Options\|X-Content-Type-Options\|X-XSS-Protection\|Content-Security-Policy\|Strict-Transport-Security" --include="*.java"

# CORS / access control headers
grep -rn "Access-Control-Allow-Origin\|addHeader.*\*" --include="*.java"

# Axis2 admin/services endpoint exposed
grep -rn "AdminAgent\|axis2-admin\|services/list" --include="*.xml"

# Debug / verbose error output to client
grep -rn "printStackTrace\|e\.getMessage()\|ex\.toString()" --include="*.java"

# Transport guarantee is NONE in web-secure.xml (line 256) — HTTPS not enforced
grep -n "transport-guarantee\|NONE\|CONFIDENTIAL" NPGParent/NPGWebGUIIn/NPGWebGUIIn/WEB-INF/web-secure.xml

# Session timeout mismatch: web.xml=30, web-secure.xml=120
grep -rn "session-timeout" --include="*.xml"
```

---

### A06 — Vulnerable and Outdated Components

```
# In pom.xml — EOL / vulnerable versions
grep -n "struts.*1\.\|axis2.*1\.4\|xerces.*2\.\(11\|[0-9]\)\.\|castor-xml\|commons-collections.*3\.\|jsch.*0\.1\.\|drools.*6\.\|commons-lang.*2\." NPGParent/pom.xml

# All dependency versions in one pass
grep -n "<version>" NPGParent/pom.xml

# jaxb 2.2.11 (EOL — replaced by Jakarta EE JAXB)
grep -n "jaxb" NPGParent/pom.xml

# Detailed EOL check per component
grep -n "struts-core\|struts-taglib" NPGParent/pom.xml
grep -n "axis2" NPGParent/pom.xml
grep -n "xercesImpl\|xerces" NPGParent/pom.xml
grep -n "castor-xml" NPGParent/pom.xml
grep -n "jsch" NPGParent/pom.xml
grep -n "drools" NPGParent/pom.xml
```

---

### A07 — Identification and Authentication Failures

```
# Hardcoded default credentials in properties / code
grep -rn "\"npg\"\|\"admin\"\|\"password\"\|\"secret\"\|\"test123\"\|\"changeme\"" --include="*.java"
grep -rn "getString.*password\|getProperty.*password" --include="*.java"

# JSch password exposed in source
grep -rn "setPassword\|setUsername\|jsch.*pass\|sftpPass" --include="*.java"

# Login attempt default hardcoded (not from config)
grep -rn "loginAttempts\s*=\s*5\|parseInt.*attempts" --include="*.java"

# Password in log output
grep -rn "log.*password\|logger.*password\|print.*password" --include="*.java"

# Session timeout inconsistency
grep -rn "session-timeout" --include="*.xml"

# Session invalidation on logout (verify actual invalidate() call)
grep -rn "session\.invalidate\|invalidate()" NPGParent/NPGWebGUIIn/src/com/telcordia/npg/login/LogoutAction.java
```

---

### A08 — Software and Data Integrity Failures

```
# ObjectInputStream / deserialization
# Confirmed in: SecurityMgrTestClient1.java, TimerViolationData.java, WorkListData.java
grep -rn "ObjectInputStream\|readObject()\|defaultReadObject" --include="*.java"

# Serializable classes in ComInterface (attack surface with commons-collections 3.2)
grep -rn "implements Serializable\|implements java\.io\.Serializable" --include="*.java"

# Castor XML deserialization (unmarshalling from XML — type-confusion risk)
grep -rn "Unmarshaller\|unmarshal\|Marshaller" --include="*.java"

# Drools rule loading from external source
grep -rn "KnowledgeBuilder\|addKnowledgePackage\|newKnowledgeBase\|kieSession" --include="*.java"
```

---

### A09 — Security Logging and Monitoring Failures

```
# Exception swallowed silently
grep -rn "catch.*Exception.*{$\|} catch.*{ *}" --include="*.java"

# Exception / stacktrace to stdout (not logger)
# Confirmed in: NPGSoapService, PortingSynAction, PortingSynActionForm, ReportSearchAction, TNSearchAction
grep -rn "System\.out\.print\|e\.printStackTrace()" --include="*.java"

# ex.toString() passed to logger (exposes internal paths / class names)
# Confirmed in: PreferencesAction, StaticListsPageBean, SystemStatusAction, TimerAction, etc.
grep -rn "_logger\.error.*ex\.toString\|logger.*ex\.toString\(\)" --include="*.java"

# SQL error details exposed
grep -rn "getSQLState()\|getErrorCode()\|getVendorCode()" --include="*.java"
```

---

### A10 — SSRF

```
# SOAP endpoint URLs controlled by config / property (verify source of ossSoapURL)
# Confirmed: OssSoapClient.java uses URL(ossSoapURL) from config
grep -rn "getProperty.*[Uu]rl\|getProperty.*[Hh]ost\|getProperty.*[Ee]ndpoint\|ossSoapURL" --include="*.java"

# Axis2 EndpointReference with externally supplied URL
# Confirmed: NPServiceProcessStub, PartSoapServiceClientIn, SOAPComposeIn
grep -rn "EndpointReference\|setTargetEPR\|setTo.*EndpointReference" --include="*.java"

# MnpserviceStub SOAP endpoint
grep -rn "MnpserviceStub\|_serviceClient.*setTo" --include="*.java"

# Hardcoded localhost WSDL paths (also path disclosure)
# Found: NPGSoapService_Service.java, NPServiceProcess_Service.java
grep -rn "new URL(\"file:/\|new URL(\"http://localhost" --include="*.java"
```

---

### JSch / SFTP Security (NPG-specific surface)

```
# JSch version 0.1.38 is EOL — no fixes since 2018
grep -n "jsch" NPGParent/pom.xml

# StrictHostKeyChecking disabled (MITM on SFTP servers)
grep -rn "StrictHostKeyChecking\|\"no\"\|setConfig" NPGParent/NPGCore/src/com/telcordia/npg/sftp/JschFactory.java

# Credentials from properties — verify not hardcoded
grep -rn "setPassword\|setUsername" NPGParent/NPGCore/src/com/telcordia/npg/sftp/JschFactory.java

# File stored with computed random name using Math.random() (weak name, guessable)
grep -rn "Math\.random\(\)" NPGParent/NPGCore/src/com/telcordia/npg/sftp/FTPAbdFiles.java
```

---

### Drools Rules Engine (NPG-specific surface)

```
# Rule files loaded from external / configurable paths (rule injection risk)
grep -rn "addResource\|ResourceFactory\|newFileSystemResource\|newClassPathResource" --include="*.java"

# Drools 6.0.0.Final is EOL — multiple unpatched CVEs
grep -n "drools" NPGParent/pom.xml

# KieSession / StatelessKieSession with user data (OGNL-like expression risk)
grep -rn "KieSession\|StatelessKieSession\|insert.*portData\|fireAllRules" --include="*.java"
grep -rn "kieSession\|KnowledgeBase" NPGParent/NPGWebGUIIn/
```

---

### Struts ActionForm / JSP (Frontend surface)

```
# XSS — raw request parameter written to JSP without escaping
grep -rn "<bean:write\|<%= request\.\|<%= param\." --include="*.jsp"

# Struts 1.x <html:text> tag (auto-escaping varies)
grep -rn "<html:text\|<html:textarea\|<html:hidden" --include="*.jsp"

# ActionForm.reset() not overridden (checkbox attack)
grep -rn "public void reset\|public void validate" --include="*.java"

# Struts 1.x is EOL since 2013 — no security patches
grep -n "struts-core\|struts-taglib\|struts-1\." NPGParent/pom.xml
```

---

## PART 2 — SEMGREP RULES

> Run: `semgrep --config semgrep-npg-rules.yaml NPGParent/`

```yaml
rules:

  # ─────────────────────────────────────────────
  # A02 — Insecure Random in Security Context
  # ─────────────────────────────────────────────
  - id: insecure-random-security-context
    patterns:
      - pattern: new Random()
      - pattern-not-inside: |
          // ... test ...
    message: "java.util.Random is not cryptographically secure — use SecureRandom (confirmed in SecurityMgrImpl, RequestsMgrIn)"
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
  # A03 — Unparameterized createStatement
  # ─────────────────────────────────────────────
  - id: unparameterized-statement
    patterns:
      - pattern: $CONN.createStatement()
    message: "createStatement() found — verify all SQL using this statement uses parameterized queries"
    languages: [java]
    severity: WARNING
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
    message: "XMLInputFactory allows external entities by default — set IS_SUPPORTING_EXTERNAL_ENTITIES=false (confirmed in MnpServiceServerImpl, BulkSyncMsgProcessor)"
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
    message: "Runtime.exec with string argument — shell metacharacter injection possible (RecursiveSearch, RunUtility)"
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
      ...
      loginAttempts = ...parseInt(...);
    message: "Login attempt limit initialized to hardcoded 5 — load from config to allow ops tuning"
    languages: [java]
    severity: INFO
    metadata:
      owasp: A04

  # ─────────────────────────────────────────────
  # A05 — Transport guarantee NONE in web-secure.xml
  # ─────────────────────────────────────────────
  - id: transport-guarantee-none
    pattern: |
      <transport-guarantee>NONE</transport-guarantee>
    message: "transport-guarantee is NONE — HTTPS not enforced for this security constraint"
    languages: [xml]
    severity: ERROR
    metadata:
      owasp: A05

  # ─────────────────────────────────────────────
  # A06 — Struts 1.x (EOL)
  # ─────────────────────────────────────────────
  - id: struts1-dependency
    pattern: |
      <artifactId>struts-core</artifactId>
      <version>1.$VERSION</version>
    message: "Struts 1.x is End-of-Life since 2013 — upgrade to Spring MVC or Jakarta Faces"
    languages: [xml]
    severity: ERROR
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A06 — Axis2 1.4.1 (EOL / CVE-2023-40743 etc.)
  # ─────────────────────────────────────────────
  - id: axis2-eol-version
    pattern: |
      <artifactId>axis2-kernel</artifactId>
      <version>1.4.$V</version>
    message: "Axis2 1.4.x is EOL with critical CVEs (CVE-2023-40743) — upgrade to CXF or JAX-WS RI"
    languages: [xml]
    severity: ERROR
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A06 — commons-collections 3.2 (gadget chain)
  # ─────────────────────────────────────────────
  - id: commons-collections-vulnerable
    pattern: |
      <artifactId>commons-collections</artifactId>
      <version>3.2</version>
    message: "commons-collections 3.2 enables deserialization gadget chains (Apache Commons exploit) — upgrade to 3.2.2+"
    languages: [xml]
    severity: ERROR
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A06 — JSch 0.1.38 (EOL)
  # ─────────────────────────────────────────────
  - id: jsch-eol-version
    pattern: |
      <artifactId>jsch</artifactId>
      <version>0.1.$V</version>
    message: "JSch 0.1.x is EOL (last release 2018) — migrate to Apache MINA SSHD or jcraft jsch 0.2.x fork"
    languages: [xml]
    severity: WARNING
    metadata:
      owasp: A06

  # ─────────────────────────────────────────────
  # A07 — Session Timeout Mismatch (web-secure.xml=120 vs web.xml=30)
  # ─────────────────────────────────────────────
  - id: session-timeout-inconsistency
    patterns:
      - pattern: <session-timeout>120</session-timeout>
    message: "web-secure.xml sets session-timeout=120min, web.xml uses 30min — align to the shorter value"
    languages: [xml]
    severity: WARNING
    metadata:
      owasp: A07

  # ─────────────────────────────────────────────
  # A08 — ObjectInputStream deserialization
  # ─────────────────────────────────────────────
  - id: object-input-stream-deserialization
    patterns:
      - pattern: |
          ObjectInputStream $OIS = new ObjectInputStream(...);
          ...
          $OIS.readObject();
    message: "ObjectInputStream.readObject() with commons-collections 3.2 on classpath — deserialization gadget chain risk"
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
    message: "Serializable domain object without serialVersionUID — review for deserialization gadget chain risk (commons-collections 3.2 present)"
    languages: [java]
    severity: INFO
    metadata:
      owasp: A08

  # ─────────────────────────────────────────────
  # A09 — printStackTrace to stdout
  # ─────────────────────────────────────────────
  - id: print-stack-trace
    pattern: $E.printStackTrace()
    message: "printStackTrace() writes to stdout — use logger.error('msg', e) instead (confirmed in NPGSoapService, PortingSynAction, ReportSearchAction)"
    languages: [java]
    severity: WARNING
    metadata:
      owasp: A09

  # ─────────────────────────────────────────────
  # A09 — ex.toString() exposed via logger (path / class leak)
  # ─────────────────────────────────────────────
  - id: exception-tostring-in-logger
    pattern: $LOG.error("...", $E.toString())
    message: "ex.toString() in logger may expose internal class names and paths — use logger.error('msg', e) to preserve stack without string coercion"
    languages: [java]
    severity: INFO
    metadata:
      owasp: A09

  # ─────────────────────────────────────────────
  # A10 — SSRF via Axis2 EndpointReference from config
  # ─────────────────────────────────────────────
  - id: ssrf-axis2-endpoint-from-config
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
| A01 | Direct object ref via request.getParameter | `request\.getParameter` | — |
| A01 | Path traversal via getLinkName | `getLinkName\(\)` | — |
| A02 | `new Random()` in SecurityMgrImpl session ID | `new Random\(\)` | `insecure-random-security-context` |
| A02 | JSch StrictHostKeyChecking | `StrictHostKeyChecking` | — |
| A03 | SQL string concat in xnp/db/* | `String.*sqlString.*=.*+` | `sql-string-concat` |
| A03 | createStatement() (unparameterized) | `createStatement\(\)` | `unparameterized-statement` |
| A03 | XXE in MnpServiceServerImpl, BulkSync | `XMLInputFactory\.newInstance\(\)` | `xxe-xmlinputfactory` |
| A03 | Command injection in RecursiveSearch, RunUtility | `getRuntime\(\)\.exec` | `command-injection-runtime-exec` |
| A04 | Hardcoded login attempts = 5 | `loginAttempts\s*=\s*5` | `hardcoded-login-attempt-limit` |
| A04 | CSRF partial (not all ActionForms) | `csrfPreventionSalt` (absent in some) | — |
| A05 | No security headers in codebase | `X-Frame-Options` (absent) | — |
| A05 | Transport-guarantee NONE | `transport-guarantee.*NONE` | `transport-guarantee-none` |
| A05 | Session timeout mismatch 30 vs 120 | `session-timeout` | `session-timeout-inconsistency` |
| A06 | Struts 1.3.10 (EOL 2013) | `struts-core.*1\.` | `struts1-dependency` |
| A06 | Axis2 1.4.1 (EOL / CVE-2023-40743) | `axis2.*1\.4` | `axis2-eol-version` |
| A06 | commons-collections 3.2 (gadget chain) | `commons-collections.*3\.2` | `commons-collections-vulnerable` |
| A06 | JSch 0.1.38 (EOL 2018) | `jsch.*0\.1\.` | `jsch-eol-version` |
| A06 | xerces 2.11.0 (EOL) | `xerces.*2\.11` | — |
| A06 | drools 6.0.0.Final (EOL) | `drools.*6\.0` | — |
| A06 | castor-xml 1.4.1 (EOL) | `castor-xml.*1\.4` | — |
| A07 | Session timeout mismatch | `session-timeout` in .xml | `session-timeout-inconsistency` |
| A08 | ObjectInputStream + commons-collections 3.2 | `ObjectInputStream\|readObject\(\)` | `object-input-stream-deserialization` |
| A08 | Serializable ComInterface classes | `implements Serializable` | `serializable-domain-object` |
| A09 | printStackTrace (NPGSoapService, Porting*) | `printStackTrace\(\)` | `print-stack-trace` |
| A09 | ex.toString() in logger calls | `ex\.toString\(\)` | `exception-tostring-in-logger` |
| A10 | SSRF via SOAP endpoint from config | `ossSoapURL\|getProperty.*[Uu]rl` | `ssrf-axis2-endpoint-from-config` |
| A10 | Hardcoded localhost WSDL URLs | `new URL\(\"http://localhost` | — |

---

## PART 4 — HOW GREP PATTERNS WERE DECIDED (Decision Logic)

```
Java + JDBC (Oracle ojdbc8) detected
  └─► grep: createStatement / executeQuery + concat → SQLi surface
  └─► xnp/db/* package confirmed: all DELETE/SELECT/INSERT/UPDATE use string concat

Axis2 SOAP (1.4.1) detected
  └─► grep: XMLInputFactory.newInstance() → XXE risk (no entity disable found)
  └─► grep: EndpointReference / setTo / new URL(ossSoapURL) → SSRF via config

JSch (0.1.38) detected
  └─► grep: setPassword / StrictHostKeyChecking → credential exposure / MITM risk
  └─► Version is EOL since 2018 — no CVE patches applied

Runtime.exec detected
  └─► grep: getRuntime().exec → command injection (RecursiveSearch, RunUtility)

commons-collections 3.2 + Serializable classes detected
  └─► grep: ObjectInputStream / readObject → deserialization gadget chain
  └─► ComInterface package has 10+ Serializable transfer objects

Drools 6.0 detected
  └─► grep: addResource / newFileSystemResource → rule injection from external path
  └─► Version is EOL — upgrade to drools 8.x / kogito

Struts 1.x ActionForms detected
  └─► grep: csrfPreventionSalt → CSRF partial coverage (not all forms)
  └─► grep: request.getParameter → direct HTTP input to business logic

Maven pom.xml detected
  └─► grep: struts 1.3.10 / axis2 1.4.1 / xerces 2.11 / castor 1.4 / jsch 0.1.38 / drools 6.0 → EOL audit
```

---

*Generated by GitHub Copilot security scan — 2026-08-05*
*Run Semgrep rules: `semgrep --config NPG-SECURITY_SCAN_PATTERNS.md NPGParent/`*
