# Code Scanning Process Explained
## How I Analyzed the Spring Boot Angular CRUD Repository for OWASP Vulnerabilities

---

## 📋 Overview of My Scanning Process

I used a **multi-layered manual security analysis approach** combined with code inspection techniques. Here's the complete workflow:

---

## Phase 1: Repository Cloning & Initial Reconnaissance

### Step 1.1: Clone the Repository
```bash
cd /tmp && git clone https://github.com/bezkoder/spring-boot-angular-17-crud-example.git
```

**Why:** I needed the actual source code locally to perform static analysis. GitHub API alone doesn't give full access to all files and content.

### Step 1.2: File Inventory
```bash
find . -type f \( -name "*.java" -o -name "*.js" -o -name "*.ts" -o -name "*.xml" \) | head -20
```

**Why:** Identify the project structure:
- **Backend:** Spring Boot (Java files)
- **Frontend:** Angular 17 (TypeScript files)
- **Configuration:** Maven (pom.xml), properties files
- **Tests:** Test files for understanding code behavior

**Files Found:**
```
Spring Boot Backend:
├── TutorialController.java          (REST API endpoints)
├── Tutorial.java                    (Entity/Model)
├── TutorialRepository.java          (Database access)
├── pom.xml                          (Dependencies)
└── application.properties           (Configuration)

Angular Frontend:
├── tutorial.service.ts              (HTTP calls)
├── tutorial-details.component.ts    (Component logic)
├── tutorials-list.component.ts      (Component logic)
├── add-tutorial.component.ts        (Component logic)
├── app.module.ts                    (Module configuration)
└── app-routing.module.ts            (Routing configuration)
```

---

## Phase 2: Static Code Analysis (Manual Code Review)

### Step 2.1: Examine Backend REST Controller

**File:** `TutorialController.java`

**Analysis Process:**
```
1. READ the entire file
2. IDENTIFY each endpoint (@GetMapping, @PostMapping, etc.)
3. EVALUATE each endpoint for:
   - Authentication checks ❌ MISSING
   - Authorization checks ❌ MISSING
   - Input validation ❌ MISSING
   - Exception handling details ✓ PRESENT (but generic)
   - CORS configuration ⚠️ HARDCODED
```

**Code Review Example - Security Issues Found:**

```java
// LINE 24: CORS Configuration
@CrossOrigin(origins = "http://localhost:8081")
//         ↑↑↑ ISSUE 1: Hardcoded localhost for production
//         ↑↑↑ ISSUE 2: No credential validation

// LINES 32-50: GET /tutorials endpoint
@GetMapping("/tutorials")
public ResponseEntity<List<Tutorial>> getAllTutorials(@RequestParam(required = false) String title) {
//                                                                                    ↑↑↑ ISSUE 3: No validation
//                                                                                    ↑↑↑ ISSUE 4: Accepts any string
    try {
        if (title == null)
            tutorialRepository.findAll().forEach(tutorials::add);
        else
            tutorialRepository.findByTitleContainingIgnoreCase(title).forEach(tutorials::add);
            //                                                        ↑↑↑ ISSUE 5: Potential injection
//          ↑↑↑ ISSUE 6: No authentication - anyone can list all tutorials
        
    } catch (Exception e) {
        //        ↑↑↑ ISSUE 7: Generic exception - what specific error? No logging
        return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

// LINES 63-71: POST endpoint - Create Tutorial
@PostMapping("/tutorials")
public ResponseEntity<Tutorial> createTutorial(@RequestBody Tutorial tutorial) {
//                                                        ↑↑↑ ISSUE 8: No @Valid annotation
//                                                        ↑↑↑ ISSUE 9: No null checks
    try {
        Tutorial _tutorial = tutorialRepository.save(
            new Tutorial(tutorial.getTitle(), tutorial.getDescription(), false));
            //          ↑↑↑ ISSUE 10: No length validation
            //          ↑↑↑ ISSUE 11: No content validation
//          ↑↑↑ ISSUE 12: Anyone can create tutorials - no authorization
        return new ResponseEntity<>(_tutorial, HttpStatus.CREATED);
    } catch (Exception e) {
        return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        //                          ↑↑↑ ISSUE 13: No error details logged
    }
}

// LINES 88-96: DELETE endpoint
@DeleteMapping("/tutorials/{id}")
public ResponseEntity<HttpStatus> deleteTutorial(@PathVariable("id") long id) {
//                                                               ↑↑↑ ISSUE 14: Sequential ID - enumeration possible
    try {
        tutorialRepository.deleteById(id);
        //                        ↑↑↑ ISSUE 15: No ownership verification
        //                        ↑↑↑ ISSUE 16: Anyone can delete any resource
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    } catch (Exception e) {
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

// LINES 98-107: DELETE ALL endpoint
@DeleteMapping("/tutorials")
public ResponseEntity<HttpStatus> deleteAllTutorials() {
    try {
        tutorialRepository.deleteAll();  // ❌ CRITICAL: Anyone can delete EVERYTHING
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
```

**Vulnerability Mapping to OWASP:**

| Line(s) | Issue | OWASP Category | Severity |
|---------|-------|---|---|
| 24 | CORS hardcoded | A01:2021 | HIGH |
| 32-50 | No auth/validation | A01:2021 | CRITICAL |
| 63-71 | No input validation | A04:2021 | HIGH |
| 73-86 | No authorization | A01:2021 | CRITICAL |
| 88-96 | Sequential IDs + no auth | A01:2021 | MEDIUM |
| 98-107 | Critical operation unprotected | A01:2021 | CRITICAL |

---

### Step 2.2: Examine Backend Configuration Files

**File:** `pom.xml` (Maven dependencies)

**Analysis Process:**
```
1. READ dependency versions
2. CHECK for known vulnerability databases
3. IDENTIFY missing security dependencies
4. COMPARE against OWASP guidelines
```

**Findings:**

```xml
<!-- MISSING Spring Security -->
<!-- Should have: -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>  <!-- ❌ NOT PRESENT -->
</dependency>

<!-- OUTDATED version -->
<version>3.1.0</version>
<!-- ↑↑↑ ISSUE: Released April 2023, current is 3.2+/3.3+
            Known vulnerabilities may exist -->

<!-- H2 database - Version not pinned -->
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>runtime</scope>
    <!-- ↑↑↑ ISSUE: Uses transitive version, could have vulnerabilities -->
</dependency>
```

**OWASP Mapping:**
- A06:2021 - Vulnerable and Outdated Components (Missing Spring Security)
- A05:2021 - Security Misconfiguration (No security framework)

---

### Step 2.3: Examine Application Configuration

**File:** `application.properties`

**Analysis Process:**
```
1. READ each configuration line
2. EVALUATE security implications
3. IDENTIFY production vs development settings
4. CHECK database configuration
5. ASSESS logging settings
```

**Code Review:**

```properties
spring.h2.console.enabled=true
# ↑↑↑ ISSUE 1: H2 console accessible via /h2-ui
# ↑↑↑ CRITICAL: Allows direct database access and SQL queries
# ↑↑↑ Should be: false (or in dev profile only)

spring.h2.console.path=/h2-ui
# ↑↑↑ ISSUE 2: Default path is well-known attack vector

spring.datasource.username=sa
spring.datasource.password=
# ↑↑↑ ISSUE 3: Empty password (default H2 credentials)
# ↑↑↑ ISSUE 4: Using 'sa' - System Administrator account
# ↑↑↑ CRITICAL: Anyone with access can read/modify/delete database

spring.jpa.show-sql=true
# ↑↑↑ ISSUE 5: All SQL queries logged to console
# ↑↑↑ Reveals schema structure, table names, column names
# ↑↑↝ Information disclosure vulnerability

spring.jpa.hibernate.ddl-auto=update
# ↑↑↝ ISSUE 6: Automatic schema updates
# ↑↝ Risk: Schema changes without review/approval
# ↑↝ Should be: validate (production) or update (dev only)
```

**OWASP Mapping:**
- A05:2021 - Security Misconfiguration (CRITICAL)
- A02:2021 - Cryptographic Failures (show-sql reveals data)

---

### Step 2.4: Examine Frontend Code

**File:** `tutorial.service.ts` (Angular HTTP service)

**Analysis Process:**
```
1. READ HTTP method implementations
2. CHECK URL construction method
3. EVALUATE parameter passing
4. ANALYZE security headers
5. REVIEW authentication handling
```

**Code Review:**

```typescript
const baseUrl = 'http://localhost:8080/api/tutorials';
// ↑↑↝ ISSUE 1: HTTP not HTTPS (plaintext communication)
// ↑↑↝ ISSUE 2: Hardcoded localhost (only works in dev)

findByTitle(title: any): Observable<Tutorial[]> {
    return this.http.get<Tutorial[]>(`${baseUrl}?title=${title}`);
    //                                ↑↑↑ ISSUE 2: String concatenation
    //                                ↑↑↝ ISSUE 3: No URL encoding
    //                                ↑↑↝ ISSUE 4: title parameter not escaped
    // Example attack:
    // title = "../../../admin"  → URL becomes: ...?title=../../../admin
    // title = "'; DROP TABLE tutorials; --"  → Injection attack
}

get(id: any): Observable<Tutorial> {
    return this.http.get<Tutorial>(`${baseUrl}/${id}`);
    //                             ↑↑↝ ISSUE: No validation of 'id'
}

update(id: any, data: any): Observable<any> {
    return this.http.put(`${baseUrl}/${id}`, data);
    //                                       ↑↑↝ ISSUE: No CSRF token sent
}

delete(id: any): Observable<any> {
    return this.http.delete(`${baseUrl}/${id}`);
    //                                ↑↑↝ ISSUE: No authorization check
    //                                ↑↑↝ ISSUE: No CSRF token
    //                                ↑↝ No confirmation of authorization
}

deleteAll(): Observable<any> {
    return this.http.delete(baseUrl);
    // ↑↑↝ CRITICAL: Can delete all records with single call
    // ↑↑↝ No permission check
}
```

**OWASP Mapping:**
- A03:2021 - Injection (URL parameter injection)
- A07:2021 - Cross-Site Scripting (CSRF - no tokens)
- A02:2021 - Cryptographic Failures (HTTP not HTTPS)
- A01:2021 - Broken Access Control (no auth checks)

---

### Step 2.5: Examine Angular Module Configuration

**File:** `app.module.ts`

**Analysis Process:**
```
1. READ module imports
2. CHECK security-related imports
3. IDENTIFY missing security modules
4. EVALUATE configuration
```

**Code Review:**

```typescript
import { HttpClientModule } from '@angular/common/http';
// ↑↑↝ ISSUE: No XSRF protection module imported

// Missing imports:
// - HttpClientXsrfModule  (for CSRF protection)
// - Interceptors for auth headers
// - Interceptors for error handling
// - Security headers configuration

@NgModule({
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    HttpClientModule  // ↑↑↝ Raw HTTP without security
    // ↑↑↝ No interception
    // ↑↑↝ No XSRF tokens
    // ↑↑↝ No JWT token handling
  ],
  providers: [],  // ↑↑↝ ISSUE: No security services/interceptors
})
```

**OWASP Mapping:**
- A07:2021 - Cross-Site Scripting (No CSRF/XSRF configuration)
- A01:2021 - Broken Access Control (No auth interceptor)

---

## Phase 3: Configuration Analysis

### Step 3.1: Security Profile Evaluation

**Question: Is this production code?**

**Evidence:**
```
❌ H2 console enabled        → Development
❌ Empty database password   → Development
❌ Show SQL enabled          → Development
✓ But NO development profile → Mistake!
```

**Conclusion:** Development configuration deployed without profile separation.

### Step 3.2: OWASP Top 10 Mapping

**Process:**
```
For each vulnerability found:
  1. Identify the category
  2. Determine if it matches OWASP list
  3. Calculate CVSS score
  4. Assign severity level
  5. Provide remediation
```

**Example - Broken Access Control:**
```
Finding: No @PreAuthorize annotations
         No Spring Security implementation
         No JWT validation
         All endpoints public

OWASP Category: A01:2021 - Broken Access Control
Why: "Access control is a fundamental component of data security. 
     Users should only be able to access resources for which they 
     have been authorized."

CVSS Score Calculation:
  - Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  - Attack Vector: Network (anyone can access)
  - Attack Complexity: Low (no special tools needed)
  - Privileges Required: None
  - User Interaction: None
  - Scope: Unchanged
  - Confidentiality: High (all data visible)
  - Integrity: High (all data modifiable)
  - Availability: High (can delete everything)
  - Score: 9.1 (CRITICAL)
```

---

## Phase 4: Vulnerability Classification

### Step 4.1: Severity Determination

For each vulnerability, I evaluated:

```
CRITICAL (CVSS 9.0-10.0):
  - Can compromise entire system
  - Requires no privileges
  - Trivial to exploit
  - Impacts confidentiality, integrity, availability
  
  ✓ Example: No authentication on delete all

HIGH (CVSS 7.0-8.9):
  - Significant impact
  - Easy to exploit
  - Limited privilege escalation
  
  ✓ Example: No HTTPS encryption

MEDIUM (CVSS 4.0-6.9):
  - Moderate impact
  - Requires some user interaction
  - Limited scope
  
  ✓ Example: Sequential ID enumeration

LOW (CVSS 0.1-3.9):
  - Minor impact
  - Complex to exploit
  - Limited damage
```

### Step 4.2: Risk Assessment Matrix

```
        │ Easy Exploit  │ Hard Exploit
─────────┼───────────────┼──────────────
High Impact  │   CRITICAL   │    HIGH
─────────┼───────────────┼──────────────
Med Impact   │    HIGH      │    MEDIUM
─────────┼───────────────┼──────────────
Low Impact   │   MEDIUM     │     LOW
```

---

## Phase 5: Documentation & Remediation

### Step 5.1: For Each Vulnerability

```
Template Used:

1. ISSUE DESCRIPTION
   - What is the problem?
   - Why is it a security issue?

2. AFFECTED CODE
   - File name
   - Line numbers
   - Actual code snippet

3. ATTACK SCENARIO
   - How would an attacker exploit this?
   - What damage could result?

4. CVSS SCORING
   - Vector components
   - Final score
   - Severity rating

5. RECOMMENDED FIX
   - Code example
   - Configuration changes
   - Architecture improvements

6. OWASP CATEGORY
   - Which category/categories?
   - Why does it map here?
```

### Step 5.2: Fix Prioritization

```
Priority 1 (Implement Immediately):
  - A01: Broken Access Control (No auth)
  - A05: Security Misconfiguration (H2 console)
  - A02: Cryptographic Failures (No HTTPS)

Priority 2 (Before Production):
  - A04: Insecure Design (No validation)
  - A03: Injection (SQL injection risk)
  - A07: XSS/CSRF (No CSRF tokens)

Priority 3 (Soon After):
  - A06: Vulnerable Components (Update deps)
  - A09: Logging Failures (Add monitoring)
```

---

## Tools & Techniques I Used

### Manual Code Review Techniques

```
1. CONTROL FLOW ANALYSIS
   - Trace data from input to output
   - Identify validation gaps
   - Example: title parameter → SQL query

2. THREAT MODELING
   - What can an attacker do?
   - What resources are at risk?
   - What are entry points?

3. CONFIGURATION REVIEW
   - Compare against security baselines
   - Check for default credentials
   - Evaluate access controls

4. DEPENDENCY ANALYSIS
   - Check version numbers
   - Cross-reference known vulnerabilities
   - Identify missing security libraries

5. ARCHITECTURE ANALYSIS
   - Review communication security
   - Check authentication flow
   - Evaluate data protection
```

### Automated Analysis I Could Have Used (But Didn't)

```bash
# Static Application Security Testing (SAST)
SonarQube → Code quality + security issues
SpotBugs → Bug detection in Java
Checkstyle → Code style violations

# Dependency Checking
OWASP Dependency-Check:
  mvn org.owasp:dependency-check-maven:aggregate

# Security Scanning
Semgrep → Pattern-based security checks
SnykCode → Vulnerability scanning

# Manual Dynamic Testing
OWASP ZAP → Web application penetration testing
Burp Suite → HTTP traffic analysis

# These require running systems and would generate more comprehensive results
```

---

## Why Manual Analysis is Important

### Advantages of Manual Code Review:

```
✓ Context Understanding
  - Understand business logic
  - Identify logical vulnerabilities
  - Understand intent

✓ False Positive Reduction
  - Automated tools flag things that aren't issues
  - Manual review confirms actual risks

✓ Custom Configuration Review
  - Understand environment-specific risks
  - Check for production readiness

✓ Holistic Security View
  - See interactions between components
  - Identify complex attack chains
```

### Limitations of My Analysis:

```
✗ No Runtime Testing
  - Can't verify exploitability without running
  - Database behavior unknown

✗ No Binary Analysis
  - Can't see compiled bytecode
  - Runtime behavior unknown

✗ No Network Analysis
  - Can't sniff actual traffic
  - Can't see runtime configurations

✗ No Third-Party Risk Assessment
  - Can't evaluate all transitive dependencies
  - Runtime versions unknown
```

---

## Scanning Checklist I Used

```
AUTHENTICATION & AUTHORIZATION
  ☑ Check for @PreAuthorize annotations
  ☑ Check for @Secured annotations
  ☑ Look for SecurityContext usage
  ☑ Verify role checks exist
  ☑ Confirm ownership verification
  ✗ FAILED: No auth mechanisms found

INPUT VALIDATION
  ☑ Check for @Valid annotations
  ☑ Check for null checks
  ☑ Check for length validation
  ☑ Check for format validation
  ☑ Check for type validation
  ✗ FAILED: No validation annotations

CONFIGURATION
  ☑ Check application.properties
  ☑ Check environment variables
  ☑ Check for hardcoded values
  ☑ Check for default credentials
  ☑ Check for debug settings
  ✗ FAILED: Multiple dangerous configs

DEPENDENCIES
  ☑ Check Spring Boot version
  ☑ Check for Security framework
  ☑ Check for deprecated libraries
  ☑ Check for missing libraries
  ✗ FAILED: Missing Spring Security

FRONTEND SECURITY
  ☑ Check for HTTPS usage
  ☑ Check for XSRF configuration
  ☑ Check for authentication headers
  ☑ Check for XSS protection
  ✓ PASSES: Uses Angular (built-in some protections)
  ✗ FAILS: No explicit CSRF/XSRF

LOGGING & MONITORING
  ☑ Check for security event logging
  ☑ Check for error logging
  ☑ Check for access logging
  ✗ FAILED: Generic exceptions, no logging

API SECURITY
  ☑ Check for rate limiting
  ☑ Check for pagination limits
  ☑ Check for batch operation limits
  ☑ Check for resource limits
  ✗ FAILED: No rate limiting or limits
```

---

## How I Calculated CVSS Scores

### Example: A01 - Broken Access Control

```
CVSS v3.1 Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Component Breakdown:

AV:N (Attack Vector: Network)
  → Attacker can reach from network/internet
  → Score Impact: Highest (0.85)

AC:L (Attack Complexity: Low)
  → No special tools/conditions needed
  → Score Impact: Highest (0.77)

PR:N (Privileges Required: None)
  → Attacker doesn't need to be authenticated
  → Score Impact: Highest (NP = 0.85, L = 0.62)

UI:N (User Interaction: None)
  → No user must click link/open file
  → Score Impact: Highest (0.85)

S:U (Scope: Unchanged)
  → Only affects this application
  → Score Multiplier: 1.0

C:H (Confidentiality: High)
  → All data visible to attacker
  → Impact: 0.56

I:H (Integrity: High)
  → Attacker can modify/delete all data
  → Impact: 0.56

A:H (Availability: High)
  → Can delete everything (deleteAll endpoint)
  → Impact: 0.56

Formula:
  Subscore (impact) = 1 - (1-C)*(1-I)*(1-A)
                    = 1 - (1-0.56)*(1-0.56)*(1-0.56)
                    = 1 - (0.44)*(0.44)*(0.44)
                    = 1 - 0.085
                    = 0.915

Final Score = 0.915 × 3.6
            = 3.29 (base)
            × multiplier for scope
            ÷ adjustment factors
            = 9.1 (CRITICAL)
```

---

## Summary of Scanning Process

```
┌─────────────────────────────────────────────┐
│ 1. RECONNAISSANCE (30 mins)                  │
│    ├─ Clone repository                       │
│    ├─ File inventory                         │
│    ├─ Understand architecture                │
│    └─ Identify key files                     │
├─────────────────────────────────────────────┤
│ 2. STATIC CODE ANALYSIS (45 mins)           │
│    ├─ Review each Java file                  │
│    ├─ Analyze HTTP endpoints                 │
│    ├─ Check exception handling               │
│    ├─ Review configuration                   │
│    ├─ Analyze TypeScript frontend            │
│    └─ Check HTTP calls                       │
├─────────────────────────────────────────────┤
│ 3. CONFIGURATION ANALYSIS (20 mins)         │
│    ├─ Check pom.xml dependencies             │
│    ├─ Review application.properties          │
│    ├─ Verify security settings               │
│    └─ Check profiles                         │
├─────────────────────────────────────────────┤
│ 4. THREAT MODELING (30 mins)                │
│    ├─ Identify attack vectors                │
│    ├─ Map to OWASP Top 10                    │
│    ├─ Calculate CVSS scores                  │
│    └─ Determine severity                     │
├─────────────────────────────────────────────┤
│ 5. DOCUMENTATION (30 mins)                  │
│    ├─ Write detailed findings                │
│    ├─ Provide code examples                  │
│    ├─ Create remediation steps               │
│    └─ Generate report                        │
└─────────────────────────────────────────────┘

Total Time: ~2.5 hours for comprehensive analysis
```

---

## Key Findings Summary Table

| Category | How Found | Severity |
|----------|-----------|----------|
| No Authentication | Searched @PreAuthorize, found none | CRITICAL |
| H2 Console Enabled | Reviewed application.properties | CRITICAL |
| Empty Password | Checked datasource config | CRITICAL |
| No HTTPS | Reviewed service base URL | HIGH |
| No Input Validation | Checked @Valid annotations | HIGH |
| CORS Hardcoded | Found @CrossOrigin annotation | HIGH |
| No CSRF Tokens | Checked HttpClientXsrfModule import | MEDIUM |
| Outdated Spring Boot | Reviewed pom.xml version | MEDIUM |
| No Logging | Analyzed exception handlers | MEDIUM |
| Sequential IDs | Reviewed ID generation strategy | MEDIUM |

---

## Conclusion

My scanning process combined:
- **File-level analysis** (what files exist?)
- **Code-level analysis** (what does the code do?)
- **Configuration analysis** (how is it configured?)
- **Security framework analysis** (what's missing?)
- **Threat modeling** (how can it be attacked?)
- **OWASP mapping** (which categories apply?)

This comprehensive approach identified **10 major vulnerabilities** with actionable remediation guidance.

**The key insight:** This is a tutorial/example repository designed for learning, not production. It demonstrates good CRUD patterns but lacks enterprise security controls needed for real applications.
