---
name: response-anomaly-detection
description: Identify indicators of unknown vulnerabilities by analyzing response anomalies — error patterns, memory artifacts, timing deviations, content differentials, and debug information leakage
---

# Response Anomaly Detection

This skill teaches you to recognize when a server response indicates an **unknown vulnerability** — not a known CVE, but a novel behavior that reveals a code-level weakness. The key insight: most zero-days are discovered not by running exploits, but by noticing that a response is **wrong** in an interesting way.

## Category 1: Memory Corruption Indicators

These patterns in web responses suggest the backend has a memory-safety issue:

### What to Look For

```
# Hex addresses in error output — sign of C/C++ segfault or buffer overflow
0x7f4a2c001234
0xdeadbeef
0x000055d3a8f21000
Segmentation fault (core dumped)
SIGSEGV
SIGABRT
munmap_chunk(): invalid pointer
double free or corruption
malloc(): corrupted top size
free(): invalid next size
*** buffer overflow detected ***
stack smashing detected
```

### Detection Script

```python
import re

MEMORY_PATTERNS = [
    r'0x[0-9a-f]{6,16}',                     # Hex memory addresses
    r'segmentation fault',                      # Segfault
    r'SIGSEGV|SIGABRT|SIGBUS|SIGFPE',          # Unix signals
    r'buffer overflow detected',                # Stack protector
    r'stack smashing detected',                 # Stack canary
    r'heap-buffer-overflow',                     # ASan
    r'heap-use-after-free',                      # ASan UAF
    r'stack-buffer-overflow',                    # ASan
    r'AddressSanitizer',                         # ASan enabled
    r'(double free|corrupted|invalid pointer)',  # Heap corruption
    r'munmap_chunk|malloc\(\)|free\(\)',         # Glibc
    r'core dump',                                # Core dump
    r'access violation',                         # Windows
    r'STATUS_ACCESS_VIOLATION',                  # Windows NTSTATUS
]

def check_memory_corruption(response_text):
    findings = []
    for pattern in MEMORY_PATTERNS:
        matches = re.findall(pattern, response_text, re.IGNORECASE)
        if matches:
            findings.append({"pattern": pattern, "matches": matches[:3]})
    return findings
```

## Category 2: Exception & Stack Trace Leakage

Stack traces reveal not just errors, but **exact code paths** that can be targeted.

### Critical Patterns by Language

```python
STACK_TRACE_PATTERNS = {
    "java": [
        r'at\s+[\w.]+\([\w]+\.java:\d+\)',     # at com.example.Class(File.java:42)
        r'java\.lang\.\w+Exception',             # java.lang.NullPointerException
        r'javax?\.\w+\.\w+Exception',            # javax.servlet.ServletException
        r'Caused by:',                            # Chained exceptions
        r'org\.springframework\.',                # Spring framework internals
        r'org\.hibernate\.',                       # Hibernate ORM internals
    ],
    "python": [
        r'Traceback \(most recent call last\)',   # Python traceback header
        r'File "[\w/\\._-]+\.py", line \d+',     # File path + line number
        r'\w+Error: .+',                          # TypeError: cannot convert
        r'django\.core\.',                         # Django framework internals
        r'flask\.app\.',                           # Flask framework internals
        r'sqlalchemy\.',                           # SQLAlchemy ORM
    ],
    "nodejs": [
        r'at\s+[\w.]+\s+\([\w/\\._-]+\.js:\d+:\d+\)',  # at Function (/app/server.js:42:10)
        r'TypeError:|ReferenceError:|RangeError:',       # JS errors
        r'node_modules/',                                 # Dependency paths
        r'UnhandledPromiseRejectionWarning',              # Async errors
        r'FATAL ERROR:.*heap',                             # V8 heap issues
    ],
    "php": [
        r'Fatal error:.+on line \d+',            # PHP fatal error
        r'Warning:.+on line \d+',                 # PHP warnings
        r'Stack trace:.*#\d+',                    # PHP stack trace
        r'in\s+/[\w/._-]+\.php:\d+',              # File path exposure
        r'PDOException|mysqli_',                   # Database driver errors
    ],
    "dotnet": [
        r'System\.\w+Exception',                  # System.NullReferenceException
        r'at\s+\w+\.\w+\(',                       # at Namespace.Class(
        r'Server Error in .+ Application',         # ASP.NET error page
        r'YSOD|Yellow Screen of Death',            # ASP.NET YSOD
        r'Microsoft\.AspNetCore\.',                # ASP.NET Core internals
    ],
    "ruby": [
        r'ActionController::RoutingError',         # Rails routing error
        r'ActiveRecord::\w+Error',                 # Rails ORM error
        r'\.rb:\d+:in\s+',                         # Ruby file:line
        r'NoMethodError|NameError|ArgumentError',  # Ruby errors
    ],
}

def detect_stack_traces(response_text):
    """Detect stack traces and identify the backend technology."""
    detections = {}
    for lang, patterns in STACK_TRACE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                detections.setdefault(lang, []).append(pattern)
    return detections
```

### What Stack Traces Reveal

When you find a stack trace, extract:

1. **Technology stack** — Language, framework, ORM, and versions
2. **File paths** — Reveals directory structure (`/var/www/app/`, `/opt/service/`)
3. **Function names** — Reveals business logic (`processPayment`, `validateToken`)
4. **Line numbers** — Pinpoints exact code location of the bug
5. **Database queries** — Sometimes raw SQL appears in ORM exceptions
6. **Internal hostnames** — Database server names, microservice URLs

## Category 3: Timing Anomaly Detection

Timing differences reveal processing differences the response body doesn't show.

### Statistical Timing Analysis

```python
import requests, time, statistics, math
requests.packages.urllib3.disable_warnings()

def timing_test(url, n=10):
    """Measure response time with statistical significance."""
    times = []
    for _ in range(n):
        start = time.time()
        try:
            requests.get(url, verify=False, timeout=30)
        except requests.exceptions.Timeout:
            times.append(30.0)
            continue
        except:
            continue
        times.append(time.time() - start)

    if len(times) < 3:
        return None, None, None

    mean = statistics.mean(times)
    stdev = statistics.stdev(times) if len(times) > 1 else 0
    return mean, stdev, times

def is_timing_anomaly(baseline_mean, baseline_stdev, test_mean, test_stdev):
    """Determine if timing difference is statistically significant."""
    if baseline_stdev == 0:
        return test_mean > baseline_mean * 2  # 2x slower

    # Calculate Z-score
    z = (test_mean - baseline_mean) / max(baseline_stdev, 0.001)
    return z > 3.0  # 3 standard deviations = 99.7% confidence

# Usage
baseline = timing_test("https://TARGET/api?param=normal")
test = timing_test("https://TARGET/api?param=MUTATION")

if baseline[0] and test[0]:
    if is_timing_anomaly(baseline[0], baseline[1], test[0], test[1]):
        print(f"TIMING ANOMALY: baseline={baseline[0]:.3f}s test={test[0]:.3f}s")
```

### What Timing Anomalies Indicate

| Timing Pattern | Possible Vulnerability |
|---|---|
| Input length correlates with time | Algorithmic complexity attack (ReDoS, hash collision) |
| Specific characters cause slowdown | Character-by-character comparison (timing oracle) |
| Longer delay on valid-looking input | Authentication oracle (valid vs invalid username) |
| Timeout on specific mutations | Infinite loop or blocking operation triggered |
| Bimodal distribution (fast/slow) | Cache hit/miss revealing internal state |

## Category 4: Response Size Differential Analysis

Response size changes reveal content that appears/disappears based on input.

### Methodology

```python
import requests, hashlib
requests.packages.urllib3.disable_warnings()

def size_diff_analysis(base_url, param, mutations):
    """Compare response sizes across mutations to detect content leakage."""
    results = []

    # Baseline
    r = requests.get(f"{base_url}?{param}=normalvalue", verify=False, timeout=10)
    baseline = {
        "size": len(r.content),
        "hash": hashlib.md5(r.content).hexdigest(),
        "status": r.status_code,
    }

    for label, value in mutations:
        try:
            r = requests.get(f"{base_url}?{param}={value}", verify=False, timeout=10)
            diff = len(r.content) - baseline["size"]
            new_hash = hashlib.md5(r.content).hexdigest()

            if abs(diff) > 50 or new_hash != baseline["hash"]:
                results.append({
                    "label": label,
                    "size_diff": diff,
                    "new_size": len(r.content),
                    "status": r.status_code,
                    "content_changed": new_hash != baseline["hash"],
                })
        except:
            pass

    return baseline, results
```

### Interpreting Size Differentials

| Size Change | Possible Meaning |
|---|---|
| Much larger response | Debug information leaked, error message with details, additional content exposed |
| Much smaller response | Content filtered/blocked, but differently than expected |
| Consistent +N bytes per mutation | Reflected input (potential XSS or injection point) |
| Size correlates with payload | Direct reflection without encoding |
| Size varies randomly | Non-deterministic behavior (race condition indicator) |

## Category 5: Error Message Fingerprinting

Not all errors are equal. Learn to distinguish "safe" errors from "interesting" ones.

### Error Classification

```python
import re

# BORING — These are normal application behavior, not vulnerabilities
BORING_ERRORS = [
    "page not found", "404", "not found",
    "invalid parameter", "missing required",
    "unauthorized", "forbidden", "access denied",
    "rate limit", "too many requests",
    "bad request", "validation error",
]

# INTERESTING — These suggest deeper issues worth investigating
INTERESTING_ERRORS = [
    # Database errors (potential injection)
    r"SQL syntax.*MySQL",
    r"ORA-\d{5}",           # Oracle errors
    r"PostgreSQL.*ERROR",
    r"SQLITE_ERROR",
    r"unterminated quoted string",
    r"near \".*\": syntax error",

    # Type/cast errors (potential type confusion exploit)
    r"cannot convert|type mismatch|invalid cast",
    r"expected .+ but got",
    r"TypeError:.*undefined is not",
    r"cannot read propert(y|ies) of (null|undefined)",

    # Path/file errors (potential path traversal)
    r"No such file or directory",
    r"failed to open stream",
    r"FileNotFoundException",
    r"ENOENT",

    # Serialization errors (potential deserialization attack)
    r"unserialize|pickle|deseriali[sz]",
    r"ClassNotFoundException",
    r"instantiate.*class",

    # Template errors (potential SSTI)
    r"template.*error|jinja|twig|freemarker|velocity|thymeleaf",
    r"TemplateSyntaxError",
    r"UndefinedError",

    # Command execution errors (potential RCE)
    r"sh: .*: not found",
    r"command not found",
    r"exec format error",
    r"/bin/(sh|bash|cmd)",
]

def classify_error(response_text):
    """Classify an error response as boring or interesting."""
    text = response_text.lower()

    # Check interesting patterns first
    for pattern in INTERESTING_ERRORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return "INTERESTING", pattern

    # Check boring patterns
    for pattern in BORING_ERRORS:
        if pattern in text:
            return "BORING", pattern

    return "UNKNOWN", None
```

## Category 6: Information Leakage in Headers

```python
# Headers that leak sensitive information
INTERESTING_HEADERS = {
    "Server": "Reveals exact server software and version",
    "X-Powered-By": "Reveals framework (Express, PHP, ASP.NET)",
    "X-AspNet-Version": "Exact .NET version",
    "X-AspNetMvc-Version": "Exact MVC version",
    "X-Debug-Token": "Symfony debug token — access profiler",
    "X-Debug-Token-Link": "Direct link to Symfony profiler",
    "X-Request-Id": "Internal request ID format reveals architecture",
    "X-Backend-Server": "Internal server hostname",
    "X-Upstream": "Internal service name",
    "X-Served-By": "Internal server identity",
    "Via": "Proxy chain reveals infrastructure",
    "X-Cache": "Cache behavior (hit/miss) reveals request routing",
    "X-Runtime": "Processing time (timing oracle)",
    "X-RateLimit-Remaining": "Rate limit state",
    "X-Amzn-RequestId": "Confirms AWS infrastructure",
    "X-Cloud-Trace-Context": "Confirms GCP infrastructure",
    "X-Ms-Request-Id": "Confirms Azure infrastructure",
}

def analyze_headers(response):
    """Check response headers for information leakage."""
    findings = []
    for header, description in INTERESTING_HEADERS.items():
        value = response.headers.get(header)
        if value:
            findings.append({
                "header": header,
                "value": value,
                "significance": description,
            })
    return findings
```

## Decision Matrix: Is This Anomaly Exploitable?

After detecting an anomaly, use this matrix to determine next steps:

| Anomaly Found | Next Step | Potential Severity |
|---|---|---|
| Memory corruption indicators | Report immediately — likely critical RCE | Critical |
| Full stack trace with file paths | Use paths to craft targeted exploits | Medium → High |
| SQL error messages on mutation | Test for blind/error-based SQLi | High → Critical |
| Type error on unexpected input | Test if type confusion bypasses auth/authz | Medium → Critical |
| Timing correlates with input | Build timing oracle, extract secrets | Medium → High |
| Response size grows with payload | Test for reflected XSS/injection | Medium → High |
| Debug endpoints accessible | Extract internal state, credentials | High → Critical |
| Template syntax errors | Test for SSTI → RCE | High → Critical |
| Serialization errors | Test for deserialization → RCE | High → Critical |
| Command not found errors | Test for command injection → RCE | Critical |

## Summary

**Detection is the first step, not the last.** When you find an anomaly:

1. **Classify** it using the categories above
2. **Reproduce** it reliably (3+ times)
3. **Investigate** the root cause — don't just log it
4. **Escalate** — try to increase impact (info leak → auth bypass → RCE)
5. **Chain** — combine with other findings for maximum impact
6. **Document** with exact reproduction steps
