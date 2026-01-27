# CRA Compliance Audit Report

**Product:** Tahini
**Date:** 2026-01-27
**Tool:** cra-auditflow v0.1.0

---

## CRA Risk Classification

| Field | Value |
|-------|-------|
| **Risk Class** | Default |
| **Applicable Articles** | Article 32 |
| **Conformity Assessment** | Self-assessment based on essential requirements (Article 32) |

## Audit Summary

| Metric | Count |
|--------|-------|
| Total Components | 4400 |
| Components with Vulnerabilities | 64 |
| Total Vulnerabilities | 99 |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Unknown | 99 |

## Vulnerability Findings

### lodash v4.17.21

PURL: `pkg:npm/lodash@4.17.21`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-xxjr-mmjv-4gpg | UNKNOWN | N/A | Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions |

### html-minifier v4.0.0

PURL: `pkg:npm/html-minifier@4.0.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-pfq8-rq6v-vf5m | UNKNOWN | N/A | kangax html-minifier REDoS vulnerability |

### semver v5.3.0

PURL: `pkg:npm/semver@5.3.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-c2qf-rxjj-qqgw | UNKNOWN | N/A | semver vulnerable to Regular Expression Denial of Service |

### request v2.88.2

PURL: `pkg:npm/request@2.88.2`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-p8p7-x288-28g6 | UNKNOWN | N/A | Server-Side Request Forgery in Request |

### form-data v2.3.3

PURL: `pkg:npm/form-data@2.3.3`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-fjxv-7rqg-78g4 | UNKNOWN | N/A | form-data uses unsafe random function in form-data for choosing boundary |

### qs v6.5.3

PURL: `pkg:npm/qs@6.5.3`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-6rw7-vpxm-498p | UNKNOWN | N/A | qs's arrayLimit bypass in its bracket notation allows DoS via memory exhaustion |

### tough-cookie v2.5.0

PURL: `pkg:npm/tough-cookie@2.5.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-72xf-g2v4-qvf3 | UNKNOWN | N/A | tough-cookie Prototype Pollution vulnerability |

### diff v4.0.2

PURL: `pkg:npm/diff@4.0.2`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-73rr-hh4g-fpgx | UNKNOWN | N/A | jsdiff has a Denial of Service vulnerability in parsePatch and applyPatch |

### tar v7.5.2

PURL: `pkg:npm/tar@7.5.2`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-8qq5-rm4j-mr97 | UNKNOWN | N/A | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via ... |
| GHSA-r6q2-hw4h-h46w | UNKNOWN | N/A | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions ... |

### router v1.23.0

PURL: `pkg:npm/%40remix-run/router@1.23.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-2w69-qvjg-hvjx | UNKNOWN | N/A | React Router vulnerable to XSS via Open Redirects |

### react-router v6.30.0

PURL: `pkg:npm/react-router@6.30.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-9jcx-v3wj-wh4m | UNKNOWN | N/A | React Router has unexpected external redirect via untrusted paths |

### diff v5.2.0

PURL: `pkg:npm/diff@5.2.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-73rr-hh4g-fpgx | UNKNOWN | N/A | jsdiff has a Denial of Service vulnerability in parsePatch and applyPatch |

### esbuild v0.17.6

PURL: `pkg:npm/esbuild@0.17.6`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-67mh-4wv8-2f99 | UNKNOWN | N/A | esbuild enables any website to send any requests to the development server an... |

### esbuild v0.21.5

PURL: `pkg:npm/esbuild@0.21.5`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-67mh-4wv8-2f99 | UNKNOWN | N/A | esbuild enables any website to send any requests to the development server an... |

### tar v6.2.1

PURL: `pkg:npm/tar@6.2.1`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-8qq5-rm4j-mr97 | UNKNOWN | N/A | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via ... |
| GHSA-r6q2-hw4h-h46w | UNKNOWN | N/A | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions ... |

### estree-util-value-to-estree v1.3.0

PURL: `pkg:npm/estree-util-value-to-estree@1.3.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-f7f6-9jq7-3rqj | UNKNOWN | N/A | estree-util-value-to-estree allows prototype pollution in generated ESTree |

### react v2.17.2

PURL: `pkg:npm/%40remix-run/react@2.17.2`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-8v8x-cx79-35w7 | UNKNOWN | N/A | React Router SSR XSS in ScrollRestoration |

### server-runtime v2.17.2

PURL: `pkg:npm/%40remix-run/server-runtime@2.17.2`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-h5cw-625j-3rxh | UNKNOWN | N/A | React Router has CSRF issue in Action/Server Action Request Processing |

### esbuild v0.19.12

PURL: `pkg:npm/esbuild@0.19.12`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-67mh-4wv8-2f99 | UNKNOWN | N/A | esbuild enables any website to send any requests to the development server an... |

### qs v6.14.0

PURL: `pkg:npm/qs@6.14.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-6rw7-vpxm-498p | UNKNOWN | N/A | qs's arrayLimit bypass in its bracket notation allows DoS via memory exhaustion |

### undici v6.22.0

PURL: `pkg:npm/undici@6.22.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-g9mf-h72j-4rw9 | UNKNOWN | N/A | Undici has an unbounded decompression chain in HTTP responses on Node.js Fetc... |

### valibot v0.41.0

PURL: `pkg:npm/valibot@0.41.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-vqpr-j7v3-hqw9 | UNKNOWN | N/A | Valibot has a ReDoS vulnerability in `EMOJI_REGEX` |

### glob v10.4.5

PURL: `pkg:npm/glob@10.4.5`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-5j98-mcp5-4vw2 | UNKNOWN | N/A | glob CLI: Command injection via -c/--cmd executes matches with shell:true |

### js-yaml v3.14.1

PURL: `pkg:npm/js-yaml@3.14.1`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-mh29-5h37-fv8m | UNKNOWN | N/A | js-yaml has prototype pollution in merge (<<) |

### js-yaml v4.1.0

PURL: `pkg:npm/js-yaml@4.1.0`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-mh29-5h37-fv8m | UNKNOWN | N/A | js-yaml has prototype pollution in merge (<<) |

### node-forge v1.3.1

PURL: `pkg:npm/node-forge@1.3.1`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-554w-wpv2-vw27 | UNKNOWN | N/A | node-forge has ASN.1 Unbounded Recursion |
| GHSA-5gfm-wpxj-wjgq | UNKNOWN | N/A | node-forge has an Interpretation Conflict vulnerability via its ASN.1 Validat... |
| GHSA-65ch-62r8-g69g | UNKNOWN | N/A | node-forge is vulnerable to ASN.1 OID Integer Truncation |

### tar v7.4.3

PURL: `pkg:npm/tar@7.4.3`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-8qq5-rm4j-mr97 | UNKNOWN | N/A | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via ... |
| GHSA-r6q2-hw4h-h46w | UNKNOWN | N/A | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions ... |

### undici v6.21.3

PURL: `pkg:npm/undici@6.21.3`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-g9mf-h72j-4rw9 | UNKNOWN | N/A | Undici has an unbounded decompression chain in HTTP responses on Node.js Fetc... |

### commons-compress v1.21

PURL: `pkg:maven/org.apache.commons/commons-compress@1.21?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4265-ccf5-phj5 | UNKNOWN | N/A | Apache Commons Compress: OutOfMemoryError unpacking broken Pack200 file |
| GHSA-4g9r-vxhx-9pgx | UNKNOWN | N/A | Apache Commons Compress: Denial of service caused by an infinite loop for a c... |

### httpclient v4.5.14

PURL: `pkg:maven/org.apache.httpcomponents/httpclient@4.5.14?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-7r82-7xv7-xcpj | UNKNOWN | N/A | Cross-site scripting in Apache HttpClient |

### netty-codec-http2 v4.1.110.Final

PURL: `pkg:maven/io.netty/netty-codec-http2@4.1.110.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-prj3-ccx8-p6x4 | UNKNOWN | N/A | Netty affected by MadeYouReset HTTP/2 DDoS vulnerability |

### netty-common v4.1.110.Final

PURL: `pkg:maven/io.netty/netty-common@4.1.110.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-389x-839f-4rhx | UNKNOWN | N/A | Denial of Service attack on windows app using Netty |
| GHSA-xq3w-v528-46rv | UNKNOWN | N/A | Denial of Service attack on windows app using netty |

### netty-codec v4.1.110.Final

PURL: `pkg:maven/io.netty/netty-codec@4.1.110.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-3p8m-j85q-pgmj | UNKNOWN | N/A | Netty's decoders vulnerable to DoS via zip bomb style attack |

### netty-handler v4.1.110.Final

PURL: `pkg:maven/io.netty/netty-handler@4.1.110.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4g8c-wm8x-jfhw | UNKNOWN | N/A | SslHandler doesn't correctly validate packets which can lead to native crash ... |
| GHSA-9959-6p3m-wxpc | UNKNOWN | N/A | Denial of service in Netty |

### netty-codec-http v4.1.110.Final

PURL: `pkg:maven/io.netty/netty-codec-http@4.1.110.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-84h7-rjj3-6jx4 | UNKNOWN | N/A | Netty has a CRLF Injection vulnerability in io.netty.handler.codec.http.HttpR... |
| GHSA-fghv-69vj-qj49 | UNKNOWN | N/A | Netty vulnerable to request smuggling due to incorrect parsing of chunk exten... |

### jose4j v0.9.5

PURL: `pkg:maven/org.bitbucket.b_c/jose4j@0.9.5?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-3677-xxcr-wjqv | UNKNOWN | N/A | jose4j is vulnerable to DoS via compressed JWE content |

### jdom2 v2.0.6

PURL: `pkg:maven/org.jdom/jdom2@2.0.6?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-2363-cqg2-863c | UNKNOWN | N/A | XML External Entity (XXE) Injection in JDOM |

### guava v30.1-android

PURL: `pkg:maven/com.google.guava/guava@30.1-android?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-5mg8-w23w-74h3 | UNKNOWN | N/A | Information Disclosure in Guava |
| GHSA-7g45-4rm6-3mm3 | UNKNOWN | N/A | Guava vulnerable to insecure use of temporary directory |

### protobuf-kotlin v3.24.4

PURL: `pkg:maven/com.google.protobuf/protobuf-kotlin@3.24.4?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-735f-pc8j-v9w8 | UNKNOWN | N/A | protobuf-java has potential Denial of Service issue |
| GHSA-h4h5-3hr4-j3g2 | UNKNOWN | N/A | protobuf-java has a potential Denial of Service issue |

### protobuf-java v3.24.4

PURL: `pkg:maven/com.google.protobuf/protobuf-java@3.24.4?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-735f-pc8j-v9w8 | UNKNOWN | N/A | protobuf-java has potential Denial of Service issue |

### netty-codec-http2 v4.1.93.Final

PURL: `pkg:maven/io.netty/netty-codec-http2@4.1.93.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-prj3-ccx8-p6x4 | UNKNOWN | N/A | Netty affected by MadeYouReset HTTP/2 DDoS vulnerability |
| GHSA-xpw8-rcwv-8f8p | UNKNOWN | N/A | io.netty:netty-codec-http2 vulnerable to HTTP/2 Rapid Reset Attack |

### netty-common v4.1.93.Final

PURL: `pkg:maven/io.netty/netty-common@4.1.93.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-389x-839f-4rhx | UNKNOWN | N/A | Denial of Service attack on windows app using Netty |
| GHSA-xq3w-v528-46rv | UNKNOWN | N/A | Denial of Service attack on windows app using netty |

### netty-codec v4.1.93.Final

PURL: `pkg:maven/io.netty/netty-codec@4.1.93.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-3p8m-j85q-pgmj | UNKNOWN | N/A | Netty's decoders vulnerable to DoS via zip bomb style attack |

### netty-handler v4.1.93.Final

PURL: `pkg:maven/io.netty/netty-handler@4.1.93.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4g8c-wm8x-jfhw | UNKNOWN | N/A | SslHandler doesn't correctly validate packets which can lead to native crash ... |
| GHSA-57m8-f3v5-hm5m | UNKNOWN | N/A | Withdrawn Advisory: Netty-handler does not validate host names by default |
| GHSA-6mjq-h674-j845 | UNKNOWN | N/A | netty-handler SniHandler 16MB allocation |
| GHSA-9959-6p3m-wxpc | UNKNOWN | N/A | Denial of service in Netty |

### netty-codec-http v4.1.93.Final

PURL: `pkg:maven/io.netty/netty-codec-http@4.1.93.Final?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-5jpm-x58v-624v | UNKNOWN | N/A | Netty's HttpPostRequestDecoder can OOM |
| GHSA-84h7-rjj3-6jx4 | UNKNOWN | N/A | Netty has a CRLF Injection vulnerability in io.netty.handler.codec.http.HttpR... |
| GHSA-fghv-69vj-qj49 | UNKNOWN | N/A | Netty vulnerable to request smuggling due to incorrect parsing of chunk exten... |

### commons-io v1.4

PURL: `pkg:maven/commons-io/commons-io@1.4?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-gwrp-pvrq-jmwv | UNKNOWN | N/A | Path Traversal and Improper Input Validation in Apache Commons IO |

### okhttp v4.9.2

PURL: `pkg:maven/com.squareup.okhttp3/okhttp@4.9.2?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4hc2-jh7r-wrc3 | UNKNOWN | N/A | Improper Certificate Validation in OkHttp |

### okio v2.9.0

PURL: `pkg:maven/com.squareup.okio/okio@2.9.0?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-w33c-445m-f8w7 | UNKNOWN | N/A | Okio Signed to Unsigned Conversion Error vulnerability |

### commons-io v2.6

PURL: `pkg:maven/commons-io/commons-io@2.6?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-78wr-2p64-hpwj | UNKNOWN | N/A | Apache Commons IO: Possible denial of service attack on untrusted input to Xm... |
| GHSA-gwrp-pvrq-jmwv | UNKNOWN | N/A | Path Traversal and Improper Input Validation in Apache Commons IO |

### okhttp v4.12.0

PURL: `pkg:maven/com.squareup.okhttp3/okhttp@4.12.0?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4hc2-jh7r-wrc3 | UNKNOWN | N/A | Improper Certificate Validation in OkHttp |

### gson v2.8.6

PURL: `pkg:maven/com.google.code.gson/gson@2.8.6?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4jrv-ppp4-jm57 | UNKNOWN | N/A | Deserialization of Untrusted Data in Gson |

### guava v28.1-android

PURL: `pkg:maven/com.google.guava/guava@28.1-android?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-5mg8-w23w-74h3 | UNKNOWN | N/A | Information Disclosure in Guava |
| GHSA-7g45-4rm6-3mm3 | UNKNOWN | N/A | Guava vulnerable to insecure use of temporary directory |

### guava v31.1-jre

PURL: `pkg:maven/com.google.guava/guava@31.1-jre?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-5mg8-w23w-74h3 | UNKNOWN | N/A | Information Disclosure in Guava |
| GHSA-7g45-4rm6-3mm3 | UNKNOWN | N/A | Guava vulnerable to insecure use of temporary directory |

### bcprov-jdk18on v1.72

PURL: `pkg:maven/org.bouncycastle/bcprov-jdk18on@1.72?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4h8f-2wvx-gg5w | UNKNOWN | N/A | Bouncy Castle Java Cryptography API vulnerable to DNS poisoning |
| GHSA-67mf-3cr5-8w23 | UNKNOWN | N/A | Bouncy Castle for Java on All (API modules) allows Excessive Allocation |
| GHSA-hr8g-6v94-x4m9 | UNKNOWN | N/A | Bouncy Castle For Java LDAP injection vulnerability |
| GHSA-wjxj-5m7g-mg7q | UNKNOWN | N/A | Bouncy Castle Denial of Service (DoS) |
| GHSA-8xfc-gm6g-vgpv | UNKNOWN | N/A | Bouncy Castle certificate parsing issues cause high CPU usage during paramete... |
| GHSA-v435-xc8x-wvr9 | UNKNOWN | N/A | Bouncy Castle affected by timing side-channel for RSA key exchange ("The Marv... |

### okhttp v3.14.9

PURL: `pkg:maven/com.squareup.okhttp3/okhttp@3.14.9?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-3cqm-mf7h-prrj | UNKNOWN | N/A | Square OkHttp can accept the wrong certificate |
| GHSA-4hc2-jh7r-wrc3 | UNKNOWN | N/A | Improper Certificate Validation in OkHttp |

### okhttp v4.3.1

PURL: `pkg:maven/com.squareup.okhttp3/okhttp@4.3.1?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-3cqm-mf7h-prrj | UNKNOWN | N/A | Square OkHttp can accept the wrong certificate |
| GHSA-4hc2-jh7r-wrc3 | UNKNOWN | N/A | Improper Certificate Validation in OkHttp |

### okio v2.4.1

PURL: `pkg:maven/com.squareup.okio/okio@2.4.1?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-w33c-445m-f8w7 | UNKNOWN | N/A | Okio Signed to Unsigned Conversion Error vulnerability |

### kotlin-stdlib v1.3.61

PURL: `pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.3.61?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-2qp4-g3q3-f92w | UNKNOWN | N/A | Improper Locking in JetBrains Kotlin |
| GHSA-cqj8-47ch-rvvq | UNKNOWN | N/A | Incorrect Default Permissions in JetBrains Kotlin |

### okio v1.17.2

PURL: `pkg:maven/com.squareup.okio/okio@1.17.2?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-w33c-445m-f8w7 | UNKNOWN | N/A | Okio Signed to Unsigned Conversion Error vulnerability |

### junit v4.12

PURL: `pkg:maven/junit/junit@4.12?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-269g-pwp5-87pp | UNKNOWN | N/A | TemporaryFolder on unix-like systems does not limit access to created files |

### json v20230227

PURL: `pkg:maven/org.json/json@20230227?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4jq9-2xhw-jpx7 | UNKNOWN | N/A | Java: DoS Vulnerability in JSON-JAVA |
| GHSA-rm7j-f5g5-27vv | UNKNOWN | N/A | Duplicate Advisory: Denial of Service  in JSON-Java |

### bcprov-jdk18on v1.76

PURL: `pkg:maven/org.bouncycastle/bcprov-jdk18on@1.76?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-4h8f-2wvx-gg5w | UNKNOWN | N/A | Bouncy Castle Java Cryptography API vulnerable to DNS poisoning |
| GHSA-67mf-3cr5-8w23 | UNKNOWN | N/A | Bouncy Castle for Java on All (API modules) allows Excessive Allocation |
| GHSA-8xfc-gm6g-vgpv | UNKNOWN | N/A | Bouncy Castle certificate parsing issues cause high CPU usage during paramete... |
| GHSA-m44j-cfrm-g8qc | UNKNOWN | N/A | Bouncy Castle crafted signature and public key can be used to trigger an infi... |
| GHSA-v435-xc8x-wvr9 | UNKNOWN | N/A | Bouncy Castle affected by timing side-channel for RSA key exchange ("The Marv... |

### guava v31.0.1-jre

PURL: `pkg:maven/com.google.guava/guava@31.0.1-jre?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-5mg8-w23w-74h3 | UNKNOWN | N/A | Information Disclosure in Guava |
| GHSA-7g45-4rm6-3mm3 | UNKNOWN | N/A | Guava vulnerable to insecure use of temporary directory |

### assertj-core v3.25.1

PURL: `pkg:maven/org.assertj/assertj-core@3.25.1?type=jar`

| ID | Severity | Score | Summary |
|----|----------|-------|---------|
| GHSA-rqfh-9r24-8c9r | UNKNOWN | N/A | AssertJ has XML External Entity (XXE) vulnerability when parsing untrusted XM... |

## SBOM Overview

| Field | Value |
|-------|-------|
| **Format** | CycloneDX |
| **Spec Version** | 1.6 |
| **Component Count** | 4400 |

---

*Generated by cra-auditflow v0.1.0 on 2026-01-27*
