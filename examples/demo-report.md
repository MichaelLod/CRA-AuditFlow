# CRA Compliance Audit Report

**Product:** VaultKeeper
**Date:** 2026-07-23
**Tool:** cra-auditflow v0.1.0

---

## CRA Risk Classification

| Field | Value |
|-------|-------|
| **Risk Class** | Important (Class I) |
| **Matched Category** | Password managers |
| **Matched Keywords** | password manager |
| **Applicable Articles** | Article 32, Annex III Part I (3) |
| **Conformity Assessment** | Self-assessment or harmonised standards (Article 32) |

## Audit Summary

| Metric | Count |
|--------|-------|
| Total Components | 12 |
| Components with Vulnerabilities | 7 |
| Total Vulnerabilities | 38 |
| Critical | 1 |
| High | 16 |
| Medium | 16 |
| Low | 1 |
| Unknown | 4 |

## Vulnerability Findings

### express v4.17.1

PURL: `pkg:npm/express@4.17.1`

| ID | Aliases | Severity | Score | Fixed in | Summary |
|----|---------|----------|-------|----------|--------|
| [GHSA-qw6h-vgh9-j6wx](https://osv.dev/vulnerability/GHSA-qw6h-vgh9-j6wx) | CVE-2024-43796 | MEDIUM | 5.0 | 4.20.0, 5.0.0 | express vulnerable to XSS via response.redirect() |
| [GHSA-rv95-896h-c2vc](https://osv.dev/vulnerability/GHSA-rv95-896h-c2vc) | CVE-2024-29041 | MEDIUM | 6.1 | 4.19.2, 5.0.0-beta.3 | Express.js Open Redirect in malformed URLs |

### lodash v4.17.15

PURL: `pkg:npm/lodash@4.17.15`

| ID | Aliases | Severity | Score | Fixed in | Summary |
|----|---------|----------|-------|----------|--------|
| [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) | CVE-2020-28500 | MEDIUM | 5.3 | 4.17.21 | Regular Expression Denial of Service (ReDoS) in lodash |
| [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | CVE-2021-23337, CVE-2026-4800 | HIGH | 7.2 | 4.17.21 | Command Injection in lodash |
| [GHSA-f23m-r3pf-42rh](https://osv.dev/vulnerability/GHSA-f23m-r3pf-42rh) | CVE-2025-13465, CVE-2026-2950 | MEDIUM | 6.5 | 4.18.0 | lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` a... |
| [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) | CVE-2020-8203 | HIGH | 7.4 | 4.17.19 | Prototype Pollution in lodash |
| [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) | CVE-2021-23337, CVE-2026-4800 | HIGH | 8.1 | 4.18.0 | lodash vulnerable to Code Injection via `_.template` imports key names |
| [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) | CVE-2025-13465, CVE-2026-2950 | MEDIUM | 6.5 | 4.17.23 | Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions |

### minimist v1.2.5

PURL: `pkg:npm/minimist@1.2.5`

| ID | Aliases | Severity | Score | Fixed in | Summary |
|----|---------|----------|-------|----------|--------|
| [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | CVE-2021-44906 | CRITICAL | 9.8 | 1.2.6, 0.2.4 | Prototype Pollution in minimist |

### axios v0.21.1

PURL: `pkg:npm/axios@0.21.1`

| ID | Aliases | Severity | Score | Fixed in | Summary |
|----|---------|----------|-------|----------|--------|
| [GHSA-3g43-6gmg-66jw](https://osv.dev/vulnerability/GHSA-3g43-6gmg-66jw) | CVE-2026-44495 | HIGH | 7.0 | 1.15.2, 0.31.1 | axios Vulnerable to Credential Theft and Response Hijacking via Prototype Pol... |
| [GHSA-3p68-rc4w-qgx5](https://osv.dev/vulnerability/GHSA-3p68-rc4w-qgx5) | CVE-2025-62718 | MEDIUM | 4.8 | 1.15.0, 0.31.0 | Axios has a NO_PROXY Hostname Normalization Bypass that Leads to SSRF |
| [GHSA-43fc-jf86-j433](https://osv.dev/vulnerability/GHSA-43fc-jf86-j433) | CVE-2026-25639 | HIGH | 7.5 | 1.13.5, 0.30.3 | Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig |
| [GHSA-5c9x-8gcm-mpgx](https://osv.dev/vulnerability/GHSA-5c9x-8gcm-mpgx) | CVE-2026-42034 | MEDIUM | 5.3 | 1.15.1, 0.31.1 | Axios' HTTP adapter-streamed uploads bypass maxBodyLength when maxRedirects: 0 |
| [GHSA-62hf-57xw-28j9](https://osv.dev/vulnerability/GHSA-62hf-57xw-28j9) | CVE-2026-42039 | HIGH | 7.5 | 1.15.1, 0.31.1 | Axios: unbounded recursion in toFormData causes DoS via deeply nested request... |
| [GHSA-6chq-wfr3-2hj9](https://osv.dev/vulnerability/GHSA-6chq-wfr3-2hj9) | CVE-2026-42035 | HIGH | 7.4 | 1.15.1, 0.31.1 | Axios: Header Injection via Prototype Pollution |
| [GHSA-7q8q-rj6j-mhjq](https://osv.dev/vulnerability/GHSA-7q8q-rj6j-mhjq) | — | UNKNOWN | N/A | 0.33.0, 1.18.0 | Axios: Nested axios option objects can consume polluted prototype values |
| [GHSA-898c-q2cr-xwhg](https://osv.dev/vulnerability/GHSA-898c-q2cr-xwhg) | CVE-2026-44490 | MEDIUM | 4.8 | 1.16.0, 0.32.0 | axios has DoS & Header Injection via Prototype Pollution Read-Side Gadgets in... |
| [GHSA-cph5-m8f7-6c5x](https://osv.dev/vulnerability/GHSA-cph5-m8f7-6c5x) | CVE-2021-3749 | HIGH | 7.5 | 0.21.2 | axios Inefficient Regular Expression Complexity vulnerability |
| [GHSA-fvcv-3m26-pcqx](https://osv.dev/vulnerability/GHSA-fvcv-3m26-pcqx) | CVE-2026-40175 | MEDIUM | 4.8 | 1.15.0, 0.31.0 | Axios has Unrestricted Cloud Metadata Exfiltration via Header Injection Chain |
| [GHSA-hfxv-24rg-xrqf](https://osv.dev/vulnerability/GHSA-hfxv-24rg-xrqf) | CVE-2026-44496 | HIGH | 7.5 | 1.16.0, 0.32.0 | Axios: Regular Expression Denial of Service (ReDoS) via Cookie Name Injection |
| [GHSA-j5f8-grm9-p9fc](https://osv.dev/vulnerability/GHSA-j5f8-grm9-p9fc) | CVE-2026-44486 | HIGH | 7.5 | 1.16.0, 0.32.0 | Axios: Proxy-Authorization header leaks to redirect target when proxy is re-e... |
| [GHSA-jr5f-v2jv-69x6](https://osv.dev/vulnerability/GHSA-jr5f-v2jv-69x6) | CVE-2025-27152 | UNKNOWN | N/A | 1.8.2, 0.30.0 | axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolut... |
| [GHSA-m7pr-hjqh-92cm](https://osv.dev/vulnerability/GHSA-m7pr-hjqh-92cm) | CVE-2026-42038 | MEDIUM | 6.8 | 1.15.1, 0.31.1 | Axios: no_proxy bypass via IP alias allows SSRF |
| [GHSA-mmx7-hfxf-jppx](https://osv.dev/vulnerability/GHSA-mmx7-hfxf-jppx) | — | UNKNOWN | N/A | 1.18.0, 0.33.0 | Axios: Prototype pollution gadgets can alter axios request construction |
| [GHSA-p92q-9vqr-4j8v](https://osv.dev/vulnerability/GHSA-p92q-9vqr-4j8v) | CVE-2026-44487 | UNKNOWN | N/A | 1.16.0, 0.32.0 | Axios: Proxy-Authorization Credential Leak to Origin Server Across HTTP-to-HT... |
| [GHSA-pf86-5x62-jrwf](https://osv.dev/vulnerability/GHSA-pf86-5x62-jrwf) | CVE-2026-42033 | HIGH | 7.4 | 1.15.1, 0.31.1 | Axios: Prototype Pollution Gadgets - Response Tampering, Data Exfiltration, a... |
| [GHSA-pjwm-pj3p-43mv](https://osv.dev/vulnerability/GHSA-pjwm-pj3p-43mv) | CVE-2026-44492 | HIGH | 8.6 | 1.16.0, 0.32.0 | axios's shouldBypassProxy does not recognize IPv4-mapped IPv6 addresses, allo... |
| [GHSA-pmwg-cvhr-8vh7](https://osv.dev/vulnerability/GHSA-pmwg-cvhr-8vh7) | CVE-2026-42043 | HIGH | 7.2 | 1.15.1, 0.31.1 | Axios: Incomplete Fix for CVE-2025-62718 — NO_PROXY Protection Bypassed via R... |
| [GHSA-vf2m-468p-8v99](https://osv.dev/vulnerability/GHSA-vf2m-468p-8v99) | CVE-2026-42036 | MEDIUM | 5.3 | 1.15.1, 0.31.1 | Axios: HTTP adapter streamed responses bypass maxContentLength |
| [GHSA-w9j2-pvgh-6h63](https://osv.dev/vulnerability/GHSA-w9j2-pvgh-6h63) | CVE-2026-42041 | MEDIUM | 4.8 | 1.15.1, 0.31.1 | Axios: Authentication Bypass via Prototype Pollution Gadget in `validateStatu... |
| [GHSA-wf5p-g6vw-rhxx](https://osv.dev/vulnerability/GHSA-wf5p-g6vw-rhxx) | CVE-2023-45857 | MEDIUM | 6.5 | 1.6.0, 0.28.0 | Axios Cross-Site Request Forgery Vulnerability |
| [GHSA-xhjh-pmcv-23jw](https://osv.dev/vulnerability/GHSA-xhjh-pmcv-23jw) | CVE-2026-42040 | LOW | 3.7 | 1.15.1, 0.31.1 | Axios: Null Byte Injection via Reverse-Encoding in AxiosURLSearchParams |
| [GHSA-xx6v-rp6x-q39c](https://osv.dev/vulnerability/GHSA-xx6v-rp6x-q39c) | CVE-2026-42042 | MEDIUM | 5.4 | 1.15.1, 0.31.1 | Axios: XSRF Token Cross-Origin Leakage via Prototype Pollution Gadget in `wit... |

### node-fetch v2.6.1

PURL: `pkg:npm/node-fetch@2.6.1`

| ID | Aliases | Severity | Score | Fixed in | Summary |
|----|---------|----------|-------|----------|--------|
| [GHSA-r683-j2x4-v87g](https://osv.dev/vulnerability/GHSA-r683-j2x4-v87g) | CVE-2022-0235 | HIGH | 8.8 | 3.1.1, 2.6.7 | node-fetch forwards secure headers to untrusted sites |

### jsonwebtoken v8.5.1

PURL: `pkg:npm/jsonwebtoken@8.5.1`

| ID | Aliases | Severity | Score | Fixed in | Summary |
|----|---------|----------|-------|----------|--------|
| [GHSA-8cf7-32gw-wr33](https://osv.dev/vulnerability/GHSA-8cf7-32gw-wr33) | CVE-2022-23539 | HIGH | 8.1 | 9.0.0 | jsonwebtoken unrestricted key type could lead to legacy keys usage  |
| [GHSA-hjrf-2m68-5959](https://osv.dev/vulnerability/GHSA-hjrf-2m68-5959) | CVE-2022-23541 | MEDIUM | 5.0 | 9.0.0 | jsonwebtoken's insecure implementation of key retrieval function could lead t... |
| [GHSA-qwph-4952-7xr6](https://osv.dev/vulnerability/GHSA-qwph-4952-7xr6) | CVE-2022-23540 | MEDIUM | 6.4 | 9.0.0 | jsonwebtoken vulnerable to signature validation bypass due to insecure defaul... |

### uuid v9.0.1

PURL: `pkg:npm/uuid@9.0.1`

| ID | Aliases | Severity | Score | Fixed in | Summary |
|----|---------|----------|-------|----------|--------|
| [GHSA-w5hq-g745-h8pq](https://osv.dev/vulnerability/GHSA-w5hq-g745-h8pq) | CVE-2026-41907, CVE-2026-41988 | HIGH | 7.5 | 11.1.1, 12.0.1, 13.0.1 | uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided |

## SBOM Overview

| Field | Value |
|-------|-------|
| **Format** | CycloneDX |
| **Spec Version** | 1.5 |
| **Component Count** | 12 |

---

*Generated by cra-auditflow v0.1.0 on 2026-07-23*
