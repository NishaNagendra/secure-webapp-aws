# Secure Web App Deployment on AWS

A minimal Flask "Hello World" application deployed with defense-in-depth security controls on AWS — network segmentation, least-privilege IAM, encryption at rest and in transit, a Web Application Firewall, and validated with a real OWASP ZAP scan (with before/after remediation).

**Live demo:** https://app.nisha-cloudsec.com *(may be taken down after portfolio review period to control costs)*

| Before HTTPS (plain HTTP) | After HTTPS (ACM cert + padlock) |
|---|---|
| ![HTTP - Not Secure](screenshots/01-http-working-notsecure.png) | ![HTTPS - Secure](screenshots/02-https-working-padlock.png) |

> The application itself is intentionally trivial. The point of this project is the security architecture around it — the kind of defense-in-depth a company would expect around any internet-facing service, however simple.

---

## Architecture

```
                         Internet
                            │
                            ▼
                  ┌───────────────────┐
                  │   AWS WAF          │  ← blocks SQLi / XSS / common attack patterns
                  │  (Managed Rules)   │
                  └─────────┬─────────┘
                            │
                  ┌─────────▼─────────┐
                  │  Application Load  │  Public Subnets (2 AZs)
                  │  Balancer (ALB)    │  HTTPS :443 (ACM cert)
                  │                    │  HTTP :80 → 301 redirect to HTTPS
                  └─────────┬─────────┘
                            │ (Security Group: ALB only allowed in)
                            ▼
                  ┌─────────────────────┐
                  │   EC2 Instance       │  Private Subnet
                  │   (Amazon Linux 2023)│  No public IP
                  │   Flask + Gunicorn   │  Encrypted EBS volume
                  │   (systemd service)  │  IMDSv2 enforced
                  └─────────┬───────────┘
                            │ (outbound only)
                            ▼
                  ┌─────────────────────┐
                  │   NAT Gateway        │  Public Subnet
                  └─────────┬───────────┘
                            │
                            ▼
                        Internet
                  (for OS updates/packages only —
                   no inbound path exists to the instance)
```

**Access for administration:** AWS Systems Manager (SSM) Session Manager — no SSH port open, no bastion host, no long-lived SSH keys. Access is IAM-authenticated and fully audit-logged by CloudTrail.

---

## Security controls and the reasoning behind each

| Control | Implementation | What it defends against |
|---|---|---|
| **Network segmentation** | EC2 lives in a private subnet with no route to the internet except outbound-via-NAT. The ALB is the only internet-facing component, in a public subnet. | Removes the app server as a direct target for internet-wide scanning/exploitation — it simply isn't reachable except through the ALB. |
| **Locked-down Security Groups** | EC2's Security Group allows inbound traffic on the app port **only from the ALB's Security Group** (a group reference, not a CIDR range). | Even if an attacker discovers the EC2 instance's private IP, no path exists to reach it except through the load balancer. This is stricter than allow-listing an IP range, since it's tied to identity, not location. |
| **Least-privilege IAM role** | EC2 instance role grants only `logs:CreateLogGroup` / `CreateLogStream` / `PutLogEvents`, scoped to a single log-group ARN prefix (`/secure-webapp/*`), not `*`. SSM Managed Instance Core was added separately, only for management access. No long-lived AWS access keys exist on the instance at all — credentials are short-lived and auto-rotated via the instance role. | If the instance is ever compromised, the blast radius is minimal: stolen credentials can't touch any other AWS service or even any other CloudWatch log group. |
| **Encrypted EBS volume** | Root volume created with `Encrypted: true` at launch time. | Protects data at rest — if a volume snapshot or disk were ever exposed, the data is unreadable without the KMS key. |
| **IMDSv2 enforced** (`HttpTokens: required`) | Default setting for new instances, explicitly verified. | Blocks a known SSRF-to-credential-theft attack pattern against the EC2 instance metadata service. |
| **HTTPS via ACM** | Free AWS-issued certificate for `app.nisha-cloudsec.com`, DNS-validated. TLS terminates at the ALB. | Encrypts traffic between the client and the ALB, preventing on-path interception/tampering. HTTP (port 80) issues a 301 redirect to HTTPS rather than serving plaintext. |
| **Plain HTTP between ALB and EC2** | Internal traffic (ALB → target group → EC2) is HTTP, not HTTPS. | This is a deliberate, standard pattern ("TLS termination at the load balancer"). This traffic never leaves the VPC, and the actual access control here is the Security Group (ALB-only) plus the lack of any internet route to the private subnet — not encryption. Encrypting internal-only traffic that's already access-controlled would add operational complexity (certificate management inside the VPC) without a proportional security benefit for this architecture. |
| **AWS WAF** | Regional Web ACL with AWS Managed Rule Groups (`AWSManagedRulesCommonRuleSet`, `AWSManagedRulesSQLiRuleSet`), associated with the ALB. | Filters common web attack patterns (SQL injection, XSS, and other OWASP Top 10-style payloads) before they ever reach the application. |
| **Security response headers** | `Content-Security-Policy`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` — added via Flask's `after_request` hook. | Defense-in-depth against XSS (CSP), clickjacking (X-Frame-Options / `frame-ancestors`), protocol downgrade attacks (HSTS), and MIME-sniffing attacks (X-Content-Type-Options). |
| **No SSH / SSM Session Manager only** | Instance is managed exclusively via AWS SSM Session Manager. | No open SSH port (22) anywhere in the architecture, no key management/rotation burden, and every session is logged and IAM-authenticated rather than relying on a shared key file. |
| **Production WSGI server** | App runs under Gunicorn, not Flask's built-in development server, managed as a systemd service (auto-restart on crash/reboot). | Flask's dev server is single-threaded and explicitly unsuitable for handling concurrent/adversarial traffic (including security scanning) — using it in a security-focused deployment would undermine the exercise. |

---

## Threat model

**In scope / mitigated:**
- Unauthenticated internet scanning and direct exploitation attempts against the app server → blocked by network isolation (no public IP, private subnet)
- Lateral movement from a compromised load balancer or adjacent resource → blocked by Security Group rules referencing the ALB's identity, not an IP range
- Credential theft via a compromised instance → limited blast radius via least-privilege IAM role, no long-lived keys, IMDSv2
- Data exposure via disk/snapshot leakage → mitigated by EBS encryption
- On-path interception of client traffic → mitigated by HTTPS/ACM + HSTS
- SQL injection / common injection attacks against the application → mitigated by WAF managed rule groups (demonstrated live, see below)
- Clickjacking, MIME-sniffing, protocol downgrade attacks → mitigated by response security headers

**Explicitly out of scope for this lab:**
- DDoS-scale volumetric attacks (would require AWS Shield Advanced, not included here)
- Application-layer business logic vulnerabilities (the app has no meaningful logic — it returns a static string)
- Multi-AZ high availability for the EC2 instance itself (single-AZ used to control lab cost; the ALB/subnets are multi-AZ)
- Full CSP directive coverage for every possible resource type (see ZAP findings below — evaluated as low risk for this app's actual resource usage)

---

## OWASP ZAP scan results (self-tested)

I ran an OWASP ZAP Automated Scan (traditional spider + active scan, "Dev Standard" policy) against the live HTTPS endpoint, authorized as the account/application owner. To ensure the scan exercised the application itself rather than being absorbed by WAF, the Web ACL was temporarily disassociated from the ALB during this test; WAF's own blocking behavior was separately verified (see below) and re-associated afterward.

### Before remediation — 5 finding types

![ZAP scan before remediation - 5 findings](screenshots/04-zap-scan-before-5-findings.png)

| Finding | Severity | Description |
|---|---|---|
| Content Security Policy (CSP) Header Not Set | Medium (informational) | No CSP header present at all |
| Missing Anti-clickjacking Header | Medium (informational) | No `X-Frame-Options` header |
| Strict-Transport-Security Header Not Set | Medium (informational) | No HSTS header |
| X-Content-Type-Options Header Missing | Low | No MIME-sniffing protection header |
| Re-examine Cache-Control Directives | Informational | Cache behavior not explicitly defined |

### Remediation
Added a Flask `after_request` hook setting all missing headers, then restarted the service and re-scanned in a fresh ZAP session (to avoid stale/cached findings from the first run).

### After remediation — 2 finding types remaining

![ZAP scan after remediation - 2 findings](screenshots/05-zap-scan-after-2-findings.png)

| Finding | Severity | Status |
|---|---|---|
| CSP: Failure to Define Directive with No Fallback | Low | **Accepted risk.** ZAP flags that the CSP doesn't explicitly define every possible directive type (e.g. `manifest-src`, `worker-src`, `form-action`). I defined directives for every resource type this app actually uses (scripts, styles, images, fonts, connections) and explicitly denied objects/framing. The remaining flagged directives apply to features this app doesn't use — assessed as low risk rather than adding unused-directive noise. |
| Re-examine Cache-Control Directives | Informational | Same informational note as before; `Cache-Control: no-store` is already set, this is ZAP's generic suggestion to review, not a specific defect. |

**Net result:** 3 of 5 original findings fully resolved (anti-clickjacking, HSTS, X-Content-Type-Options); the CSP finding was substantially hardened (from "missing entirely" to "present, explicit for all used resource types") and the remainder was a documented, risk-assessed decision rather than an oversight.

---

## WAF — live blocking demonstration

With the Web ACL re-associated to the ALB, I sent a request containing a classic SQL injection pattern:

```
https://app.nisha-cloudsec.com/?id=1' OR '1'='1
```

**Result:** `403 Forbidden`, generated by AWS WAF's `AWSManagedRulesSQLiRuleSet` (confirmed via `get-sampled-requests`, showing the exact rule that matched, source IP, and full request).

![WAF blocking SQL injection attempt](screenshots/03-waf-blocks-sqli-403.png)

A normal request to the same URL (no attack payload) continued to return the application's expected response, confirming the WAF is discriminating between malicious and legitimate traffic rather than blocking indiscriminately.

---

## Access & operations notes

- All infrastructure was provisioned via AWS CLI under a dedicated, purpose-scoped IAM user (`secure-webapp-builder`) — kept separate from an existing read-only auditing identity used for other projects, to keep permission scopes clean and intentional.
- Root/console credentials were used only for account-level tasks (checking Free Tier/billing status) — never for resource provisioning.
- DNS is managed via Cloudflare (domain registrar); AWS ACM validates ownership via a DNS CNAME record, and application traffic is routed directly to the ALB (Cloudflare proxying disabled for this record) so that TLS terminates at AWS, not at a third party.

## Known limitations / what I'd do differently in production

- Single-AZ EC2 (no auto-scaling group / multi-AZ compute) — acceptable for a demo, not for production availability requirements
- No automated CI/CD pipeline for deploying app changes — updates were made manually via SSM session for this lab
- WAF and the NAT Gateway are cost-bearing resources; they were run only for the duration of active testing rather than continuously, to control lab spend
- A production setup would likely also add: AWS Config rules for continuous compliance checking, GuardDuty for threat detection (see companion project), and a CI/CD pipeline with security scanning gates (SAST/dependency scanning) before deployment

---

## Related project

This deployment is also the target environment for a companion project: **GuardDuty + CloudWatch Threat Monitoring**, which simulates reconnaissance (Nmap) and privilege-escalation (IAM policy change) scenarios against this same EC2 instance, with automated Lambda-based incident response.
