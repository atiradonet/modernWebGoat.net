# ModernWebGoat.NET

A **deliberately vulnerable** ASP.NET Core application for secure coding training. Covers all **OWASP Top 10 (2025)** categories with exploitable examples in both Minimal API endpoints and Razor Pages.

> **WARNING:** This application is intentionally insecure. Do **NOT** deploy it to any network-accessible environment. Run it only on localhost for educational purposes.

## Quick Start

```bash
# Prerequisites: .NET 10 SDK
git clone git@github.com:atiradonet/modernWebGoat.net.git
cd modernWebGoat.net/src/ModernWebGoat
dotnet run
```

Open http://localhost:5000 — the landing page links to every vulnerability category.

## Tech Stack

- .NET 10 / C# 14
- ASP.NET Core Minimal API + Razor Pages
- Entity Framework Core with SQLite
- Newtonsoft.Json (for insecure deserialization demos)

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| alice | password | user |
| bob | bob | user |

## Vulnerability Index

### A01 — Broken Access Control
| Vulnerability | Endpoint |
|---------------|----------|
| IDOR — access any user's profile | `GET /api/users/{id}` |
| Missing function-level authorization | `GET /api/admin/users` |
| Path traversal | `GET /api/files/download?name=../../etc/passwd` |
| Path traversal (page) | `/Vulnerabilities/FileDownload` |
| CORS misconfiguration | `AllowAnyOrigin()` in Program.cs |
| SSRF (API) | `GET /api/fetch?url=http://169.254.169.254/` |
| SSRF (page) | `/Vulnerabilities/FetchUrl` |

### A02 — Security Misconfiguration
| Vulnerability | Endpoint |
|---------------|----------|
| Detailed error / stack trace | `GET /api/config/error` |
| App config exposure | `GET /api/config/info` |
| Directory browsing | `/uploads/` |
| Missing security headers | All responses |

### A03 — Software Supply Chain Failures *(NEW in 2025)*
| Vulnerability | Endpoint |
|---------------|----------|
| Dependency inventory | `GET /api/supply-chain/dependencies` |
| No SBOM generated | `GET /api/supply-chain/sbom` |
| No dependency pinning / lock file | `GET /api/supply-chain/pinning` |
| Unverified package download | `POST /api/supply-chain/install-package` |

### A04 — Cryptographic Failures
| Vulnerability | Endpoint |
|---------------|----------|
| Weak encryption (DES) | `GET /api/crypto/encrypt?data=hello` |
| Hardcoded secrets exposed | `GET /api/crypto/secrets` |
| MD5 hashing demo | `GET /api/crypto/hash?data=password` |
| SSN/CC in plaintext | `GET /api/users/1` |

### A05 — Injection
| Vulnerability | Endpoint |
|---------------|----------|
| SQL injection | `/Vulnerabilities/SqlSearch?Query=' OR 1=1 --` |
| SQL injection (API) | `GET /api/injection/products?q=' OR 1=1 --` |
| Command injection | `/Vulnerabilities/CommandExec` (POST: `127.0.0.1; id`) |
| Command injection (API) | `POST /api/injection/exec` |
| Reflected XSS | `/Vulnerabilities/Search?Query=<script>alert(1)</script>` |
| Stored XSS | `/Vulnerabilities/Comments` |

### A06 — Insecure Design
| Vulnerability | Endpoint |
|---------------|----------|
| Negative quantity order | `POST /api/orders` (`{"quantity": -5}`) |
| Unlimited coupon reuse | `POST /api/orders` (`{"couponCode": "DISCOUNT50"}`) |
| Predictable reset token | `POST /api/password-reset?username=admin` |
| No rate limiting | All endpoints |

### A07 — Authentication Failures
| Vulnerability | Endpoint |
|---------------|----------|
| No account lockout | `/Vulnerabilities/Login` |
| Weak password policy | `/Vulnerabilities/Register` |
| Insecure JWT (5-char key) | `POST /api/auth/login` |
| JWT config info | `GET /api/auth/jwt-info` |

### A08 — Software or Data Integrity Failures
| Vulnerability | Endpoint |
|---------------|----------|
| Insecure deserialization | `POST /api/deserialize/` (TypeNameHandling.All) |
| Deserialization info | `GET /api/deserialize/info` |

### A09 — Security Logging & Alerting Failures
| Vulnerability | Endpoint |
|---------------|----------|
| Sensitive data in logs | `POST /api/log/sensitive` |
| Audit logs with PII | `GET /api/log/audit` |

### A10 — Mishandling of Exceptional Conditions *(NEW in 2025)*
| Vulnerability | Endpoint |
|---------------|----------|
| Fail-open auth bypass | `GET /api/exceptional/fail-open?token=` |
| Null dereference stack trace leak | `GET /api/exceptional/null-deref?id=99999` |
| Integer overflow | `GET /api/exceptional/overflow?price=2147483647&quantity=2` |
| Transfer with no edge-case validation | `POST /api/exceptional/transfer` |
| TOCTOU race condition (withdraw) | `POST /api/exceptional/withdraw` |
| Category info | `GET /api/exceptional/info` |

## Project Structure

```
src/ModernWebGoat/
├── Program.cs              # Entry point + all misconfigurations
├── appsettings.json        # Hardcoded secrets (A04)
├── Data/                   # DbContext + seed data
├── Models/                 # User, Product, Order, Comment, AuditLog
├── Endpoints/              # Minimal API endpoints by OWASP category
├── Pages/                  # Razor Pages (interactive vulnerability demos)
└── wwwroot/                # Static files + uploads directory
```

## License

MIT
