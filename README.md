# ModernWebGoat.NET

A **deliberately vulnerable** ASP.NET Core application for secure coding training. Covers all **OWASP Top 10 (2021)** categories with exploitable examples in both Minimal API endpoints and Razor Pages.

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

### A02 — Cryptographic Failures
| Vulnerability | Endpoint |
|---------------|----------|
| Weak encryption (DES) | `GET /api/crypto/encrypt?data=hello` |
| Hardcoded secrets exposed | `GET /api/crypto/secrets` |
| MD5 hashing demo | `GET /api/crypto/hash?data=password` |
| SSN/CC in plaintext | `GET /api/users/1` |

### A03 — Injection
| Vulnerability | Endpoint |
|---------------|----------|
| SQL injection | `/Vulnerabilities/SqlSearch?Query=' OR 1=1 --` |
| SQL injection (API) | `GET /api/injection/products?q=' OR 1=1 --` |
| Command injection | `/Vulnerabilities/CommandExec` (POST: `127.0.0.1; id`) |
| Command injection (API) | `POST /api/injection/exec` |
| Reflected XSS | `/Vulnerabilities/Search?Query=<script>alert(1)</script>` |
| Stored XSS | `/Vulnerabilities/Comments` |

### A04 — Insecure Design
| Vulnerability | Endpoint |
|---------------|----------|
| Negative quantity order | `POST /api/orders` (`{"quantity": -5}`) |
| Unlimited coupon reuse | `POST /api/orders` (`{"couponCode": "DISCOUNT50"}`) |
| Predictable reset token | `POST /api/password-reset?username=admin` |
| No rate limiting | All endpoints |

### A05 — Security Misconfiguration
| Vulnerability | Endpoint |
|---------------|----------|
| Detailed error / stack trace | `GET /api/config/error` |
| App config exposure | `GET /api/config/info` |
| Directory browsing | `/uploads/` |
| Missing security headers | All responses |

### A06 — Vulnerable and Outdated Components
| Vulnerability | Endpoint |
|---------------|----------|
| Dependency inventory | `GET /api/config/dependencies` |

### A07 — Authentication Failures
| Vulnerability | Endpoint |
|---------------|----------|
| No account lockout | `/Vulnerabilities/Login` |
| Weak password policy | `/Vulnerabilities/Register` |
| Insecure JWT (5-char key) | `POST /api/auth/login` |
| JWT config info | `GET /api/auth/jwt-info` |

### A08 — Software and Data Integrity Failures
| Vulnerability | Endpoint |
|---------------|----------|
| Insecure deserialization | `POST /api/deserialize/` (TypeNameHandling.All) |
| Deserialization info | `GET /api/deserialize/info` |

### A09 — Logging & Monitoring Failures
| Vulnerability | Endpoint |
|---------------|----------|
| Sensitive data in logs | `POST /api/log/sensitive` |
| Audit logs with PII | `GET /api/log/audit` |

### A10 — Server-Side Request Forgery
| Vulnerability | Endpoint |
|---------------|----------|
| SSRF (API) | `GET /api/fetch?url=http://169.254.169.254/` |
| SSRF (page) | `/Vulnerabilities/FetchUrl` |

## Project Structure

```
src/ModernWebGoat/
├── Program.cs              # Entry point + all misconfigurations
├── appsettings.json        # Hardcoded secrets (A02)
├── Data/                   # DbContext + seed data
├── Models/                 # User, Product, Order, Comment, AuditLog
├── Endpoints/              # Minimal API endpoints by OWASP category
├── Pages/                  # Razor Pages (interactive vulnerability demos)
└── wwwroot/                # Static files + uploads directory
```

## License

MIT
