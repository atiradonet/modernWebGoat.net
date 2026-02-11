# =============================================================================
# ModernWebGoat.NET — DELIBERATELY INSECURE Dockerfile
# =============================================================================
# This Dockerfile contains numerous security anti-patterns for training.
# Do NOT use this as a reference for production container builds.
# =============================================================================

# VULNERABILITY: Using 'latest' tag — non-reproducible builds, supply chain risk (A03)
# VULNERABILITY: Using full SDK image in production — massive attack surface (A02)
# The SDK image includes compilers, debuggers, and dev tools that should never ship
FROM mcr.microsoft.com/dotnet/sdk:latest

# VULNERABILITY: Metadata leaks internal info — org structure, contact, repo (A02)
LABEL maintainer="admin@modernwebgoat.local"
LABEL internal.team="AppSec Training"
LABEL internal.repo="https://github.com/atiradonet/modernWebGoat.net"
LABEL internal.cost-center="CC-4401-SECURITY"

# VULNERABILITY: Hardcoded secrets as ENV variables — visible in image history/inspect (A04)
# Anyone with 'docker inspect' or 'docker history' can extract these
ENV ASPNETCORE_ENVIRONMENT=Development
ENV JWT_SECRET=s3cr3
ENV DB_PASSWORD=admin123
ENV API_KEY=FAKE-AKIAIOSFODNN7EXAMPLE
ENV PAYMENT_GATEWAY_KEY=FAKE-pay-gateway-key-do-not-use
ENV INTERNAL_SECRET=super-secret-internal-key-12345
ENV ENCRYPTION_KEY=12345678

# VULNERABILITY: Running as root — container escape / privilege escalation (A02)
# No USER directive means everything runs as root (UID 0)

# VULNERABILITY: Installing unnecessary packages — expands attack surface (A02)
# curl, wget, vim, net-tools, procps are useful for attackers doing recon
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    net-tools \
    procps \
    dnsutils \
    iputils-ping \
    ssh \
    && rm -rf /var/lib/apt/lists/*

# VULNERABILITY: No .dockerignore — copies .git, obj, bin, secrets, IDE files (A02/A03)
# This leaks full git history, credentials, and build artifacts into the image
WORKDIR /app
COPY . .

# VULNERABILITY: Build and publish in same layer — dev dependencies in final image (A03)
RUN dotnet restore src/ModernWebGoat/ModernWebGoat.csproj \
    && dotnet publish src/ModernWebGoat/ModernWebGoat.csproj -c Release -o /app/publish

# VULNERABILITY: Exposing multiple ports including debug port (A02)
# Port 5000 = app, Port 4848 = debugger attach point
EXPOSE 5000
EXPOSE 4848

# VULNERABILITY: Disabling HTTPS entirely via env var (A02)
ENV ASPNETCORE_URLS=http://+:5000
ENV DOTNET_RUNNING_IN_CONTAINER=true

# VULNERABILITY: No HEALTHCHECK — orchestrators can't detect unhealthy containers (A02)
# No resource limits defined — container can consume unlimited host resources

# VULNERABILITY: No read-only filesystem hint — container can write anywhere (A02)

WORKDIR /app/publish
ENTRYPOINT ["dotnet", "ModernWebGoat.dll"]
