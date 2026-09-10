# Deployment & Production Architecture Guide

## 1. Docker Compose Deployment
Launch the full containerized stack (Proxy, Frontend Dashboard, Redis):
```bash
docker-compose up -d --build
```
Services will be available at:
- **Proxy Gateway**: `http://localhost:8000`
- **Security Dashboard**: `http://localhost:5173`
- **Redis Cache**: `localhost:6379`

---

## 2. Production Hardening Checklist
1. **TLS / HTTPS**: Terminate TLS at Nginx, Cloudflare, or an AWS Application Load Balancer with valid SSL certificates.
2. **CORS Restrictions**: In `proxy/server.py`, replace `allow_origins=["*"]` with explicit production domains (e.g. `https://sentinel.internal.org`).
3. **Audit Ledger Persistence**: Configure persistent volume mounts for `AUDIT_STORAGE_PATH` to ensure audit chain preservation across container restarts.
4. **Secrets Management**: Supply environment variables via HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets. Never store production credentials in `.env` files.

---

## 3. Backup & Disaster Recovery
- **Audit Ledger Backup**:
  ```bash
  cp data/audit_ledger.db data/audit_ledger_$(date +%Y%m%d).db.bak
  ```
- **Integrity Validation Post-Restore**:
  Invoke `GET /audit` to verify the SHA-256 chain remains contiguous.
