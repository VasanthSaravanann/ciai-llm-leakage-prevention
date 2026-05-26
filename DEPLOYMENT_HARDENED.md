**Hardened Deployment Guidance**

Minimal recommendations to run CIAI in a hardened, enterprise-ready mode.

- **Network & VPC**: Deploy in a private VPC. Place the application in private subnets and use a NAT or egress-only gateway for provider API calls. Restrict inbound access to the app via an internal ALB only.
- **TLS**: Terminate TLS at the ingress (ALB/NGINX) with TLS 1.2+ and strong ciphers. Do not expose non-TLS endpoints.
- **Secrets**: Use a managed secrets store. Set `KMS_KEY_ID` or `FERNET_SECRET_NAME` for AWS Secrets Manager, or configure `VAULT_URL` + `VAULT_TOKEN` for Vault. Do not use env vars for provider keys in production.
- **DB & Redis**: Place DB and Redis in private subnets. Use security groups to restrict access to the app instances only. Prefer managed services (RDS, ElastiCache) and enforce encryption at rest.
- **IAM**: Use least-privilege IAM roles for any cloud services. Give the app only the permissions it needs (e.g., decrypt with KMS, read/write specific secrets).
- **Admin auth**: Enable `ADMIN_AUTH_REQUIRED=1` and configure an identity provider (OIDC) that maps groups to roles. Use the `ADMIN_API_KEY` for machine scraping only if necessary.
- **Monitoring & SLOs**: Expose `/metrics` to Prometheus in the internal network. Configure alerting for P95 latency, detection error rate, and Redis availability.
- **Key Rotation**: Use the `scripts/rotate_fernet_key.py` script to rotate envelope keys. Automate rotation and track key roll events.
- **Audit**: Ensure `ENCRYPT_LOGS=1` and store logs in an encrypted, access-controlled store. Audit admin accesses to `/dashboard` and `/metrics`.

Example env vars for hardened deploy (managed KMS + private Redis):

```
DATABASE_URL=postgresql://... (private)
REDIS_URL=redis://my-redis-cluster:6379/0
KMS_KEY_ID=arn:aws:kms:region:account:key/abcd-1234
FERNET_SECRET_NAME=ciai/fernet_key
ADMIN_AUTH_REQUIRED=1
GATEWAY_MODE=fail_closed
```

See README.md for additional operational notes.
