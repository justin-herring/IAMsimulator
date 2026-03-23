# AWS IAM Simulator

A hands-on practice lab for learning AWS Identity and Access Management (IAM) concepts. Built with Flask and SQLite, pre-loaded with a realistic "AcmeCorp" scenario.

## What it covers

- **Users** — create and manage IAM users, attach policies directly or via groups
- **Groups** — organize users and apply shared permissions
- **Roles** — service roles with trust policies (EC2, Lambda, cross-account)
- **Policies** — create and edit JSON policy documents with a built-in health checker
- **Access Simulator** — evaluate whether a user or role can perform an action on a resource, with a full step-by-step evaluation trace
- **Audit Log** — tracks every action taken in the lab

## Key concepts demonstrated

- Explicit Deny always overrides Allow
- Policy inheritance through groups
- Least-privilege scoping to specific resources
- Cross-account role assumption with MFA conditions
- Service roles for EC2 and Lambda

## Pre-loaded scenario (AcmeCorp)

| Principal | Access |
|-----------|--------|
| alice | AdminFullAccess via Admins group |
| bob | S3ReadOnly + EC2ReadOnly via Engineers group, DenyBilling direct |
| carol | BillingReadOnly via FinanceTeam + scoped S3 bucket access |

**Try these in the simulator:**
```
bob  + s3:GetObject       + arn:aws:s3:::acme-reports/q1.csv  → ALLOW
bob  + billing:ViewBilling + *                                  → DENY
carol + billing:ViewBilling + *                                 → ALLOW
alice + ec2:TerminateInstances + *                              → ALLOW
```

## Getting started

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py

# Open in browser
http://localhost:5000
```

## Tech stack

- Python / Flask
- SQLAlchemy / SQLite
- Bootstrap 5
