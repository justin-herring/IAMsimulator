"""
seed_data.py — Pre-populate the database with a realistic "AcmeCorp" IAM scenario.

This gives you a working environment to explore right away.
The scenario is designed to demonstrate key IAM concepts:

  - Least-privilege: each group gets only the permissions their role needs
  - Explicit deny: DenyBillingForEngineers overrides any allow (try it in simulator!)
  - Role assumption: EC2 and Lambda roles show how services get permissions
  - Policy inheritance: bob gets S3ReadOnly through Engineers group, not directly

Try these in the Simulator after seeding:
  - bob + s3:GetObject + arn:aws:s3:::acme-reports/*      → ALLOW (via group)
  - bob + billing:ViewBilling + *                          → DENY  (explicit deny)
  - carol + billing:ViewBilling + *                        → ALLOW (FinanceTeam)
  - alice + ec2:TerminateInstances + *                     → ALLOW (AdminFullAccess)
  - bob + ec2:TerminateInstances + *                       → DENY  (no allow in Engineers)
"""

import json
from models import db, User, Group, Role, Policy, AuditLog


# ---------------------------------------------------------------------------
# Policy documents
# ---------------------------------------------------------------------------

POLICIES = [
    {
        "name": "AdminFullAccess",
        "description": "Full access to all AWS services and resources. "
                       "Only assign to break-glass admin accounts.",
        "policy_type": "AWS_MANAGED",
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
    },
    {
        "name": "S3ReadOnly",
        "description": "Read-only access to all S3 buckets. "
                       "Useful for developers who need to inspect data.",
        "policy_type": "AWS_MANAGED",
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:GetBucketLocation"
                    ],
                    "Resource": "*"
                }
            ]
        }
    },
    {
        "name": "EC2ReadOnly",
        "description": "Read-only access to EC2 resources. "
                       "Engineers can view instances but not modify them.",
        "policy_type": "AWS_MANAGED",
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:DescribeImages",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeVpcs",
                        "ec2:DescribeSubnets"
                    ],
                    "Resource": "*"
                }
            ]
        }
    },
    {
        "name": "BillingReadOnly",
        "description": "Read access to billing and cost management. "
                       "Required for finance team to review AWS spend.",
        "policy_type": "AWS_MANAGED",
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "billing:ViewBilling",
                        "ce:GetCostAndUsage",
                        "ce:GetCostForecast",
                        "budgets:ViewBudget"
                    ],
                    "Resource": "*"
                }
            ]
        }
    },
    {
        "name": "DenyBillingForEngineers",
        "description": "Explicit DENY on billing actions for engineering staff. "
                       "This demonstrates that Deny ALWAYS overrides Allow — "
                       "even if a user is in a group that has billing access.",
        "policy_type": "CUSTOMER_MANAGED",
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": [
                        "billing:*",
                        "ce:*",
                        "budgets:*"
                    ],
                    "Resource": "*"
                }
            ]
        }
    },
    {
        "name": "S3AcmeReportsBucketReadWrite",
        "description": "Read and write access to the acme-reports S3 bucket only. "
                       "Scoped to a specific resource — this is least-privilege.",
        "policy_type": "CUSTOMER_MANAGED",
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [
                        "arn:aws:s3:::acme-reports",
                        "arn:aws:s3:::acme-reports/*"
                    ]
                }
            ]
        }
    },
    {
        "name": "LambdaBasicExecution",
        "description": "Minimum permissions for a Lambda function: write logs to CloudWatch.",
        "policy_type": "AWS_MANAGED",
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    "Resource": "arn:aws:logs:*:*:*"
                }
            ]
        }
    },
]


# ---------------------------------------------------------------------------
# Trust policies for roles
# ---------------------------------------------------------------------------

EC2_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}

LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}

CROSSACCOUNT_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"}
            }
        }
    ]
}


# ---------------------------------------------------------------------------
# Seed function
# ---------------------------------------------------------------------------

def seed(app):
    """Create all seed data inside the given Flask app context."""
    with app.app_context():
        # Skip if already seeded
        if User.query.count() > 0:
            print("Database already seeded — skipping.")
            return

        print("Seeding AcmeCorp IAM scenario...")

        # --- Create Policies ---
        policy_map = {}
        for p in POLICIES:
            policy = Policy(
                name=p["name"],
                description=p["description"],
                policy_type=p["policy_type"],
                policy_document=json.dumps(p["document"], indent=2),
            )
            db.session.add(policy)
            policy_map[p["name"]] = policy

        db.session.flush()

        # --- Create Groups ---
        admins_group = Group(
            name="Admins",
            description="Full administrative access. Membership should be strictly limited."
        )
        engineers_group = Group(
            name="Engineers",
            description="Software engineering team. S3 read + EC2 read access."
        )
        finance_group = Group(
            name="FinanceTeam",
            description="Finance department. Billing and reporting access."
        )

        db.session.add_all([admins_group, engineers_group, finance_group])
        db.session.flush()

        # Attach policies to groups
        admins_group.policies.append(policy_map["AdminFullAccess"])
        engineers_group.policies.append(policy_map["S3ReadOnly"])
        engineers_group.policies.append(policy_map["EC2ReadOnly"])
        finance_group.policies.append(policy_map["BillingReadOnly"])
        finance_group.policies.append(policy_map["S3ReadOnly"])

        # --- Create Users ---
        alice = User(
            username="alice",
            email="alice@acmecorp.com",
        )
        bob = User(
            username="bob",
            email="bob@acmecorp.com",
        )
        carol = User(
            username="carol",
            email="carol@acmecorp.com",
        )

        db.session.add_all([alice, bob, carol])
        db.session.flush()

        # Add users to groups
        alice.groups.append(admins_group)
        bob.groups.append(engineers_group)
        carol.groups.append(finance_group)

        # Attach a direct policy to bob to demonstrate deny-override
        # bob is in Engineers (gets S3ReadOnly + EC2ReadOnly via group)
        # but also has DenyBillingForEngineers directly — this blocks billing even
        # if he were ever added to FinanceTeam
        bob.policies.append(policy_map["DenyBillingForEngineers"])

        # carol also has a direct scoped policy for the reports bucket
        carol.policies.append(policy_map["S3AcmeReportsBucketReadWrite"])

        # --- Create Roles ---
        ec2_role = Role(
            name="EC2InstanceRole",
            description="Assumed by EC2 instances to access S3 and write logs. "
                        "Services use roles instead of users — no long-term credentials.",
            trust_policy=json.dumps(EC2_TRUST_POLICY, indent=2),
        )
        lambda_role = Role(
            name="LambdaExecutionRole",
            description="Assumed by Lambda functions. Minimum permissions: CloudWatch Logs.",
            trust_policy=json.dumps(LAMBDA_TRUST_POLICY, indent=2),
        )
        crossaccount_role = Role(
            name="CrossAccountReadRole",
            description="Can be assumed by account 123456789012 with MFA. "
                        "Demonstrates cross-account access patterns.",
            trust_policy=json.dumps(CROSSACCOUNT_TRUST_POLICY, indent=2),
        )

        db.session.add_all([ec2_role, lambda_role, crossaccount_role])
        db.session.flush()

        ec2_role.policies.append(policy_map["S3ReadOnly"])
        lambda_role.policies.append(policy_map["LambdaBasicExecution"])
        crossaccount_role.policies.append(policy_map["S3ReadOnly"])
        crossaccount_role.policies.append(policy_map["EC2ReadOnly"])

        # --- Seed Audit Log ---
        seed_events = [
            AuditLog(actor="system", action="CreateUser",   target="user:alice",  result="SUCCESS"),
            AuditLog(actor="system", action="CreateUser",   target="user:bob",    result="SUCCESS"),
            AuditLog(actor="system", action="CreateUser",   target="user:carol",  result="SUCCESS"),
            AuditLog(actor="system", action="CreateGroup",  target="group:Admins",       result="SUCCESS"),
            AuditLog(actor="system", action="AddUserToGroup", target="user:alice → group:Admins", result="SUCCESS"),
            AuditLog(actor="system", action="AttachGroupPolicy", target="group:Engineers → policy:S3ReadOnly", result="SUCCESS"),
            AuditLog(actor="system", action="AttachUserPolicy", target="user:bob → policy:DenyBillingForEngineers", result="SUCCESS"),
        ]
        db.session.add_all(seed_events)

        db.session.commit()
        print("Seeding complete.")
        print("\nTry these in the Simulator:")
        print("  bob  + s3:GetObject      + arn:aws:s3:::acme-reports/q1.csv -> ALLOW")
        print("  bob  + billing:ViewBilling + *                               -> DENY")
        print("  carol + billing:ViewBilling + *                              -> ALLOW")
        print("  alice + ec2:TerminateInstances + *                           -> ALLOW")
