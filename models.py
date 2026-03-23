"""
models.py — SQLAlchemy database models for the IAM Simulator.

This mirrors the core AWS IAM data model:
  - Users:    individual identities (humans, service accounts)
  - Groups:   collections of users that share permissions
  - Roles:    assumable identities (used by services, cross-account, etc.)
  - Policies: JSON documents that define what actions are allowed/denied
  - AuditLog: immutable record of every IAM change (like AWS CloudTrail)

Many-to-many relationships (called "attachments" in AWS):
  user  <-> group    (users belong to groups)
  user  <-> policy   (inline/attached policies on a user)
  group <-> policy   (inline/attached policies on a group)
  role  <-> policy   (inline/attached policies on a role)
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
import json

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Association / junction tables (pure many-to-many — no extra columns)
# ---------------------------------------------------------------------------

user_groups = db.Table(
    "user_groups",
    db.Column("user_id",  db.Integer, db.ForeignKey("users.id"),  primary_key=True),
    db.Column("group_id", db.Integer, db.ForeignKey("groups.id"), primary_key=True),
)

user_policies = db.Table(
    "user_policies",
    db.Column("user_id",   db.Integer, db.ForeignKey("users.id"),    primary_key=True),
    db.Column("policy_id", db.Integer, db.ForeignKey("policies.id"), primary_key=True),
)

group_policies = db.Table(
    "group_policies",
    db.Column("group_id",  db.Integer, db.ForeignKey("groups.id"),   primary_key=True),
    db.Column("policy_id", db.Integer, db.ForeignKey("policies.id"), primary_key=True),
)

role_policies = db.Table(
    "role_policies",
    db.Column("role_id",   db.Integer, db.ForeignKey("roles.id"),    primary_key=True),
    db.Column("policy_id", db.Integer, db.ForeignKey("policies.id"), primary_key=True),
)


# ---------------------------------------------------------------------------
# Primary entity models
# ---------------------------------------------------------------------------

class User(db.Model):
    """
    An IAM User represents a single identity (a person or application).
    In real AWS, users have long-term credentials (passwords, access keys).
    Best practice: prefer roles over long-lived user credentials.
    """
    __tablename__ = "users"

    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(64),  unique=True, nullable=False)
    email      = db.Column(db.String(128), unique=True, nullable=False)
    is_active  = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    groups   = db.relationship("Group",  secondary=user_groups,   back_populates="users")
    policies = db.relationship("Policy", secondary=user_policies, back_populates="users")

    def effective_policies(self):
        """Return all policies that apply to this user (direct + via groups)."""
        direct = list(self.policies)
        group_level = [p for g in self.groups for p in g.policies]
        # Deduplicate by id
        seen, result = set(), []
        for p in direct + group_level:
            if p.id not in seen:
                seen.add(p.id)
                result.append(p)
        return result

    def __repr__(self):
        return f"<User {self.username}>"


class Group(db.Model):
    """
    An IAM Group is a collection of users.
    Policies attached to a group apply to all members.
    Groups cannot be principals in policies (you can't grant access TO a group).
    """
    __tablename__ = "groups"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(64),  unique=True, nullable=False)
    description = db.Column(db.String(256), nullable=True)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    users    = db.relationship("User",   secondary=user_groups,   back_populates="groups")
    policies = db.relationship("Policy", secondary=group_policies, back_populates="groups")

    def __repr__(self):
        return f"<Group {self.name}>"


class Role(db.Model):
    """
    An IAM Role is an identity with specific permissions that can be ASSUMED
    by trusted entities (users, services, other accounts).
    Unlike users, roles have no long-term credentials — they issue temporary tokens.

    trust_policy: JSON that defines WHO can assume this role.
    Example: {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
              "Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
    """
    __tablename__ = "roles"

    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(64),  unique=True, nullable=False)
    description  = db.Column(db.String(256), nullable=True)
    trust_policy = db.Column(db.Text, nullable=False)   # JSON string
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    policies = db.relationship("Policy", secondary=role_policies, back_populates="roles")

    def trust_policy_parsed(self):
        try:
            return json.loads(self.trust_policy)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f"<Role {self.name}>"


class Policy(db.Model):
    """
    An IAM Policy is a JSON document that defines permissions.
    Structure:
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow" | "Deny",
            "Action": "s3:GetObject" | ["s3:*", "ec2:Describe*"],
            "Resource": "*" | "arn:aws:s3:::my-bucket/*"
          }
        ]
      }

    policy_type: "AWS_MANAGED" (like AmazonS3ReadOnlyAccess) or "CUSTOMER_MANAGED"
    """
    __tablename__ = "policies"

    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(128), unique=True, nullable=False)
    description     = db.Column(db.String(256), nullable=True)
    policy_document = db.Column(db.Text, nullable=False)   # JSON string
    policy_type     = db.Column(db.String(32), default="CUSTOMER_MANAGED")
    created_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    users  = db.relationship("User",  secondary=user_policies,  back_populates="policies")
    groups = db.relationship("Group", secondary=group_policies, back_populates="policies")
    roles  = db.relationship("Role",  secondary=role_policies,  back_populates="policies")

    def document_parsed(self):
        try:
            return json.loads(self.policy_document)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f"<Policy {self.name}>"


class AuditLog(db.Model):
    """
    Immutable audit trail of all IAM events — similar to AWS CloudTrail.
    In real AWS, every API call is recorded with who made it, when, and the result.
    This is critical for security investigations and compliance.
    """
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    actor      = db.Column(db.String(64),  nullable=False)   # who performed the action
    action     = db.Column(db.String(128), nullable=False)   # e.g. "AttachUserPolicy"
    target     = db.Column(db.String(128), nullable=True)    # e.g. "user:bob"
    detail     = db.Column(db.Text, nullable=True)           # JSON extra info
    result     = db.Column(db.String(16), default="SUCCESS") # SUCCESS | DENIED | ERROR

    def detail_parsed(self):
        try:
            return json.loads(self.detail) if self.detail else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f"<AuditLog {self.action} on {self.target}>"
