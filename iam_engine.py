"""
iam_engine.py — AWS IAM Policy Evaluation Engine

This is the heart of the simulator. It implements the same logic that AWS
uses internally when deciding whether to allow or deny an API call.

AWS IAM Evaluation Logic (in order):
  1. Start with implicit DENY (default is always deny)
  2. Check all applicable policies for an explicit DENY  → if found: DENY
  3. Check all applicable policies for an explicit ALLOW → if found: ALLOW
  4. No matching allow found                             → implicit DENY

Key concepts:
  - Explicit Deny ALWAYS wins, even if another policy explicitly allows it.
  - Wildcards: "*" matches any string; "s3:*" matches any S3 action;
    "arn:aws:s3:::bucket/*" matches any object in that bucket.
  - Policies are evaluated as a UNION — all attached policies are combined.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
"""

import fnmatch
import json
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Result dataclass — returned by evaluate()
# ---------------------------------------------------------------------------

@dataclass
class EvaluationStep:
    """Represents one step in the policy evaluation trace."""
    policy_name: str
    statement_index: int
    effect: str         # "Allow" or "Deny"
    matched_action: str
    matched_resource: str
    outcome: str        # "MATCHED_DENY", "MATCHED_ALLOW", "NO_MATCH"
    reason: str         # human-readable explanation


@dataclass
class EvaluationResult:
    """The final result of evaluating a principal's access to an action+resource."""
    decision: str                          # "ALLOW" or "DENY"
    reason: str                            # human-readable summary
    matching_policy: Optional[str] = None  # policy name that determined the result
    steps: List[EvaluationStep] = field(default_factory=list)

    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"


# ---------------------------------------------------------------------------
# Wildcard matching helper
# ---------------------------------------------------------------------------

def _matches(pattern: str, value: str) -> bool:
    """
    Case-insensitive wildcard match supporting * and ?.
    AWS IAM uses case-insensitive matching for actions (e.g., s3:getobject == s3:GetObject)
    but case-sensitive for resource ARNs.
    """
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _action_matches(pattern: str, action: str) -> bool:
    """Check if an action matches a pattern (supports wildcards, e.g., 's3:*')."""
    return _matches(pattern, action)


def _resource_matches(pattern: str, resource: str) -> bool:
    """
    Check if a resource ARN matches a pattern.
    "*" matches everything.
    "arn:aws:s3:::my-bucket/*" matches any object in my-bucket.
    """
    if pattern == "*":
        return True
    return fnmatch.fnmatchcase(resource, pattern)


# ---------------------------------------------------------------------------
# Statement evaluation
# ---------------------------------------------------------------------------

def _evaluate_statement(stmt: dict, action: str, resource: str) -> Optional[str]:
    """
    Evaluate a single policy Statement against the requested action and resource.

    Returns:
      "Allow"  — this statement explicitly allows the action
      "Deny"   — this statement explicitly denies the action
      None     — this statement does not apply (no match)
    """
    effect = stmt.get("Effect", "")
    if effect not in ("Allow", "Deny"):
        return None

    # --- Action matching ---
    raw_actions = stmt.get("Action", [])
    not_actions = stmt.get("NotAction", [])

    if raw_actions:
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]
        action_match = any(_action_matches(a, action) for a in raw_actions)
    elif not_actions:
        # NotAction: applies to every action EXCEPT the listed ones
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        action_match = not any(_action_matches(a, action) for a in not_actions)
    else:
        return None

    if not action_match:
        return None

    # --- Resource matching ---
    raw_resources = stmt.get("Resource", [])
    if isinstance(raw_resources, str):
        raw_resources = [raw_resources]

    resource_match = any(_resource_matches(r, resource) for r in raw_resources)
    if not resource_match:
        return None

    return effect  # "Allow" or "Deny"


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

def evaluate(principal_policies: list, action: str, resource: str) -> EvaluationResult:
    """
    Evaluate whether a principal (identified by their list of Policy objects)
    is allowed to perform `action` on `resource`.

    Args:
        principal_policies: list of Policy model instances attached to the principal
        action:             the IAM action being requested, e.g. "s3:GetObject"
        resource:           the resource ARN, e.g. "arn:aws:s3:::my-bucket/report.csv"

    Returns:
        EvaluationResult with decision, reason, and full evaluation trace
    """
    steps: List[EvaluationStep] = []
    explicit_allows: List[EvaluationStep] = []

    # Step 1 — Walk every policy and every statement
    for policy in principal_policies:
        try:
            doc = json.loads(policy.policy_document)
        except (json.JSONDecodeError, TypeError):
            continue

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, stmt in enumerate(statements):
            effect = _evaluate_statement(stmt, action, resource)

            raw_actions   = stmt.get("Action") or stmt.get("NotAction", "*")
            raw_resources = stmt.get("Resource", "*")

            step = EvaluationStep(
                policy_name=policy.name,
                statement_index=idx,
                effect=stmt.get("Effect", "Unknown"),
                matched_action=str(raw_actions),
                matched_resource=str(raw_resources),
                outcome="NO_MATCH",
                reason="",
            )

            if effect == "Deny":
                step.outcome = "MATCHED_DENY"
                step.reason = (
                    f"Statement [{idx}] in '{policy.name}' explicitly DENIES "
                    f"'{action}' on '{resource}'. "
                    f"Explicit Deny always wins — evaluation stops here."
                )
                steps.append(step)
                # Explicit deny → short-circuit immediately
                return EvaluationResult(
                    decision="DENY",
                    reason=step.reason,
                    matching_policy=policy.name,
                    steps=steps,
                )

            elif effect == "Allow":
                step.outcome = "MATCHED_ALLOW"
                step.reason = (
                    f"Statement [{idx}] in '{policy.name}' explicitly ALLOWS "
                    f"'{action}' on '{resource}'."
                )
                explicit_allows.append(step)

            else:
                step.reason = (
                    f"Statement [{idx}] in '{policy.name}' does not match "
                    f"action='{action}' or resource='{resource}' — skipped."
                )

            steps.append(step)

    # Step 2 — Did any statement allow it?
    if explicit_allows:
        first_allow = explicit_allows[0]
        return EvaluationResult(
            decision="ALLOW",
            reason=first_allow.reason,
            matching_policy=first_allow.policy_name,
            steps=steps,
        )

    # Step 3 — Implicit deny (no explicit allow found)
    reason = (
        f"No policy statement explicitly allows '{action}' on '{resource}'. "
        f"AWS IAM defaults to DENY when no Allow is found (implicit deny)."
    )
    if not principal_policies:
        reason = (
            f"This principal has no policies attached. "
            f"Without an explicit Allow, all requests are implicitly DENIED."
        )

    return EvaluationResult(
        decision="DENY",
        reason=reason,
        matching_policy=None,
        steps=steps,
    )


# ---------------------------------------------------------------------------
# Policy health checks (used by dashboard)
# ---------------------------------------------------------------------------

def check_policy_health(policy) -> List[str]:
    """
    Return a list of security warnings for a policy document.
    These mirror real AWS IAM best-practice checks.
    """
    warnings = []
    try:
        doc = json.loads(policy.policy_document)
    except (json.JSONDecodeError, TypeError):
        return ["Invalid JSON — policy document cannot be parsed."]

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if effect == "Allow":
            if "*" in actions or any(a.endswith(":*") and a.startswith("*") for a in actions):
                warnings.append(
                    f"Statement [{idx}]: Action '*' grants ALL permissions on ALL services. "
                    f"This violates least-privilege. Use specific service actions."
                )
            elif any(a.endswith(":*") for a in actions):
                service = actions[0].split(":")[0] if actions else "unknown"
                warnings.append(
                    f"Statement [{idx}]: '{actions[0]}' grants ALL {service} actions. "
                    f"Consider narrowing to only the actions you need."
                )

            if "*" in resources:
                warnings.append(
                    f"Statement [{idx}]: Resource '*' applies to ALL resources. "
                    f"Scope this to specific ARNs where possible."
                )

    return warnings
