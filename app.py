"""
app.py — Flask application and all route handlers for the IAM Simulator.

Routes:
  GET  /                          → dashboard
  GET  /users                     → user list
  GET  /users/<id>                → user detail
  POST /users/create              → create user
  POST /users/<id>/delete         → delete user
  POST /users/<id>/attach-policy  → attach policy to user
  POST /users/<id>/detach-policy  → detach policy from user
  POST /users/<id>/add-group      → add user to group
  POST /users/<id>/remove-group   → remove user from group

  GET  /groups                    → group list
  GET  /groups/<id>               → group detail
  POST /groups/create             → create group
  POST /groups/<id>/delete        → delete group
  POST /groups/<id>/attach-policy → attach policy to group
  POST /groups/<id>/detach-policy → detach policy from group

  GET  /roles                     → role list
  GET  /roles/<id>                → role detail
  POST /roles/create              → create role
  POST /roles/<id>/delete         → delete role
  POST /roles/<id>/attach-policy  → attach policy to role
  POST /roles/<id>/detach-policy  → detach policy from role

  GET  /policies                  → policy list
  GET  /policies/<id>             → policy editor
  POST /policies/create           → create policy
  POST /policies/<id>/update      → update policy document
  POST /policies/<id>/delete      → delete policy

  GET  /simulator                 → simulator UI
  POST /simulator/evaluate        → run evaluation (JSON API)

  GET  /audit                     → audit log
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy

from models import db, User, Group, Role, Policy, AuditLog
from iam_engine import evaluate, check_policy_health
import seed_data

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "iam-simulator-dev-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'iam.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_event(action: str, target: str, actor: str = "admin", result: str = "SUCCESS", detail: dict = None):
    entry = AuditLog(
        actor=actor,
        action=action,
        target=target,
        result=result,
        detail=json.dumps(detail) if detail else None,
    )
    db.session.add(entry)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    users    = User.query.all()
    groups   = Group.query.all()
    roles    = Role.query.all()
    policies = Policy.query.all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()

    # Health checks
    warnings = []
    for u in users:
        if not u.policies and not u.groups:
            warnings.append(f"User '{u.username}' has no policies attached (no permissions).")
    for p in policies:
        issues = check_policy_health(p)
        for issue in issues:
            warnings.append(f"Policy '{p.name}': {issue}")

    return render_template(
        "dashboard.html",
        users=users, groups=groups, roles=roles, policies=policies,
        recent_logs=recent_logs, warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@app.route("/users")
def users_list():
    users = User.query.order_by(User.username).all()
    return render_template("users.html", users=users)


@app.route("/users/<int:user_id>")
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    all_policies = Policy.query.order_by(Policy.name).all()
    all_groups   = Group.query.order_by(Group.name).all()
    effective    = user.effective_policies()
    return render_template(
        "user_detail.html",
        user=user,
        all_policies=all_policies,
        all_groups=all_groups,
        effective_policies=effective,
    )


@app.route("/users/create", methods=["POST"])
def user_create():
    username = request.form.get("username", "").strip()
    email    = request.form.get("email", "").strip()
    if not username or not email:
        flash("Username and email are required.", "danger")
        return redirect(url_for("users_list"))
    if User.query.filter_by(username=username).first():
        flash(f"User '{username}' already exists.", "danger")
        return redirect(url_for("users_list"))
    user = User(username=username, email=email)
    db.session.add(user)
    log_event("CreateUser", f"user:{username}")
    db.session.commit()
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("user_detail", user_id=user.id))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    name = user.username
    db.session.delete(user)
    log_event("DeleteUser", f"user:{name}")
    db.session.commit()
    flash(f"User '{name}' deleted.", "warning")
    return redirect(url_for("users_list"))


@app.route("/users/<int:user_id>/attach-policy", methods=["POST"])
def user_attach_policy(user_id):
    user      = User.query.get_or_404(user_id)
    policy_id = request.form.get("policy_id", type=int)
    policy    = Policy.query.get_or_404(policy_id)
    if policy not in user.policies:
        user.policies.append(policy)
        log_event("AttachUserPolicy", f"user:{user.username} → policy:{policy.name}")
        db.session.commit()
        flash(f"Policy '{policy.name}' attached to {user.username}.", "success")
    else:
        flash(f"Policy '{policy.name}' is already attached.", "info")
    return redirect(url_for("user_detail", user_id=user_id))


@app.route("/users/<int:user_id>/detach-policy", methods=["POST"])
def user_detach_policy(user_id):
    user      = User.query.get_or_404(user_id)
    policy_id = request.form.get("policy_id", type=int)
    policy    = Policy.query.get_or_404(policy_id)
    if policy in user.policies:
        user.policies.remove(policy)
        log_event("DetachUserPolicy", f"user:{user.username} → policy:{policy.name}")
        db.session.commit()
        flash(f"Policy '{policy.name}' detached from {user.username}.", "warning")
    return redirect(url_for("user_detail", user_id=user_id))


@app.route("/users/<int:user_id>/add-group", methods=["POST"])
def user_add_group(user_id):
    user     = User.query.get_or_404(user_id)
    group_id = request.form.get("group_id", type=int)
    group    = Group.query.get_or_404(group_id)
    if group not in user.groups:
        user.groups.append(group)
        log_event("AddUserToGroup", f"user:{user.username} → group:{group.name}")
        db.session.commit()
        flash(f"{user.username} added to group '{group.name}'.", "success")
    else:
        flash(f"{user.username} is already in '{group.name}'.", "info")
    return redirect(url_for("user_detail", user_id=user_id))


@app.route("/users/<int:user_id>/remove-group", methods=["POST"])
def user_remove_group(user_id):
    user     = User.query.get_or_404(user_id)
    group_id = request.form.get("group_id", type=int)
    group    = Group.query.get_or_404(group_id)
    if group in user.groups:
        user.groups.remove(group)
        log_event("RemoveUserFromGroup", f"user:{user.username} → group:{group.name}")
        db.session.commit()
        flash(f"{user.username} removed from '{group.name}'.", "warning")
    return redirect(url_for("user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

@app.route("/groups")
def groups_list():
    groups = Group.query.order_by(Group.name).all()
    return render_template("groups.html", groups=groups)


@app.route("/groups/<int:group_id>")
def group_detail(group_id):
    group        = Group.query.get_or_404(group_id)
    all_policies = Policy.query.order_by(Policy.name).all()
    all_users    = User.query.order_by(User.username).all()
    return render_template(
        "group_detail.html",
        group=group, all_policies=all_policies, all_users=all_users,
    )


@app.route("/groups/create", methods=["POST"])
def group_create():
    name = request.form.get("name", "").strip()
    desc = request.form.get("description", "").strip()
    if not name:
        flash("Group name is required.", "danger")
        return redirect(url_for("groups_list"))
    if Group.query.filter_by(name=name).first():
        flash(f"Group '{name}' already exists.", "danger")
        return redirect(url_for("groups_list"))
    group = Group(name=name, description=desc)
    db.session.add(group)
    log_event("CreateGroup", f"group:{name}")
    db.session.commit()
    flash(f"Group '{name}' created.", "success")
    return redirect(url_for("group_detail", group_id=group.id))


@app.route("/groups/<int:group_id>/delete", methods=["POST"])
def group_delete(group_id):
    group = Group.query.get_or_404(group_id)
    name  = group.name
    db.session.delete(group)
    log_event("DeleteGroup", f"group:{name}")
    db.session.commit()
    flash(f"Group '{name}' deleted.", "warning")
    return redirect(url_for("groups_list"))


@app.route("/groups/<int:group_id>/attach-policy", methods=["POST"])
def group_attach_policy(group_id):
    group     = Group.query.get_or_404(group_id)
    policy_id = request.form.get("policy_id", type=int)
    policy    = Policy.query.get_or_404(policy_id)
    if policy not in group.policies:
        group.policies.append(policy)
        log_event("AttachGroupPolicy", f"group:{group.name} → policy:{policy.name}")
        db.session.commit()
        flash(f"Policy '{policy.name}' attached to group '{group.name}'.", "success")
    else:
        flash("Policy already attached.", "info")
    return redirect(url_for("group_detail", group_id=group_id))


@app.route("/groups/<int:group_id>/detach-policy", methods=["POST"])
def group_detach_policy(group_id):
    group     = Group.query.get_or_404(group_id)
    policy_id = request.form.get("policy_id", type=int)
    policy    = Policy.query.get_or_404(policy_id)
    if policy in group.policies:
        group.policies.remove(policy)
        log_event("DetachGroupPolicy", f"group:{group.name} → policy:{policy.name}")
        db.session.commit()
        flash(f"Policy '{policy.name}' detached.", "warning")
    return redirect(url_for("group_detail", group_id=group_id))


@app.route("/groups/<int:group_id>/add-user", methods=["POST"])
def group_add_user(group_id):
    group   = Group.query.get_or_404(group_id)
    user_id = request.form.get("user_id", type=int)
    user    = User.query.get_or_404(user_id)
    if user not in group.users:
        group.users.append(user)
        log_event("AddUserToGroup", f"user:{user.username} → group:{group.name}")
        db.session.commit()
        flash(f"{user.username} added to group.", "success")
    else:
        flash(f"{user.username} is already in this group.", "info")
    return redirect(url_for("group_detail", group_id=group_id))


@app.route("/groups/<int:group_id>/remove-user", methods=["POST"])
def group_remove_user(group_id):
    group   = Group.query.get_or_404(group_id)
    user_id = request.form.get("user_id", type=int)
    user    = User.query.get_or_404(user_id)
    if user in group.users:
        group.users.remove(user)
        log_event("RemoveUserFromGroup", f"user:{user.username} → group:{group.name}")
        db.session.commit()
        flash(f"{user.username} removed from group.", "warning")
    return redirect(url_for("group_detail", group_id=group_id))


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

@app.route("/roles")
def roles_list():
    roles = Role.query.order_by(Role.name).all()
    return render_template("roles.html", roles=roles)


@app.route("/roles/<int:role_id>")
def role_detail(role_id):
    role         = Role.query.get_or_404(role_id)
    all_policies = Policy.query.order_by(Policy.name).all()
    return render_template("role_detail.html", role=role, all_policies=all_policies)


@app.route("/roles/create", methods=["POST"])
def role_create():
    name         = request.form.get("name", "").strip()
    desc         = request.form.get("description", "").strip()
    trust_policy = request.form.get("trust_policy", "").strip()
    if not name:
        flash("Role name is required.", "danger")
        return redirect(url_for("roles_list"))
    if Role.query.filter_by(name=name).first():
        flash(f"Role '{name}' already exists.", "danger")
        return redirect(url_for("roles_list"))
    try:
        json.loads(trust_policy)
    except (json.JSONDecodeError, ValueError):
        flash("Trust policy must be valid JSON.", "danger")
        return redirect(url_for("roles_list"))
    role = Role(name=name, description=desc, trust_policy=trust_policy)
    db.session.add(role)
    log_event("CreateRole", f"role:{name}")
    db.session.commit()
    flash(f"Role '{name}' created.", "success")
    return redirect(url_for("role_detail", role_id=role.id))


@app.route("/roles/<int:role_id>/delete", methods=["POST"])
def role_delete(role_id):
    role = Role.query.get_or_404(role_id)
    name = role.name
    db.session.delete(role)
    log_event("DeleteRole", f"role:{name}")
    db.session.commit()
    flash(f"Role '{name}' deleted.", "warning")
    return redirect(url_for("roles_list"))


@app.route("/roles/<int:role_id>/attach-policy", methods=["POST"])
def role_attach_policy(role_id):
    role      = Role.query.get_or_404(role_id)
    policy_id = request.form.get("policy_id", type=int)
    policy    = Policy.query.get_or_404(policy_id)
    if policy not in role.policies:
        role.policies.append(policy)
        log_event("AttachRolePolicy", f"role:{role.name} → policy:{policy.name}")
        db.session.commit()
        flash(f"Policy '{policy.name}' attached to role '{role.name}'.", "success")
    else:
        flash("Policy already attached.", "info")
    return redirect(url_for("role_detail", role_id=role_id))


@app.route("/roles/<int:role_id>/detach-policy", methods=["POST"])
def role_detach_policy(role_id):
    role      = Role.query.get_or_404(role_id)
    policy_id = request.form.get("policy_id", type=int)
    policy    = Policy.query.get_or_404(policy_id)
    if policy in role.policies:
        role.policies.remove(policy)
        log_event("DetachRolePolicy", f"role:{role.name} → policy:{policy.name}")
        db.session.commit()
        flash(f"Policy '{policy.name}' detached.", "warning")
    return redirect(url_for("role_detail", role_id=role_id))


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@app.route("/policies")
def policies_list():
    policies = Policy.query.order_by(Policy.name).all()
    return render_template("policies.html", policies=policies)


@app.route("/policies/<int:policy_id>")
def policy_editor(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    health = check_policy_health(policy)
    return render_template("policy_editor.html", policy=policy, health_warnings=health)


@app.route("/policies/create", methods=["POST"])
def policy_create():
    name     = request.form.get("name", "").strip()
    desc     = request.form.get("description", "").strip()
    document = request.form.get("policy_document", "").strip()
    if not name:
        flash("Policy name is required.", "danger")
        return redirect(url_for("policies_list"))
    if Policy.query.filter_by(name=name).first():
        flash(f"Policy '{name}' already exists.", "danger")
        return redirect(url_for("policies_list"))
    try:
        json.loads(document)
    except (json.JSONDecodeError, ValueError):
        flash("Policy document must be valid JSON.", "danger")
        return redirect(url_for("policies_list"))
    policy = Policy(name=name, description=desc, policy_document=document)
    db.session.add(policy)
    log_event("CreatePolicy", f"policy:{name}")
    db.session.commit()
    flash(f"Policy '{name}' created.", "success")
    return redirect(url_for("policy_editor", policy_id=policy.id))


@app.route("/policies/<int:policy_id>/update", methods=["POST"])
def policy_update(policy_id):
    policy   = Policy.query.get_or_404(policy_id)
    document = request.form.get("policy_document", "").strip()
    try:
        json.loads(document)
    except (json.JSONDecodeError, ValueError):
        flash("Policy document must be valid JSON.", "danger")
        return redirect(url_for("policy_editor", policy_id=policy_id))
    policy.policy_document = document
    log_event("UpdatePolicy", f"policy:{policy.name}")
    db.session.commit()
    flash(f"Policy '{policy.name}' updated.", "success")
    return redirect(url_for("policy_editor", policy_id=policy_id))


@app.route("/policies/<int:policy_id>/delete", methods=["POST"])
def policy_delete(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    name   = policy.name
    db.session.delete(policy)
    log_event("DeletePolicy", f"policy:{name}")
    db.session.commit()
    flash(f"Policy '{name}' deleted.", "warning")
    return redirect(url_for("policies_list"))


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------

@app.route("/simulator")
def simulator():
    users = User.query.order_by(User.username).all()
    roles = Role.query.order_by(Role.name).all()
    return render_template("simulator.html", users=users, roles=roles)


@app.route("/simulator/evaluate", methods=["POST"])
def simulator_evaluate():
    data          = request.get_json()
    principal_type = data.get("principal_type", "user")
    principal_id  = data.get("principal_id", type(int)(0) if False else data.get("principal_id"))
    action        = data.get("action", "").strip()
    resource      = data.get("resource", "").strip()

    if not action or not resource:
        return jsonify({"error": "action and resource are required"}), 400

    if principal_type == "user":
        principal = User.query.get(principal_id)
        if not principal:
            return jsonify({"error": "User not found"}), 404
        policies = principal.effective_policies()
        label    = f"user:{principal.username}"
    elif principal_type == "role":
        principal = Role.query.get(principal_id)
        if not principal:
            return jsonify({"error": "Role not found"}), 404
        policies = principal.policies
        label    = f"role:{principal.name}"
    else:
        return jsonify({"error": "principal_type must be 'user' or 'role'"}), 400

    result = evaluate(policies, action, resource)

    # Log the simulation
    log_event(
        action="SimulateAccess",
        target=f"{label} → {action} on {resource}",
        detail={"decision": result.decision, "matching_policy": result.matching_policy},
        result=result.decision,
    )
    db.session.commit()

    steps_out = [
        {
            "policy_name":     s.policy_name,
            "statement_index": s.statement_index,
            "effect":          s.effect,
            "outcome":         s.outcome,
            "reason":          s.reason,
        }
        for s in result.steps
    ]

    return jsonify({
        "decision":        result.decision,
        "reason":          result.reason,
        "matching_policy": result.matching_policy,
        "principal":       label,
        "action":          action,
        "resource":        resource,
        "steps":           steps_out,
    })


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

@app.route("/audit")
def audit_log():
    page    = request.args.get("page", 1, type=int)
    per_page = 25
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template("audit_log.html", logs=logs)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_data.seed(app)
    app.run(debug=True, port=5000)
