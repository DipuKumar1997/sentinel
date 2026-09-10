
"""Idempotent seed script: platform roles/permissions + a demo organization.

Run automatically on container startup (see docker-compose.yml). Safe to
run multiple times -- every insert is guarded by an existence check.
"""
from __future__ import annotations

import asyncio

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.rbac import Permission, Role, RoleName, role_permissions

_PERMISSIONS = [
    ("case.view", "View cases within own organization"),
    ("case.assign", "Assign a case to an analyst"),
    ("case.escalate", "Escalate a case's priority/status"),
    ("evidence.view", "View evidence objects"),
    ("evidence.export", "Export evidence/reports"),
    ("user.manage", "Manage users within own organization"),
    ("org.manage", "Manage organization settings"),
    ("platform.manage", "Manage cross-organization platform settings"),
]

_ROLE_PERMISSIONS = {
    RoleName.EMPLOYEE: ["case.view"],
    RoleName.SECURITY_ANALYST: ["case.view", "evidence.view"],
    RoleName.INVESTIGATOR: [
        "case.view",
        "case.assign",
        "evidence.view",
        "evidence.export",
    ],
    RoleName.SOC_ADMIN: [
        "case.view",
        "case.assign",
        "case.escalate",
        "evidence.view",
        "evidence.export",
        "user.manage",
    ],
    RoleName.ORG_ADMIN: [
        "case.view",
        "case.assign",
        "case.escalate",
        "evidence.view",
        "evidence.export",
        "user.manage",
        "org.manage",
    ],
    RoleName.PLATFORM_ADMIN: [p[0] for p in _PERMISSIONS],
}


async def seed() -> None:
    async with AsyncSessionLocal() as db:
        existing_perms = {
            p.code: p
            for p in (
                await db.execute(select(Permission))
            ).scalars().all()
        }

        for code, description in _PERMISSIONS:
            if code not in existing_perms:
                perm = Permission(
                    code=code,
                    description=description,
                )
                db.add(perm)
                existing_perms[code] = perm

        await db.flush()

        existing_roles = {
            r.name: r
            for r in (
                await db.execute(select(Role))
            ).scalars().all()
        }

        for role_name in _ROLE_PERMISSIONS:
            role = existing_roles.get(role_name.value)

            if role is None:
                role = Role(
                    name=role_name.value,
                    description=f"Platform role: {role_name.value}",
                )
                db.add(role)
                await db.flush()
                existing_roles[role_name.value] = role

        existing_mappings = {
            (role_id, permission_id)
            for role_id, permission_id in (
                await db.execute(
                    select(
                        role_permissions.c.role_id,
                        role_permissions.c.permission_id,
                    )
                )
            ).all()
        }

        for role_name, perm_codes in _ROLE_PERMISSIONS.items():
            role = existing_roles[role_name.value]

            for code in perm_codes:
                permission = existing_perms[code]
                mapping = (role.id, permission.id)

                if mapping not in existing_mappings:
                    await db.execute(
                        role_permissions.insert().values(
                            role_id=role.id,
                            permission_id=permission.id,
                        )
                    )
                    existing_mappings.add(mapping)

        await db.commit()

    print("Seed complete: roles and permissions ensured.")


if __name__ == "__main__":
    asyncio.run(seed())
