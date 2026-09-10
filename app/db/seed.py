"""Idempotent seed script: platform roles/permissions + a demo organization.

Run automatically on container startup (see docker-compose.yml). Safe to
run multiple times -- every insert is guarded by an existence check.
"""
from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.session import AsyncSessionLocal
from app.models.rbac import Permission, Role, RoleName

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
    RoleName.INVESTIGATOR: ["case.view", "case.assign", "evidence.view", "evidence.export"],
    RoleName.SOC_ADMIN: ["case.view", "case.assign", "case.escalate", "evidence.view", "evidence.export", "user.manage"],
    RoleName.ORG_ADMIN: [
        "case.view", "case.assign", "case.escalate", "evidence.view", "evidence.export",
        "user.manage", "org.manage",
    ],
    RoleName.PLATFORM_ADMIN: [p[0] for p in _PERMISSIONS],
}


async def seed() -> None:
    async with AsyncSessionLocal() as db:
        existing_perms = {
            p.code: p
            for p in (await db.execute(select(Permission))).scalars().all()
        }

        for code, description in _PERMISSIONS:
            if code not in existing_perms:
                perm = Permission(code=code, description=description)
                db.add(perm)
                existing_perms[code] = perm

        await db.flush()

        existing_roles = {
            r.name: r
            for r in (
                await db.execute(
                    select(Role).options(selectinload(Role.permissions))
                )
            ).scalars().all()
        }

        for role_name, perm_codes in _ROLE_PERMISSIONS.items():
            role = existing_roles.get(role_name.value)

            if role is None:
                role = Role(
                    name=role_name.value,
                    description=f"Platform role: {role_name.value}",
                )
                db.add(role)
                await db.flush()
                existing_roles[role_name.value] = role

            role.permissions = [existing_perms[c] for c in perm_codes]

        await db.commit()

    print("Seed complete: roles and permissions ensured.")


if __name__ == "__main__":
    asyncio.run(seed())
