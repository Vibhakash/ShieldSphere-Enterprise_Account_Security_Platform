import asyncio
from app.db.session import AsyncSessionLocal
from app.db.models.user import User
from sqlalchemy import select

async def main():
    async with AsyncSessionLocal() as db:
        r = await db.execute(select(User))
        users = r.scalars().all()
        print(f"Total users: {len(users)}")
        for u in users:
            print(f"  Email: {u.email}, Username: {u.username}, Active: {u.is_active}")

asyncio.run(main())
