"""
Background worker: APScheduler jobs for auto-blocking and security score updates.
"""
import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


def _block_key(block) -> str:
    if block.user_id is None:
        return f"blocked_ip:{block.ip_address}"
    return f"blocked_ip:{block.user_id}:{block.ip_address}"


async def _synchronize_active_blocks():
    """Restore active database blocks to Redis after a service restart."""
    from app.db.session import AsyncSessionLocal
    from app.db.models.security import IpBlocklist
    from sqlalchemy import select, or_
    import redis.asyncio as aioredis
    from app.core.config import settings

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IpBlocklist).where(
                IpBlocklist.is_active == True,  # noqa
                or_(IpBlocklist.expires_at.is_(None), IpBlocklist.expires_at > now),
            )
        )
        blocks = result.scalars().all()

    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        for block in blocks:
            if block.expires_at is None:
                await redis_client.set(_block_key(block), "1")
            else:
                ttl = max(1, int((block.expires_at - now).total_seconds()))
                await redis_client.set(_block_key(block), "1", ex=ttl)
        logger.info("Synchronized %s active IP blocks to Redis", len(blocks))
    except Exception as exc:
        logger.error("Unable to synchronize active IP blocks to Redis: %s", exc)
    finally:
        await redis_client.aclose()


async def _rebuild_all_baselines():
    """Nightly: rebuild behavior baselines for all active users."""
    from app.db.session import AsyncSessionLocal
    from app.db.models.user import User
    from app.services.uba_engine import rebuild_user_baseline
    from sqlalchemy import select

    logger.info("Starting nightly UBA baseline rebuild")
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.is_active == True))  # noqa
        users = result.scalars().all()
        for user in users:
            try:
                await rebuild_user_baseline(db, user.id)
            except Exception as e:
                logger.error(f"Baseline rebuild failed for user {user.id}: {e}")
    logger.info(f"Baseline rebuild complete for {len(users)} users")


async def _cleanup_expired_blocks():
    """Hourly: remove expired IP blocks."""
    from app.db.session import AsyncSessionLocal
    from app.db.models.security import IpBlocklist
    from sqlalchemy import select
    import redis.asyncio as aioredis
    from app.core.config import settings

    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(IpBlocklist).where(
                IpBlocklist.is_active == True,  # noqa
                IpBlocklist.expires_at.isnot(None),
                IpBlocklist.expires_at <= now,
            )
        )
        expired = result.scalars().all()
        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            for block in expired:
                block.is_active = False
                await redis_client.delete(_block_key(block))
            if expired:
                await db.commit()
                logger.info(f"Removed {len(expired)} expired IP blocks")
        finally:
            await redis_client.aclose()


async def _cleanup_stale_sessions():
    """Daily: deactivate sessions past their expiry."""
    from app.db.session import AsyncSessionLocal
    from app.db.models.session import UserSession
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(UserSession).where(
                UserSession.is_active == True,  # noqa
                UserSession.expires_at.isnot(None),
                UserSession.expires_at <= now,
            )
        )
        stale = result.scalars().all()
        for s in stale:
            s.is_active = False
            s.revoked_at = now
        if stale:
            await db.commit()
            logger.info(f"Deactivated {len(stale)} stale sessions")


async def _recover_interrupted_simulations():
    """Mark simulations interrupted by a backend restart with their real state."""
    from app.db.session import AsyncSessionLocal
    from app.db.models.simulation import AttackSimulation
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AttackSimulation).where(AttackSimulation.status == "running")
        )
        interrupted = result.scalars().all()
        if not interrupted:
            return
        now = datetime.now(timezone.utc)
        for simulation in interrupted:
            simulation.status = "failed"
            simulation.error_message = "Backend restarted before this simulation completed"
            simulation.ended_at = now
        await db.commit()
        logger.warning("Marked %s interrupted simulations as failed", len(interrupted))


async def _run_next_queued_simulation():
    """Claim one persisted simulation and run it outside the request lifecycle."""
    from app.db.session import AsyncSessionLocal
    from app.db.models.simulation import AttackSimulation
    from app.services.sandbox_manager import run_simulation
    from sqlalchemy import select
    import redis.asyncio as aioredis
    from app.core.config import settings

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AttackSimulation)
            .where(AttackSimulation.status == "queued")
            .order_by(AttackSimulation.created_at.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        simulation = result.scalar_one_or_none()
        if not simulation:
            return

        simulation.status = "running"
        simulation.started_at = datetime.now(timezone.utc)
        await db.commit()

        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            await run_simulation(db=db, simulation=simulation, redis_client=redis_client)
        finally:
            await redis_client.aclose()


async def run_queued_simulation(simulation_id):
    """Immediately claim and run one queued simulation, if it has not been claimed.

    The scheduler remains a recovery path for queued work after a restart, while
    this function starts a newly requested sandbox run without waiting for the
    next polling interval. ``FOR UPDATE SKIP LOCKED`` makes the two paths safe
    to run concurrently.
    """
    from app.db.session import AsyncSessionLocal
    from app.db.models.simulation import AttackSimulation
    from app.services.sandbox_manager import run_simulation
    from sqlalchemy import select
    import redis.asyncio as aioredis
    from app.core.config import settings

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AttackSimulation)
            .where(
                AttackSimulation.id == simulation_id,
                AttackSimulation.status == "queued",
            )
            .with_for_update(skip_locked=True)
        )
        simulation = result.scalar_one_or_none()
        if not simulation:
            return

        simulation.status = "running"
        simulation.started_at = datetime.now(timezone.utc)
        await db.commit()

        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            await run_simulation(db=db, simulation=simulation, redis_client=redis_client)
        finally:
            await redis_client.aclose()


def init_scheduler():
    """Initialize and start all background jobs."""
    scheduler.add_job(_rebuild_all_baselines, "cron", hour=2, minute=0, id="rebuild_baselines")
    scheduler.add_job(_cleanup_expired_blocks, "interval", hours=1, id="cleanup_blocks")
    scheduler.add_job(_cleanup_stale_sessions, "cron", hour=3, minute=0, id="cleanup_sessions")
    scheduler.add_job(
        _recover_interrupted_simulations,
        "date",
        id="recover_interrupted_simulations",
        replace_existing=True,
    )
    scheduler.add_job(
        _synchronize_active_blocks,
        "date",
        id="synchronize_active_blocks",
        replace_existing=True,
    )
    scheduler.add_job(
        _synchronize_active_blocks,
        "interval",
        minutes=1,
        id="synchronize_active_blocks_repeating",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.add_job(
        _run_next_queued_simulation,
        "interval",
        seconds=2,
        id="run_queued_simulations",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    logger.info("APScheduler started with background jobs")


def shutdown_scheduler():
    scheduler.shutdown(wait=False)
