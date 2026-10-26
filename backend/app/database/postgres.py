import psycopg

from app.config.settings import POSTGRES_URL


def check_postgres() -> dict:
    if not POSTGRES_URL:
        return {
            "connected": False,
            "reason": "POSTGRES_URL is not configured"
        }

    try:
        with psycopg.connect(
            POSTGRES_URL,
            connect_timeout=2
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()

        return {"connected": True}

    except Exception as error:
        return {
            "connected": False,
            "reason": str(error)
        }