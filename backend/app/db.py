import psycopg
from app.config import DATABASE_URL

class DatabaseConnectionError(RuntimeError):
    pass

def get_conn():
    try:
        return psycopg.connect(DATABASE_URL, autocommit=False)
    except psycopg.OperationalError as exc:
        raise DatabaseConnectionError("Database connection failed") from exc
