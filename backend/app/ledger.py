from app.db import get_conn

def get_balance(address: str) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  coalesce(sum(case when to_address=%s then amount else 0 end), 0)
                  -
                  coalesce(sum(case when from_address=%s then amount else 0 end), 0)
                as balance
                from public.ledger
                """,
                (address, address),
            )
            row = cur.fetchone()
            return int(row[0] or 0)
