def get_balance(conn, address: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COALESCE(SUM(delta),0) FROM ledger_entries WHERE address=%s",
            (address,)
        )
        return cur.fetchone()[0]

