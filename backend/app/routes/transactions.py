from fastapi import APIRouter, HTTPException
from app.db import get_conn
from app.schemas import SendTx
from app.crypto import verify_signature
from app.ledger import get_balance

router = APIRouter(prefix="/tx")

@router.post("/send")
def send_tx(tx: SendTx):
    message = f"{tx.from_address}:{tx.to_address}:{tx.amount}:{tx.nonce}".encode()

    if not verify_signature(tx.public_key, message, tx.signature):
        raise HTTPException(400, "Invalid signature")

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # nonce check
            cur.execute(
                "SELECT last_nonce FROM wallet_nonces WHERE address=%s FOR UPDATE",
                (tx.from_address,)
            )
            row = cur.fetchone()
            last_nonce = row[0] if row else 0

            if tx.nonce <= last_nonce:
                raise HTTPException(400, "Invalid nonce")

            balance = get_balance(conn, tx.from_address)
            if balance < tx.amount:
                raise HTTPException(400, "Insufficient balance")

            # tx
            cur.execute(
                """
                INSERT INTO transactions (from_address, to_address, amount, memo, signature, nonce)
                VALUES (%s,%s,%s,%s,%s,%s)
                RETURNING id
                """,
                (tx.from_address, tx.to_address, tx.amount, tx.memo, tx.signature, tx.nonce)
            )
            tx_id = cur.fetchone()[0]

            # ledger
            cur.execute(
                "INSERT INTO ledger_entries (tx_id,address,delta) VALUES (%s,%s,%s)",
                (tx_id, tx.from_address, -tx.amount)
            )
            cur.execute(
                "INSERT INTO ledger_entries (tx_id,address,delta) VALUES (%s,%s,%s)",
                (tx_id, tx.to_address, tx.amount)
            )

            # nonce update
            cur.execute(
                """
                INSERT INTO wallet_nonces (address,last_nonce)
                VALUES (%s,%s)
                ON CONFLICT (address)
                DO UPDATE SET last_nonce=EXCLUDED.last_nonce
                """,
                (tx.from_address, tx.nonce)
            )

        conn.commit()
        return {"status": "confirmed", "tx_id": str(tx_id)}
    finally:
        conn.close()

