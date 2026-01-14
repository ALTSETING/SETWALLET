from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.db import get_conn
from app.crypto import verify_signature
from app.ledger import get_balance
import hashlib

router = APIRouter(prefix="/tx", tags=["transactions"])

class Tx(BaseModel):
    from_address: str
    to_address: str
    amount: int = Field(gt=0)
    nonce: int
    signature: str
    public_key: str
    memo: str | None = None

@router.post("/send")
def send_tx(tx: Tx):
    msg = f"{tx.from_address}:{tx.to_address}:{tx.amount}:{tx.nonce}".encode()

    if not verify_signature(tx.public_key, msg, tx.signature):
        raise HTTPException(400, "Bad signature")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # перевірка гаманця
            cur.execute(
                "SELECT public_key FROM wallets WHERE address=%s",
                (tx.from_address,)
            )
            row = cur.fetchone()
            if not row:
                cur.execute(
                    "INSERT INTO wallets(address, public_key) VALUES (%s, %s)",
                    (tx.from_address, tx.public_key),
                )
                row_public_key = tx.public_key
            else:
                row_public_key = row[0]

            if row_public_key.strip() != tx.public_key.strip():
                raise HTTPException(400, "Public key mismatch")

            # баланс
            if get_balance(tx.from_address) < tx.amount:
                raise HTTPException(400, "Insufficient balance")

            # nonce
            cur.execute(
                "SELECT COALESCE(MAX(nonce),0) FROM ledger WHERE from_address=%s",
                (tx.from_address,)
            )
            if tx.nonce <= cur.fetchone()[0]:
                raise HTTPException(400, "Bad nonce")

            tx_id = hashlib.sha256(msg + tx.signature.encode()).hexdigest()[:24]

            cur.execute("""
                INSERT INTO ledger(tx_id, from_address, to_address, amount, nonce, memo)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (
                tx_id, tx.from_address, tx.to_address,
                tx.amount, tx.nonce, tx.memo
            ))
        conn.commit()

    return {"ok": True, "tx_id": tx_id}
