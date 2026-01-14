from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from app.config import ADMIN_TOKEN
from app.db import get_conn, DatabaseConnectionError
import hashlib
import time

router = APIRouter(prefix="/admin", tags=["admin"])


class MintRequest(BaseModel):
    address: str
    amount: int = Field(gt=0)
    memo: str | None = None


@router.post("/mint")
def mint_tokens(body: MintRequest, x_admin_token: str | None = Header(default=None)):
    if not ADMIN_TOKEN:
        raise HTTPException(500, "ADMIN_TOKEN is not set")

    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(401, "Unauthorized")

    from_address = "GENESIS"

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COALESCE(MAX(nonce),0) FROM ledger WHERE from_address=%s",
                    (from_address,),
                )
                next_nonce = int(cur.fetchone()[0] or 0) + 1

                msg = f"{from_address}:{body.address}:{body.amount}:{next_nonce}:{time.time()}".encode()
                tx_id = hashlib.sha256(msg).hexdigest()[:24]

                cur.execute(
                    """
                    INSERT INTO ledger(tx_id, from_address, to_address, amount, nonce, memo)
                    VALUES (%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        tx_id,
                        from_address,
                        body.address,
                        body.amount,
                        next_nonce,
                        body.memo,
                    ),
                )
            conn.commit()

        return {"ok": True, "tx_id": tx_id}
    except DatabaseConnectionError:
        raise HTTPException(503, "Database unavailable. Check DATABASE_URL credentials.")
