from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.db import get_conn
from app.crypto import verify_signature_p256, compute_address_from_public_pem

router = APIRouter()

class SendReq(BaseModel):
    from_address: str
    to_address: str
    amount: int = Field(gt=0)
    nonce: int = Field(gt=0)
    signature: str
    public_key: str
    memo: str | None = None

@router.post("/send")
def send_tx(req: SendReq):
    # 0) address must match public key
    expected = compute_address_from_public_pem(req.public_key)
    if req.from_address != expected:
        raise HTTPException(status_code=400, detail="from_address does not match public key")

    # 1) verify signature over EXACT same message as frontend
    msg = f"{req.from_address}:{req.to_address}:{req.amount}:{req.nonce}"
    ok = verify_signature_p256(req.public_key, msg, req.signature)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid signature")

    with get_conn() as conn:
        try:
            with conn.cursor() as cur:
                # 2) lock sender row
                cur.execute(
                    "select balance, last_nonce from wallets where address=%s for update",
                    (req.from_address,),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="Sender wallet not found")

                balance, last_nonce = int(row[0]), int(row[1])

                # 3) nonce anti-replay
                if req.nonce <= last_nonce:
                    raise HTTPException(status_code=400, detail="Nonce too low (replay)")

                # 4) достатній баланс
                if balance < req.amount:
                    raise HTTPException(status_code=400, detail="Insufficient balance")

                # 5) ensure receiver exists (auto-create with balance 0)
                cur.execute("select address from wallets where address=%s", (req.to_address,))
                if not cur.fetchone():
                    # receiver has no public_key yet; store placeholder (can update later)
                    cur.execute(
                        "insert into wallets(address, public_key, balance, last_nonce) values (%s,%s,0,0)",
                        (req.to_address, "UNREGISTERED"),
                    )

                # 6) apply transfer
                cur.execute(
                    "update wallets set balance = balance - %s, last_nonce = %s where address=%s",
                    (req.amount, req.nonce, req.from_address),
                )
                cur.execute(
                    "update wallets set balance = balance + %s where address=%s",
                    (req.amount, req.to_address),
                )

                # 7) write tx
                cur.execute(
                    """
                    insert into transactions(from_address, to_address, amount, nonce, signature)
                    values (%s,%s,%s,%s,%s)
                    returning id
                    """,
                    (req.from_address, req.to_address, req.amount, req.nonce, req.signature),
                )
                tx_id = str(cur.fetchone()[0])

            conn.commit()
            return {"ok": True, "tx_id": tx_id}
        except HTTPException:
            conn.rollback()
            raise
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail=f"Server error: {e}")
