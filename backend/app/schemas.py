from pydantic import BaseModel

class RegisterWallet(BaseModel):
    address: str
    public_key: str
    vault_encrypted: str | None = None

class SendTx(BaseModel):
    from_address: str
    to_address: str
    amount: int
    memo: str | None = None
    signature: str
    nonce: int
    public_key: str

