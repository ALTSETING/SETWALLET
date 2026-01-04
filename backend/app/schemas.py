from pydantic import BaseModel, Field

class RegisterWallet(BaseModel):
    address: str
    public_key: str

class SendTx(BaseModel):
    from_address: str
    to_address: str
    amount: int = Field(gt=0)
    nonce: int
    memo: str | None = None
    signature: str
    public_key: str
