"""Auth-related Pydantic request schemas."""
from pydantic import BaseModel


class UserRegister(BaseModel):
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class ClaimAgentRequest(BaseModel):
    hostname: str
    one_time_token: str
