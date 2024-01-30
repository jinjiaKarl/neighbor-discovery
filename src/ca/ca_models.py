from typing import Union
from pydantic import BaseModel


class Csr(BaseModel):
    common_name: str

class Issue(BaseModel):
    csr: str
    max_days: Union[int, None] = 365

class Check(BaseModel):
    cert: str