import uuid
from typing import Optional
from pydantic import BaseModel, Field

# TODO : How to make fields empty ? 
class Machine(BaseModel):
    id: str = Field(default_factory=uuid.uuid4, alias="_id") # need alias bc _ makes private in pydantic
    ip: str = Field(...) 
    ipv6: str = Field(...) 
    os: str = Field(...) 
    mac: str = Field(...) 
    macvendor: str = Field(...) 
    openports: list = Field(...)

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "_id": "066de609-b04a-4b30-b46c-32537c7f1f6e",
                "ipv6":"toto",
                "os":"tata",
                "ip": "Don Quixote",
                "mac": "Miguel de Cervantes",
                "macvendor": "...",
                "openports": [1, 2]
            }
        }

# class MachineUpdate(BaseModel):
#     ip: Optional[str]
#     ipv6 : Optional[str]
#     os : Optional[str]
#     mac: Optional[str]
#     macvendor: Optional[str]
    
#     class Config:
#         json_schema_extra = {
#             "example": {
#                 "_id": "066de609-b04a-4b30-b46c-32537c7f1f6e",
#                 "ipv6":"toto",
#                 "os":"tata",
#                 "ip": "Don Quixote",
#                 "mac": "Miguel de Cervantes",
#                 "macvendor": "..."
#             }
#         }