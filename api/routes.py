from fastapi import APIRouter, Body, Request, Response, HTTPException, status
from fastapi.encoders import jsonable_encoder
from typing import List
import re
import requests

from models import Machine

router = APIRouter()    

@router.post("/", response_description="Create a machine", response_model=Machine)
def create_machine(request: Request, machine: Machine = Body(...)):
    machine = {k: v for k, v in machine.dict().items() if v is not None}
    machine["_id"] = machine["id"]
    del machine["id"]
    id = str(machine["_id"])
    if len(machine) >= 1:
        update_result = request.app.database["db"].update_one(
            {"_id": id, "mac": machine["mac"], "ip": machine["ip"],"ipv6": machine["ipv6"]},
            {"$set": machine},
            upsert=True
        )

    if (
        existing_machine := request.app.database["db"].find_one({"_id": id})
    ) is not None:
        return existing_machine

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Machine with ID {id} not found")

# Warning : response model validates that the output is correct 
@router.get("/", response_description="List all machines", response_model=List[Machine])
def list_machines(request: Request):
    machines = list(request.app.database["db"].find(limit=100))
    return machines

@router.get("/{id}", response_description="Get a single machine by id", response_model=Machine)
def find_machine(id: str, request: Request):
    if (machine := request.app.database["db"].find_one({"_id": id})) is not None:
        return machine
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Machine with ID {id} not found")

@router.get("/mac/{mac}", response_description="Get machines matching MAC", response_model=List[Machine])
def find_machine(mac:str, request: Request):
    machines = list(request.app.database["db"].find({"mac":mac}))
    return machines

@router.get("/os/{os}", response_description="Get machines matching OS", response_model=List[Machine])
def find_machine(os:str, request: Request):
    machines = list(request.app.database["db"].find({"os":os}))
    return machines

@router.get("/ip/{ip}", response_description="Get machines matching exactly IP", response_model=List[Machine])
def find_machine(ip:str, request: Request):
    machines = list(request.app.database["db"].find({"ip":ip}))
    return machines

@router.get("/ip/rex/{rex}", response_description="Get machines matching IP with regex", response_model=List[Machine])
def find_machine(rex:str, request: Request):
    regex = re.compile(rex, re.IGNORECASE)
    machines = list(request.app.database["db"].find({"ip":regex}))
    return machines

@router.get("/ipv6/{ipv6}", response_description="Get machines matching exactly IPv6", response_model=List[Machine])
def find_machine(ipv6:str, request: Request):
    machines = list(request.app.database["db"].find({"ipv6":ipv6}))
    return machines

@router.get("/ipv6/rex/{rex}", response_description="Get machines matching IP with regex", response_model=List[Machine])
def find_machine(rex:str, request: Request):
    regex = re.compile(rex, re.IGNORECASE)
    machines = list(request.app.database["db"].find({"ipv6":regex}))
    return machines

@router.get("/maccvendor/{maccvendor}", response_description="Get machines matching MAC Vendor", response_model=List[Machine])
def find_machine(maccvendor:str, request: Request):
    machines = list(request.app.database["db"].find({"maccvendor":maccvendor}))
    return machines

@router.delete("/{id}", response_description="Delete a machine")
def delete_machine(id: str, request: Request, response: Response):
    delete_result = request.app.database["db"].delete_one({"_id": id})

    if delete_result.deleted_count == 1:
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Machine with ID {id} not found")
