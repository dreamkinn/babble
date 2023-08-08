import uuid
from pymongo import MongoClient

class DatabaseHandler:
    def __init__(self, config, args, TOTAL, output, debug=False):
        self.config = config
        self.args = args
        self.out = output
        self.TOTAL = TOTAL
        self.debug = debug
        self.db = MongoClient(config["ATLAS_URI"])[config["DB_NAME"]]["db"] 
        
    def getall(self):
        all_machines = list(self.db.find(limit=100))

    def put_machine(self, machine):
        # machine = {k: v for k, v in machine.dict().items() if v is not None}
        # if len(machine) >= 1:
        machine["_id"] = self.get_existing(machine)

        update_result = self.db.update_one(
            # {"_id": machine["_id"], "mac": machine["mac"], "ip": machine["ip"],"ipv6": machine["ipv6"]}, # TODO : this is causing issues
            {"_id": machine["_id"]}, # TODO : this is causing issues
            {"$set": machine},
            upsert=True
        )

        if (
            existing_machine := self.db.find_one({"_id": machine["_id"]})
        ) is not None:
            return existing_machine
    
    def get_existing(self,machine):
        # "best" identifier
        print(machine["ip"])
        machines = list(self.db.find({"ip":machine["ip"]}))
        print(machines)
        if len(machines) == 1:
            return machines[0]["_id"]
        if len(machines) > 1:
            print(f"ERROR : UP address {machine['ip']} appears several times")
            return str(uuid.uuid4())

        machines = list(self.db.find({"ipv6":machine["ipv6"]}))
        if len(machines) == 1:
            return machines[0]["_id"]
        if len(machines) > 1:
            print(f"ERROR : UP address {machine['ipv6']} appears several times")
            return str(uuid.uuid4())
        
        # TODO : change this (will cause issues)
        machines = list(self.db.find({"mac":machine["mac"]}))
        if len(machines) == 1:
            return machines[0]["_id"]
        if len(machines) > 1:
            print(f"ERROR : MAC address {machine['mac']} appears several times")
            return str(uuid.uuid4())

        return str(uuid.uuid4())

        