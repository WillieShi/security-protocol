import json
from pprint import pprint

with open("data.json") as f:
    data = json.load(f)

pprint(data["bank"]["user_info"][0].get("hashed_pin"))
