"""
Create venv then pip install -r requirements.txt for packages/dependencies needed ie transformers, openai and pyattck.
"""
import json
from pyattck import Attck

attack = Attck()

actor_data = []
technique_data = []

# Iterate over actors and collect the data
for actor in attack.enterprise.actors:
    actor_entry = {"id": actor.external_references[0].external_id, "name": actor.name}
    actor_data.append(actor_entry)

# Iterate over techniques and collect the data
for technique in attack.enterprise.techniques:
    tid = next(
        (ref.external_id for ref in technique.external_references if ref.external_id),
        None,
    )
    technique_entry = {"id": tid, "name": technique.name}
    technique_data.append(technique_entry)

# Save actor data to a separate file
actor_file_path = "actor_data.json"
with open(actor_file_path, "w") as actor_file:
    json.dump(actor_data, actor_file, indent=4)

# Save technique data to a separate file
technique_file_path = "technique_data.json"
with open(technique_file_path, "w") as technique_file:
    json.dump(technique_data, technique_file, indent=4)
