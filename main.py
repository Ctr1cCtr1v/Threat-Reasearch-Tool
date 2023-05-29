"""
Create venv then pip install -r requirements.txt for packages/dependencies needed ie transformers, openai and pyattck.
Insert openai api key before running main program. 
Run the MITRE_update.py file to generate/update dataset with current MITRE ATTCK framework.
"""
import re, json, openai
from transformers import GPT2Tokenizer

openai.api_key = "InsertAPIKey"

file_path = "test.txt"


def load_reference_data(file_path):
    with open(file_path, "r") as file:
        reference_data = json.load(file)
    return reference_data


# SET THE reference_data_file VARIABLE
technique_reference_data_file = "technique_data.json"
technique_data = load_reference_data(technique_reference_data_file)

actor_reference_data_file = "actor_data.json"
actor_data = load_reference_data(actor_reference_data_file)


def chatgpt_summary():
    # Improve and tweak summary via editing number of tokens value in max_length= and max_tokens= in addition to message = ""
    # Note do not exceed combined 4097 tokens for the max lenth and max token value
    messages = []

    message = "Describe the tactics, techniques, and procedures used and summarize the MITRE attack patterns found in the following text in one paragraph."
    if message:
        messages.append({"role": "user", "content": message})

    # Read the contents of the .txt file
    with open(file_path, "r", encoding="utf-8") as file:
        file_content = file.read()

    # Clean the file content
    file_content = re.sub(
        r"\W+", " ", file_content
    )  # Remove non-alphanumeric characters
    file_content = re.sub(r"\s+", " ", file_content)  # Remove extra whitespace

    # Tokenize and truncate the file content
    tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
    tokens = tokenizer.encode(file_content, truncation=True, max_length=3800)
    tokens = tokens[:3700]
    truncated_content = tokenizer.decode(tokens)

    # Append the truncated file content as a user message
    messages.append({"role": "user", "content": truncated_content.strip()})

    # Create the chat completion using messages
    chat = openai.ChatCompletion.create(
        model="gpt-3.5-turbo", messages=messages, max_tokens=397
    )

    summary = chat.choices[0].message.content

    return summary


def extract_mitre_groups(file_path, actor_data):
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    # Regular expression pattern for matching MITRE ATT&CK Groups
    pattern = r"(G\d{4})|([A-Za-z\s]+)"

    # Extract MITRE ATT&CK Groups
    matches = re.findall(pattern, content)

    # Validate groups against reference data
    validated_groups = []
    for match in matches:
        group_id = match[0]
        group_name = match[1].strip()

        # Check if group matches either the id or the name in reference data
        matched_entries = [
            entry
            for entry in actor_data
            if (entry["id"] and group_id and entry["id"] == group_id)
            or (entry["name"].lower() == group_name.lower())
            or (
                group_name.lower()
                in [alias.lower() for alias in entry.get("aliases", [])]
            )
            or (group_name.lower() in entry["name"].lower())
        ]

        if matched_entries:
            validated_groups.extend(matched_entries)

    validated_groups = [dict(g) for g in {tuple(d.items()) for d in validated_groups}]

    return validated_groups


def extract_mitre_techniques(file_path, validated_groups, summary):
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    # Regular expression patterns for matching MITRE ATT&CK IDs and names
    id_pattern = r"(T\d{4}(?:\.\d{1,3}(?:\.\d{1,3})?)?)"
    name_pattern = r"([A-Z][\w\s.-]+(?:\s*-\s*[\w\s.-]+)*)"

    # Extract technique IDs and names separately
    technique_ids = re.findall(id_pattern, content)
    technique_names = re.findall(name_pattern, content)

    # Combine technique IDs and names into mentioned techniques
    mentioned_techniques = []
    for technique_id in technique_ids:
        mentioned_techniques.append({"id": technique_id, "name": ""})
    for technique_name in technique_names:
        mentioned_techniques.append({"id": "", "name": technique_name.strip()})

    # Validate techniques against reference data
    validated_techniques = []
    for technique in mentioned_techniques:
        matched_entries = [
            entry
            for entry in technique_data
            if (technique["id"] and entry["id"] and technique["id"] == entry["id"])
            or (
                technique["name"]
                and entry["name"]
                and technique["name"].lower() == entry["name"].lower()
            )
            or (
                technique["name"]
                and "aliases" in entry
                and technique["name"].lower()
                in [alias.lower() for alias in entry["aliases"]]
            )
            or (
                technique["name"]
                and entry["name"]
                and technique["name"].lower() in entry["name"].lower()
            )
            or (
                technique["name"]
                and entry["name"]
                and entry["name"].lower() in technique["name"].lower()
            )
        ]

        if matched_entries:
            validated_techniques.extend(matched_entries)

    # Remove duplicates from validated techniques
    validated_techniques = [
        dict(t) for t in {tuple(d.items()) for d in validated_techniques}
    ]

    mentioned_techniques = []
    for technique in validated_techniques:
        if technique["id"] in content or technique["name"] in content:
            mentioned_techniques.append(technique)

    mentioned_groups = []
    for group in validated_groups:
        if group["id"] in content or group["name"] in content:
            mentioned_groups.append(group)

    # Prepare the JSON data
    data = {
        "summary": summary,
        "ttps": sorted(mentioned_techniques, key=lambda x: x["id"]),
        "groups": sorted(mentioned_groups, key=lambda x: x["id"]),
    }

    # Output JSON to a file
    output_file_path = "output.json"
    with open(output_file_path, "w") as output_file:
        json.dump(data, output_file, indent=4)


summary = chatgpt_summary()
validated_groups = extract_mitre_groups(file_path, actor_data)
extract_mitre_techniques(file_path, validated_groups, summary)
