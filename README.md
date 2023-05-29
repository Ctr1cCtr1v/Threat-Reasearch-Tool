# Threat Research Program
## **Goal**
The goal is to create a program that extracts from published research; Tactics, Techniques, and Procedures (TTPs) that Advanced Persistent Threats (APTs) use to attack their victims. Understanding the Tactics, Techniques, and Procedures used by APTs is crucial for effective cybersecurity. Knowledge of APT TTPs aids in incident response, risk assessment, and mitigation, enabling organizations to strengthen their defenses and patch vulnerabilities. Understanding APT TTPs enhances the ability for professionals to detect, prevent, and respond to APT attacks, safeguarding assets and sensitive information. Sharing this information fosters collaboration among cybersecurity professionals and helps predict future attack trends.

## **Thought Process**
Take an arbitrary text file (ideally from a reputable cybersecurity news source) and scan the data for information referencing ATPs and TTPs. Correlate this information along with a summary of the text and output it into a useable format for data analysis and trend research. 

## **main.py**
This program finds the TTPs, APTs, generates a summary and outputs useful information in a JSON file.
### *-SETUP-*
Update the filepath and encoding to match your storage location and system.
Insert openai api key before running main program. 
Run the MITRE_update.py file to generate/update dataset with current MITRE ATTCK framework.
Pip install any packages/dependencies needed ie transformers, re, openai etc.

## **MITRE_update.py**
This program gathers the latest MITRE ATT&CK data on TTP's and ATP's then codifies it to be used as a local dataset for the main.py program.
### *-SETUP-*
Pip install any packages/dependencies needed ie pyattck.

## **Future Goals**
Enable the program to auto scrape websites and blogposts to gather intel from.
Use GPT-4 when available or other llm for more robust and comprehensive summary generation as well as TTP analysis.
