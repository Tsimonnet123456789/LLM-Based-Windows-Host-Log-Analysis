import anthropic
import pandas as pd
import os
import glob
import json
input_file = r"C:\Users\tcsim\PycharmProjects\Capstone-LLM-Project-\TOP5\Claude_STOP.csv"

output_folder = r"C:\Users\tcsim\PycharmProjects\Capstone-LLM-Project-\TOP5\Processed_Top5"


output_path = os.path.join(output_folder, "Claude_STOP.csv")
# takes the top 5 from each chunk and picks the overall top 5
print("Processing")
df = pd.read_csv(input_file)

chunk_logs_str = "\n".join(
    " | ".join(f"{col}={row[col]}" for col in df.columns)
    for _, row in df.iterrows()
)

prompt = f"""
Find the top 5 most suspicious logs from the logs below.
Do not change any information only pick the top 5.
Do NOT pick multiple logs that are the same activity
Return ONLY valid JSON 
No markdown 
No extra text

OUTPUT FORMAT:
{{
  "top_5_suspicious": [
    {{
      "RowID": 0,
      "Suspicion_Score": 0,
      "summary": ""
    }}
  ]
}}

LOGS:
{chunk_logs_str}
"""

response = client.messages.create(
    model="claude-haiku-4-5",
    max_tokens=10000,
    temperature=0,
    system="You are a Wazuh System information event manager.",
    messages=[
        {"role": "user", "content": prompt}
    ]
)

output_text = response.content[0].text
# makes sure there are no errors
try:
    cleaned = output_text.strip()

    # remove markdown if present
    if cleaned.startswith("```"):
        cleaned = cleaned.replace("```json", "").replace("```", "").strip()

    chunk_json = json.loads(cleaned)

except Exception as e:
        print(f"JSON error in : {e}")
        print(output_text)


# writes the data to a CSV file
top5_df = pd.DataFrame(chunk_json["top_5_suspicious"])

top5_df.to_csv(output_path, index=False)

print(f"Saved top 5 to: {output_path}")