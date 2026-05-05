from openai import OpenAI
import pandas as pd
import os
import json

client = OpenAI()
# takes the top 5 from each chunk then gets the over all top 5
input_file = r"C:\Users\tcsim\PycharmProjects\Capstone-LLM-Project-\TOP5\GPT_STOP.csv"

output_folder = r"C:\Users\tcsim\PycharmProjects\Capstone-LLM-Project-\TOP5\Processed_Top5"


output_path = os.path.join(output_folder, "GPT_STOP.csv")

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

response = client.chat.completions.create(
    model="gpt-4-turbo",
    temperature=0,
    messages=[
        {"role": "system", "content": "You analyze Windows event logs for suspicious activity."},
        {"role": "user", "content": prompt}
    ]
)

output_text = response.choices[0].message.content
# alert if there any errors
try:
    chunk_json = json.loads(output_text)
except Exception as e:
    print(f"JSON error in : {e}")
    print(output_text)




top5_df = pd.DataFrame(chunk_json["top_5_suspicious"])

top5_df.to_csv(output_path, index=False)

print(f"Saved top 5 to: {output_path}")