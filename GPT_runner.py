from openai import OpenAI
import pandas as pd
import os
import glob
import json

client = OpenAI()
# takes the chunks and returns the output
# once a chunk is done it will be writen this is done incase the program crashes
chunk_folder = r"C:\Users\tcsim\PycharmProjects\Capstone-LLM-Project-\Small_suspious_logs\Suspicious_chunks"

chunk_files = glob.glob(os.path.join(chunk_folder, "*.csv"))

chunk_files = sorted(
    chunk_files,
    key=lambda x: int(os.path.basename(x).replace("chunk", "").replace(".csv", ""))
)

output_folder = "processed_chunks"
os.makedirs(output_folder, exist_ok=True)

for file in chunk_files:

    chunk_name = os.path.splitext(os.path.basename(file))[0]
    output_path = os.path.join(output_folder, f"{chunk_name}_processed.csv")


    if os.path.exists(output_path):
        print(f"Skipping: {chunk_name}")
        continue

    print(f"Processing: {chunk_name}")

    df = pd.read_csv(file)

    chunk_logs_str = "\n".join(
        " | ".join(f"{col}={row[col]}" for col in df.columns)
        for _, row in df.iterrows()
    )

    prompt = f"""
You are a Wazuh System information event manager.
Analyze EACH input log and return exactly one result for each RowID.

key tasks
Assign a Suspicion_Score from 0 to 15
Write a Human readable summary for why the log was suspicious.
Find the top 5 most susipious logs
important rules
The first 10 rows are context from the previous chunk
You MUST return exactly one result for each input RowID
Do NOT skip any RowID
Do NOT guess, assume, or infer missing details
Keep each summary short, maximum 8 words
Provide a reason for the Suspicion_Score based only on the log data. 
IMPORTANT
0–2: Normal system activity 
3–5: Low risk 
6–8: medium risk 
9–11:  High risk Suspicious activity
12–15: Critical risk likely malicious activity

Return ONLY valid JSON
 No markdown
 No extra text

OUTPUT FORMAT:
{{
  "chunk_all_logs": [
    {{
      "RowID": 0,
      "Suspicion_Score": 0,
      "summary": ""
    }}
  ],
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
            {"role": "system", "content": "You are a Wazuh System information event manager."},
            {"role": "user", "content": prompt}
        ]
    )

    output_text = response.choices[0].message.content

    try:
        chunk_json = json.loads(output_text)
    except Exception as e:
        print(f"JSON error in {chunk_name}: {e}")
        print(output_text)
        continue

    if "chunk_all_logs" not in chunk_json:
        print(f"Missing 'chunk_all_logs' in {chunk_name}")
        print(output_text)
        continue

    chunk_results = pd.DataFrame(chunk_json["chunk_all_logs"])
    chunk_results2 = pd.DataFrame(chunk_json["top_5_suspicious"])


    merged_df = df.merge(chunk_results, on="RowID", how="left")

    merged_df.to_csv(output_path, index=False)
    top5_output_path = os.path.join(output_folder, f"{chunk_name}_top5.csv")
    chunk_results2.to_csv(top5_output_path, index=False)
    print(f"Saved: {output_path}")

print("DONE")
print("All chunks processed")