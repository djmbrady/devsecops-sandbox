import os
import json
from pathlib import Path
from groq import Groq
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)
client = Groq(api_key=os.environ.get("GROQ_API_KEY").strip())

# 1. DEFINE THE REAL FILE-INSPECTION TOOL
def check_repository_manifest(dependency_file: str) -> str:
    """Reads a real dependency file (e.g., package.json, requirements.txt) from the local workspace."""
    print(f"\n[TOOL CALLED] Inspecting real local file: '{dependency_file}'...")

    file_path = Path(dependency_file)

    if not file_path.exists():
        return f"Error: The dependency file '{dependency_file}' was not found in the workspace root."

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        print(f"[TOOL OUTPUT]: Successfully read {len(content)} characters from {dependency_file}")
        return content
    except Exception as e:
        return f"Error reading file: {str(e)}"

# Register the tool schema for the LLM
tools = [
    {
        "type": "function",
        "function": {
            "name": "check_repository_manifest",
            "description": "Examine a real dependency file (like package.json or requirements.txt) in the repository to check installed package versions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dependency_file": {
                        "type": "string",
                        "description": "The filename of the dependency manifest to inspect, e.g., 'package.json' or 'requirements.txt'."
                    }
                },
                "required": ["dependency_file"]
            }
        }
    }
]

# 2. RUN THE AGENTIC LOOP
def run_cve_identification_agent(cve_advisory: str):
    print(f"--- Analyzing Advisory: {cve_advisory} ---\n")

    system_prompt = (
        "You are an expert Application Security CVE Identification Agent. "
        "Your job is to analyze incoming security advisories, use your tool to inspect "
        "local dependency files (such as package.json or requirements.txt) in the workspace, "
        "determine if the vulnerable package and version are present, and output a prioritized remediation summary."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Security Advisory: {cve_advisory}\nPlease check the workspace repository manifest files (e.g., package.json) to see if we are vulnerable."}
    ]

    # THE AGENTIC LOOP: Keep running as long as the model wants to call tools
    while True:
        response = client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=messages,
            tools=tools,
            tool_choice="auto"
        )

        response_message = response.choices[0].message
        messages.append(response_message)

        # If the model did not request a tool call, it's finished and ready to provide the report
        if not response_message.tool_calls:
            return response_message.content

        # Execute every tool call the model requested
        for tool_call in response_message.tool_calls:
            function_name = tool_call.function.name
            function_args = json.loads(tool_call.function.arguments)

            if function_name == "check_repository_manifest":
                tool_output = check_repository_manifest(
                    dependency_file=function_args.get("dependency_file")
                )

                # Append real file content back into message history
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_output
                })

if __name__ == "__main__":
    # Test with a real CVE
    sample_cve = "CVE-2021-23337: lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution."

    report = run_cve_identification_agent(sample_cve)
    print("\n=== FINAL AGENT IDENTIFICATION REPORT ===")
    print(report)