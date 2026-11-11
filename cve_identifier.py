import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv(override=True)
client = Groq(api_key=os.environ.get("GROQ_API_KEY").strip())

def check_repository_manifest(repo_name: str, dependency_file: str) -> str:
    print(f"\n[TOOL CALLED] Checking manifest '{dependency_file}' in repository '{repo_name}'...")
    mock_repos = {
        "payment-service": json.dumps({"dependencies": {"lodash": "4.17.15", "express": "4.17.1"}}),
        "user-portal": json.dumps({"dependencies": {"lodash": "4.18.0", "axios": "1.2.0"}}),
        "auth-api": json.dumps({"dependencies": {"lodash": "4.17.10", "jsonwebtoken": "8.5.1"}}),
    }
    result = mock_repos.get(repo_name, "Repository or file not found.")
    print(f"[TOOL OUTPUT]: {result}")
    return result

tools = [
    {
        "type": "function",
        "function": {
            "name": "check_repository_manifest",
            "description": "Examine a repository's package manifest file to check dependency versions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_name": {"type": "string", "description": "Name of the target repo to check."},
                    "dependency_file": {"type": "string", "description": "Name of the file, e.g., package.json"}
                },
                "required": ["repo_name", "dependency_file"]
            }
        }
    }
]

def run_cve_identification_agent(cve_advisory: str, target_repos: list):
    print(f"--- Analyzing Advisory: {cve_advisory} ---\n")

    system_prompt = (
        "You are an expert Application Security CVE Identification Agent. "
        "Your job is to analyze incoming security advisories, inspect target repositories "
        "using your tool one by one until you have checked all relevant ones, determine which repos are vulnerable, "
        "and output a prioritized remediation summary."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Advisory: {cve_advisory}\nTarget Repositories to audit: {target_repos}"}
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

        # If the model did NOT request a tool call, it means it's finished and ready to give its final report!
        if not response_message.tool_calls:
            return response_message.content

        # Otherwise, execute every tool call the model requested
        for tool_call in response_message.tool_calls:
            function_name = tool_call.function.name
            function_args = json.loads(tool_call.function.arguments)

            if function_name == "check_repository_manifest":
                tool_output = check_repository_manifest(
                    repo_name=function_args.get("repo_name"),
                    dependency_file=function_args.get("dependency_file")
                )

                # Append tool output back into message history
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_output
                })

if __name__ == "__main__":
    sample_cve = "CVE-2021-23337: lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution."
    repos_to_check = ["payment-service", "user-portal", "auth-api"]

    report = run_cve_identification_agent(sample_cve, repos_to_check)
    print("\n=== FINAL AGENT IDENTIFICATION REPORT ===")
    print(report)