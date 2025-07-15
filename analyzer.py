import os
import requests
import json
from github import Github
from pathlib import Path
import tempfile
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import logging
import traceback

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='analysis.log'
)

load_dotenv()

class ProjectAnalyzer:
    def __init__(self):
        self.openrouter_key = os.getenv("OPENROUTER_API_KEY")
        if not self.openrouter_key:
            logging.error("OPENROUTER_API_KEY not set in environment variables")
            raise ValueError("OPENROUTER_API_KEY is required")

        self.gh_token = os.getenv("GITHUB_TOKEN")
        self.model = "cognitivecomputations/dolphin3.0-r1-mistral-24b:free"
        self.headers = {
            "Authorization": f"Bearer {self.openrouter_key}",
            "HTTP-Referer": "https://github.com",
            "X-Title": "ProjectAnalyzer",
            "Content-Type": "application/json"
        }
        self.max_files = 5 

    def clone_repo(self, repo_url):
        try:
            temp_dir = tempfile.mkdtemp()
            logging.info(f"Cloning repository {repo_url} to {temp_dir}")
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, temp_dir],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return temp_dir
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to clone repository: {e.stderr.decode()}")
            raise

    def get_code_files(self, repo_path):
        try:
            c_files = list(Path(repo_path).rglob("*.[ch]"))
            cpp_files = list(Path(repo_path).rglob("*.[ch]pp"))
            all_files = c_files + cpp_files
            logging.info(f"Found {len(all_files)} C/C++ files in {repo_path}")
            return all_files
        except Exception as e:
            logging.error(f"Error searching for code files: {str(e)}")
            return []

    def analyze_file(self, file_path):
        try:
            logging.info(f"Analyzing file: {file_path}")
            content = Path(file_path).read_text(encoding='utf-8', errors='ignore')[:15000]
            
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a code analysis tool. Identify functions that parse or handle network packets. "
                                  "Look for: buffer operations, protocol headers parsing, checksums, "
                                  "network byte order conversions (ntohs/htonl), socket operations."
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this file and find network packet handling functions.\n"
                                   "Return JSON format: {\"functions\": [{\"name\": \"func_name\", \"type\": \"parser|handler\", \"evidence\": \"...\"}]}\n"
                                   f"File: {file_path.name}\nCode:\n```c\n{content}\n```"
                    }
                ],
                "response_format": {"type": "json_object"}
            }

            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=self.headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            
            result = response.json()["choices"][0]["message"]["content"]
            logging.debug(f"Raw API response: {result}")
            return result
        except Exception as e:
            error_msg = f"Error analyzing {file_path}: {str(e)}"
            logging.error(error_msg)
            return json.dumps({"error": error_msg})

    def analyze_rfc(self, rfc_number):
        try:
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an RFC analysis specialist. Extract technical specifications with maximum detail and structure. "
                                "Follow these rules:\n"
                                "1. For constants: include all protocol-defined values with types (HEX/DEC/ASCII)\n"
                                "2. For packet formats: provide complete syntax with examples\n"
                                "3. Use nested JSON structure with clear categorization\n"
                                "4. Include all special cases and edge conditions\n"
                                "Output must be directly usable in code without post-processing."
                    },
                    {
                        "role": "user",
                        "content": f"Analyze RFC {rfc_number} (HTTP/1.1) and provide:\n\n"
                                "1. ALL protocol constants grouped by category:\n"
                                "   - HTTP versions\n"
                                "   - Methods\n"
                                "   - Status codes\n"
                                "   - Headers\n"
                                "   - Special values (like CRLF)\n\n"
                                "2. COMPLETE packet formats with:\n"
                                "   - Formal syntax\n"
                                "   - Examples\n"
                                "   - All possible variants\n\n"
                                "3. Special transmission cases\n\n"
                                "Return JSON format EXACTLY like this example:\n"
                                "{\n"
                                "  \"constants\": [\n"
                                "    {\"name\": \"HTTP_VER\", \"value\": \"HTTP/1.1\", \"type\": \"ASCII\", \"description\": \"...\"},\n"
                                "    {\"name\": \"STATUS_OK\", \"value\": 200, \"type\": \"DEC\", \"description\": \"...\"}\n"
                                "  ],\n"
                                "  \"packet_formats\": [\n"
                                "    {\n"
                                "      \"name\": \"Request\",\n"
                                "      \"syntax\": \"...\", \n"
                                "      \"example\": \"...\",\n"
                                "      \"variants\": [...]\n"
                                "    }\n"
                                "  ],\n"
                                "  \"special_cases\": [...]\n"
                                "}"
                    }
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.3  
            }

            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=self.headers,
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            
            
            result = response.json()["choices"][0]["message"]["content"]
            json.loads(result)  
            return result
            
        except Exception as e:
            error_msg = f"RFC analysis failed: {str(e)}"
            logging.error(error_msg)
            return json.dumps({"error": error_msg})

    def analyze_github_repo(self, repo_url):
        try:
            logging.info(f"Starting analysis of repository: {repo_url}")
            repo_path = self.clone_repo(repo_url)
            files = self.get_code_files(repo_path)
            
            if not files:
                logging.warning("No C/C++ files found in repository")
                return {"error": "No source files found"}

            results = []
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {executor.submit(self.analyze_file, file): file for file in files[:self.max_files]}  
                
                for future in futures:
                    file = futures[future]
                    try:
                        result = future.result()
                        parsed = json.loads(result)
                        
                        if isinstance(parsed, dict):
                            if "functions" in parsed and parsed["functions"]:
                                results.append({
                                    "file": str(file),
                                    "functions": parsed["functions"]
                                })
                            elif "error" in parsed:
                                logging.error(f"Analysis error for {file}: {parsed['error']}")
                    except json.JSONDecodeError as e:
                        logging.error(f"Failed to parse JSON for {file}: {str(e)}")
                        continue
                    except Exception as e:
                        logging.error(f"Unexpected error processing {file}: {str(e)}")
                        continue

            if not results:
                results = {
                    "status": "completed",
                    "message": "No network packet handling functions found",
                    "scanned_files": len(files)
                }

            return results
            
        except Exception as e:
            error_msg = f"Repository analysis failed: {str(e)}\n{traceback.format_exc()}"
            logging.error(error_msg)
            return {"error": error_msg}

if __name__ == "__main__":
    try:
        print("Starting analysis...")
        analyzer = ProjectAnalyzer()
        
        
        print("Analyzing libhv repository...")
        repo_results = analyzer.analyze_github_repo("https://github.com/ithewei/libhv")
        with open("libhv_analysis.json", "w", encoding='utf-8') as f:
            json.dump(repo_results, f, indent=2, ensure_ascii=False)
        print("Repository analysis saved to libhv_analysis.json")
        
       
        print("\nAnalyzing HTTP RFC...")
        rfc_results = analyzer.analyze_rfc("2616")
        with open("http_rfc_analysis.json", "w", encoding='utf-8') as f:
            f.write(rfc_results)
        print("RFC analysis saved to http_rfc_analysis.json")
        
        print("\nAnalysis complete. Check analysis.log for details.")
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        logging.error(f"Fatal error: {str(e)}\n{traceback.format_exc()}")