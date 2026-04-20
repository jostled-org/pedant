import requests
import subprocess

response = requests.get("https://example.com/api")
subprocess.run(["ls", "-la"])
