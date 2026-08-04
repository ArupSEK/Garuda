#!/usr/bin/env bash
set -u
tools=(python3 nmap naabu httpx nuclei testssl.sh ssh-audit dnsx gowitness)
for tool in "${tools[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%-14s Installed\n' "$tool"
  else
    printf '%-14s Missing\n' "$tool"
  fi
done

