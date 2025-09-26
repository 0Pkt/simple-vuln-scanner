# 🕵️ Simple Vulnerability Scanner

A Python script to test web apps for **Reflected XSS** and **SQL Injection (SQLi)**.  
Built as a learning/demo tool for application security and automation.

⚠️ **For educational use only.** Do not scan websites you don’t own or have explicit permission to test.

---

## 🚀 Features
- Detects:
  - **Reflected XSS** → injects `<script>alert(1)</script>` and checks reflection.
  - **Basic SQLi** → injects `' OR '1'='1` and looks for SQL error messages.
- Works via **command line** (no config files needed).
- Built with **Python + Requests**.
- Includes error handling for timeouts and connection failures.

---
