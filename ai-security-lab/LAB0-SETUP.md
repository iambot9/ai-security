# LAB 0: Environment Setup

**AI Security Lab Series**
Course: Attacking and Defending AI Agent Systems
Lab: 0 of 6 — Environment Setup
Estimated Time: 45–60 minutes

---

## Overview

This lab establishes the foundation for the entire course. You will set up a Python development environment, install security-focused libraries, scaffold the full project directory, and verify that everything runs before you write a single line of business logic.

Getting the environment right before writing any code is a discipline that matters more in security work than anywhere else. A misconfigured environment introduces ambiguity: when an attack fails or a defense doesn't trigger, you need to know whether the problem is your code or your setup. A clean, reproducible environment eliminates that variable entirely.

**The learning progression across all labs:**

```
LAB 0  →  LAB 1–2  →  LAB 3–4  →  LAB 5–6  →  TEST
Setup     Build        Break        Defend       Validate
          the agent    it           it
```

By the end of this setup, you will have:
- A working Python virtual environment with all required dependencies
- The full project directory tree scaffolded and ready
- A running FastAPI application verified via curl
- (Optional) A Docker environment for containerized deployment

---

## Section 1: Prerequisites

Before running any commands, verify that the required tools are present on your system. Skipping this check is the most common cause of confusing errors later.

### 1.1 Python 3.11+

Python 3.11 introduced significant performance improvements and better error messages. More importantly for this lab, several of the AI security libraries (LLM Guard, Presidio) require 3.10 at minimum and are tested against 3.11.

**Step 1.** Open a terminal and check your Python version:

```bash
python3 --version
```

Expected output (version must be 3.11.x or higher):

```
Python 3.11.9
```

If you see `Python 2.x` or `Python 3.9` or earlier, you need to upgrade. On macOS with Homebrew:

```bash
brew install python@3.11
```

On Ubuntu/Debian:

```bash
sudo apt update && sudo apt install python3.11 python3.11-venv python3.11-dev
```

**Step 2.** Confirm that `pip` is available and associated with the correct Python version:

```bash
python3 -m pip --version
```

Expected output (the Python path should reference 3.11):

```
pip 24.x.x from /usr/local/lib/python3.11/... (python 3.11)
```

> **Why this matters:** pip version mismatches — where `pip` points to a system Python 2 installation — are a classic environment trap. Always invoke pip through `python3 -m pip` rather than the bare `pip` command to guarantee you are installing into the correct interpreter.

**Step 3.** Confirm `venv` is available:

```bash
python3 -m venv --help
```

You should see usage output. If you see a `ModuleNotFoundError`, install it:

```bash
# macOS (Homebrew)
brew install python@3.11

# Ubuntu/Debian
sudo apt install python3.11-venv
```

### 1.2 Docker Desktop (Optional)

Docker is used in the final phase of this lab series to containerize the agent and run it in an isolated environment. It is not required for Labs 1–5, but you should install it now so it is ready when needed.

**Step 4.** Check if Docker is installed:

```bash
docker --version
docker compose version
```

Expected output:

```
Docker version 27.x.x, build ...
Docker Compose version v2.x.x
```

If Docker is not installed, download Docker Desktop from `https://www.docker.com/products/docker-desktop/` and follow the installer. After installation, start Docker Desktop and wait for it to report "Engine running" before continuing.

> **Why Docker matters for security labs:** Containerization enforces explicit isolation boundaries. When you run the vulnerable agent inside a container, you get a concrete model of the attack surface: what ports are exposed, what filesystem paths are accessible, what environment variables are visible. This mirrors real-world deployment far better than running directly on your laptop.

### 1.3 A Code Editor

Visual Studio Code is recommended for this lab series because the Python extension provides inline type checking, which helps catch bugs in the agent code before you run it.

**Step 5.** Confirm VS Code is installed:

```bash
code --version
```

If this command is not found, install the `code` CLI from within VS Code: open the Command Palette (`Cmd+Shift+P` on macOS), search for "Shell Command: Install 'code' command in PATH", and run it.

Recommended VS Code extensions for this lab:
- Python (Microsoft)
- Pylance
- REST Client (Huachao Mao) — for sending HTTP requests from within the editor
- Thunder Client — alternative to REST Client

### 1.4 curl or Postman

You will use curl throughout this lab to send HTTP requests to the agent. Postman is a graphical alternative.

**Step 6.** Verify curl is available:

```bash
curl --version
```

Expected output:

```
curl 8.x.x (x86_64-apple-darwin...) ...
```

curl is pre-installed on macOS and most Linux distributions. If it is missing on a minimal Linux installation:

```bash
sudo apt install curl
```

### 1.5 Knowledge Prerequisites

This lab series assumes:

- **Python:** You can read and write Python functions, classes, and basic async/await syntax. You do not need to be an expert.
- **REST APIs:** You understand what HTTP verbs (GET, POST) and status codes (200, 401, 500) mean. You have used curl or a similar tool before.
- **SQL:** You can read a SELECT statement and understand what a JOIN does. You do not need to write complex queries.
- **IAM concepts:** You are familiar with authentication vs. authorization, roles and permissions, and the principle of least privilege. This background will be directly relevant in Labs 3 and 4.

---

## Section 2: Project Directory Structure

You will create the entire project scaffold now, even though most files will be empty. This serves two purposes: it forces you to understand the architecture before you start coding, and it prevents the "where does this file go?" friction that slows down labs.

### 2.1 Understanding the Architecture

Before running any commands, understand what each directory contains and why it is separated this way:

```
ai-security-lab/
├── agent/          # The target system — the vulnerable chatbot agent
├── attacks/        # Offensive scripts — one file per lab vulnerability
├── defenses/       # Defensive components — custom and enterprise library integrations
└── tests/          # Automated test suite — validates both attacks and defenses
```

This separation mirrors the red team / blue team division in a real security engagement. The `agent/` directory is the crown jewel — the system under test. The `attacks/` directory is the attacker's toolkit. The `defenses/` directory is the defender's response. Keeping them separate ensures that defensive code is never accidentally loaded during an attack simulation, and that attack scripts can be read and understood in isolation.

### 2.2 Create the Directory Tree

**Step 7.** Navigate to your working directory and create the full project structure:

```bash
cd ~/Documents/claude

mkdir -p ai-security-lab/agent
mkdir -p ai-security-lab/attacks
mkdir -p ai-security-lab/defenses
mkdir -p ai-security-lab/tests
```

**Step 8.** Create all required files. The `touch` command creates empty files without overwriting anything that already exists:

```bash
# Agent module files
touch ai-security-lab/agent/__init__.py
touch ai-security-lab/agent/app.py
touch ai-security-lab/agent/llm.py
touch ai-security-lab/agent/tools.py
touch ai-security-lab/agent/system_prompt.py
touch ai-security-lab/agent/database.py
touch ai-security-lab/agent/config.py

# Attack scripts — one per vulnerability class
touch ai-security-lab/attacks/__init__.py
touch ai-security-lab/attacks/lab1_prompt_injection.py
touch ai-security-lab/attacks/lab2_sensitive_disclosure.py
touch ai-security-lab/attacks/lab3_insecure_output.py
touch ai-security-lab/attacks/lab4_excessive_agency.py
touch ai-security-lab/attacks/lab5_rag_poisoning.py
touch ai-security-lab/attacks/lab6_denial_of_service.py

# Defense modules — custom implementations and enterprise library wrappers
touch ai-security-lab/defenses/__init__.py
touch ai-security-lab/defenses/input_guard.py
touch ai-security-lab/defenses/output_guard.py
touch ai-security-lab/defenses/rbac.py
touch ai-security-lab/defenses/rate_limiter.py
touch ai-security-lab/defenses/prompt_armor.py
touch ai-security-lab/defenses/audit_logger.py
touch ai-security-lab/defenses/llm_guard_scanner.py
touch ai-security-lab/defenses/presidio_anonymizer.py
touch ai-security-lab/defenses/guardrails_validator.py
touch ai-security-lab/defenses/comparison.py

# Test suite
touch ai-security-lab/tests/test_attacks.py
touch ai-security-lab/tests/test_defenses.py

# Root-level project files
touch ai-security-lab/requirements.txt
touch ai-security-lab/Dockerfile
touch ai-security-lab/docker-compose.yml
```

**Step 9.** Verify the structure was created correctly:

```bash
find ai-security-lab -type f | sort
```

Expected output:

```
ai-security-lab/Dockerfile
ai-security-lab/agent/__init__.py
ai-security-lab/agent/app.py
ai-security-lab/agent/config.py
ai-security-lab/agent/database.py
ai-security-lab/agent/llm.py
ai-security-lab/agent/system_prompt.py
ai-security-lab/agent/tools.py
ai-security-lab/attacks/__init__.py
ai-security-lab/attacks/lab1_prompt_injection.py
ai-security-lab/attacks/lab2_sensitive_disclosure.py
ai-security-lab/attacks/lab3_insecure_output.py
ai-security-lab/attacks/lab4_excessive_agency.py
ai-security-lab/attacks/lab5_rag_poisoning.py
ai-security-lab/attacks/lab6_denial_of_service.py
ai-security-lab/defenses/__init__.py
ai-security-lab/defenses/audit_logger.py
ai-security-lab/defenses/comparison.py
ai-security-lab/defenses/guardrails_validator.py
ai-security-lab/defenses/input_guard.py
ai-security-lab/defenses/llm_guard_scanner.py
ai-security-lab/defenses/output_guard.py
ai-security-lab/defenses/presidio_anonymizer.py
ai-security-lab/defenses/prompt_armor.py
ai-security-lab/defenses/rate_limiter.py
ai-security-lab/defenses/rbac.py
ai-security-lab/docker-compose.yml
ai-security-lab/requirements.txt
ai-security-lab/tests/test_attacks.py
ai-security-lab/tests/test_defenses.py
```

### 2.3 File Roles — Quick Reference

Understanding what each file will eventually contain helps you reason about the attack surface:

| File | Role | Security Relevance |
|------|------|--------------------|
| `agent/app.py` | FastAPI application entry point, route definitions | The attack surface — every route is a potential entry point |
| `agent/llm.py` | LLM client wrapper (calls the AI model API) | Trust boundary — user input crosses into the LLM here |
| `agent/tools.py` | Tool definitions the agent can invoke (DB queries, file ops) | Excessive agency risk — tools with overly broad permissions |
| `agent/system_prompt.py` | The agent's system prompt | Prompt injection target — attacker tries to override this |
| `agent/database.py` | SQLite database access layer | Injection and data disclosure risk |
| `agent/config.py` | Environment variables and configuration | Secret storage — API keys, database paths |
| `defenses/input_guard.py` | Custom input validation logic | First line of defense against malicious input |
| `defenses/output_guard.py` | Custom output sanitization | Prevents sensitive data leakage in responses |
| `defenses/rbac.py` | Role-Based Access Control implementation | Enforces least-privilege on tool invocations |
| `defenses/rate_limiter.py` | Request throttling | Mitigates denial-of-service and enumeration attacks |
| `defenses/audit_logger.py` | Security event logging | Non-repudiation and forensics |
| `defenses/llm_guard_scanner.py` | Wrapper around the LLM Guard library | Enterprise-grade prompt injection and toxicity detection |
| `defenses/presidio_anonymizer.py` | Wrapper around Microsoft Presidio | PII detection and anonymization in inputs and outputs |
| `defenses/guardrails_validator.py` | Wrapper around Guardrails AI | Schema validation and output contract enforcement |
| `defenses/comparison.py` | Side-by-side defense comparison harness | Used in Lab 5 to benchmark defenses against each other |

---

## Section 3: Virtual Environment Setup

A virtual environment is a self-contained Python installation. Every package you install goes into the virtual environment, not into your system Python. This matters for two reasons:

1. **Reproducibility:** Someone else can recreate your exact environment from `requirements.txt` without affecting their system.
2. **Isolation:** Security libraries sometimes have complex dependency trees. Keeping them isolated prevents version conflicts that would be nearly impossible to debug.

### 3.1 Create and Activate the Virtual Environment

**Step 10.** Create the virtual environment inside the project directory:

```bash
cd ~/Documents/claude/ai-security-lab
python3 -m venv .venv
```

This creates a `.venv/` directory containing a complete Python installation. It is prefixed with a dot to signal that it is an environment artifact, not source code.

**Step 11.** Activate the virtual environment.

On macOS and Linux:

```bash
source .venv/bin/activate
```

On Windows (PowerShell):

```powershell
.venv\Scripts\Activate.ps1
```

On Windows (Command Prompt):

```cmd
.venv\Scripts\activate.bat
```

After activation, your terminal prompt will change to show the environment name:

```
(.venv) $
```

> **Why this matters:** If you forget to activate the virtual environment, packages will install into your system Python and `import` statements in the project will fail silently or use the wrong version. Always confirm that `(.venv)` appears in your prompt before running any `pip install` or `python` command in this project.

**Step 12.** Confirm that `python` and `pip` now point to the virtual environment:

```bash
which python
which pip
```

Expected output (paths should contain `.venv`):

```
/Users/yourname/Documents/claude/ai-security-lab/.venv/bin/python
/Users/yourname/Documents/claude/ai-security-lab/.venv/bin/pip
```

### 3.2 Create requirements.txt

**Step 13.** Open `requirements.txt` and add the following content exactly. This file pins the direct dependencies for the project. Transitive dependencies will be resolved automatically by pip.

```
# Web framework and server
fastapi==0.115.5
uvicorn[standard]==0.32.1

# HTTP client (for attack scripts that make outbound requests)
httpx==0.28.1

# Data validation (FastAPI uses this internally; we also use it for output contracts)
pydantic==2.10.3

# Multipart form data support (for file upload attack scenarios)
python-multipart==0.0.19

# Testing
pytest==8.3.4
pytest-asyncio==0.24.0
httpx  # also used as the async test client for FastAPI

# AI Security — Input/Output scanning
llm-guard==0.3.14

# PII Detection and Anonymization (Microsoft Presidio)
presidio-analyzer==2.2.355
presidio-anonymizer==2.2.355

# Guardrails — Output schema validation and contract enforcement
guardrails-ai==0.5.14

# Anthropic SDK (for calling Claude as the agent's LLM)
anthropic==0.40.0
```

> **Note:** `sqlite3` is part of the Python standard library and does not need to be listed in `requirements.txt`. It is available in any Python 3.x installation without a separate install step. The `anthropic` SDK is included here because this lab series uses Claude as the agent's underlying LLM. If you prefer OpenAI, replace `anthropic` with `openai`.

**Step 14.** Install all dependencies:

```bash
pip install -r requirements.txt
```

This will take 3–8 minutes on first run because the AI security libraries (LLM Guard, Presidio) pull in large NLP model weights. You will see progress bars for each package.

> **Note:** On Apple Silicon (M1/M2/M3) Macs, some packages with native extensions compile from source. If you see a build error, ensure you have Xcode command-line tools: `xcode-select --install`

**Step 15.** After installation completes, verify the key packages are importable:

```bash
python -c "import fastapi; print('fastapi', fastapi.__version__)"
python -c "import uvicorn; print('uvicorn OK')"
python -c "import anthropic; print('anthropic OK')"
python -c "import llm_guard; print('llm_guard OK')"
python -c "from presidio_analyzer import AnalyzerEngine; print('presidio OK')"
python -c "import guardrails; print('guardrails OK')"
```

Each line should print the package name and version (or "OK") without any errors. If a package fails to import, reinstall it individually:

```bash
pip install --force-reinstall <package-name>
```

### 3.3 Set Up the Anthropic API Key

The agent uses Claude as its LLM backend. You need an Anthropic API key.

**Step 16.** If you do not have an Anthropic API key, create one at `https://console.anthropic.com/`. Navigate to "API Keys" and generate a new key.

**Step 17.** Set the API key as an environment variable. Do NOT hardcode it in any source file — this is a security anti-pattern that the labs explicitly demonstrate and defend against.

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

To make this persist across terminal sessions, add it to your shell profile:

```bash
# For zsh (default on macOS)
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.zshrc
source ~/.zshrc

# For bash
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.bashrc
source ~/.bashrc
```

> **Security note:** Never commit your API key to git. If you accidentally do, rotate the key immediately in the Anthropic console — the old key is compromised the moment it touches a git history, even if you delete it in a later commit. In Lab 2, you will exploit exactly this kind of configuration mistake in the vulnerable agent.

**Step 18.** Verify the key is set (this only shows whether it is set, not the value):

```bash
echo "API key is set: $([ -n "$ANTHROPIC_API_KEY" ] && echo YES || echo NO)"
```

---

## Section 4: Docker Setup (Optional)

Complete this section now if you want Docker ready for the containerization phase. If you are skipping Docker for now, proceed to Section 5.

### 4.1 Create the Dockerfile

**Step 19.** Open `Dockerfile` and add the following content:

```dockerfile
# syntax=docker/dockerfile:1

# Use an official Python slim image as the base.
# Slim images remove documentation and locale files, reducing attack surface.
FROM python:3.11-slim

# Set the working directory inside the container.
WORKDIR /app

# Copy only the requirements file first, before the rest of the code.
# This takes advantage of Docker's layer caching: if requirements.txt has not
# changed, Docker will not re-run pip install on subsequent builds.
COPY requirements.txt .

# Install dependencies.
# --no-cache-dir prevents pip from writing a local cache inside the image,
# which would unnecessarily increase image size.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source code into the image.
COPY agent/ ./agent/
COPY defenses/ ./defenses/

# Expose port 8000. This is documentation — it does not actually publish the port.
# The actual port mapping is done in docker-compose.yml or the docker run command.
EXPOSE 8000

# Run the application.
# Using the JSON array form (exec form) prevents the shell from wrapping the
# command, which means signals (SIGTERM, SIGINT) are delivered directly to uvicorn.
# This allows graceful shutdown, which matters for audit log flushing.
CMD ["uvicorn", "agent.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 4.2 Create docker-compose.yml

**Step 20.** Open `docker-compose.yml` and add the following content:

```yaml
version: "3.9"

services:
  agent:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      # Map host port 8000 to container port 8000.
      # Format: "host:container"
      - "8000:8000"
    environment:
      # Pass the API key from the host environment into the container.
      # Never hardcode secrets in this file.
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - ENV=development
    volumes:
      # Mount the agent and defenses directories for live code reloading
      # during development. Remove this in production.
      - ./agent:/app/agent
      - ./defenses:/app/defenses
    restart: unless-stopped

  # Uncomment this service in Lab 5 when you add RAG (vector database) support.
  # chromadb:
  #   image: chromadb/chroma:latest
  #   ports:
  #     - "8001:8000"
  #   volumes:
  #     - chroma_data:/chroma/chroma

# volumes:
#   chroma_data:
```

### 4.3 Build and Run with Docker

**Step 21.** Build the Docker image (run this from the `ai-security-lab/` directory):

```bash
docker compose build
```

Expected output ends with:

```
 => => writing image sha256:...
 => => naming to docker.io/library/ai-security-lab-agent
```

**Step 22.** Start the container:

```bash
docker compose up -d
```

The `-d` flag runs the container in detached mode (background). Check that it started successfully:

```bash
docker compose ps
```

Expected output:

```
NAME                    IMAGE                    COMMAND                  SERVICE   CREATED         STATUS         PORTS
ai-security-lab-agent   ai-security-lab-agent    "uvicorn agent.app:a…"   agent     5 seconds ago   Up 4 seconds   0.0.0.0:8000->8000/tcp
```

**Step 23.** To stop the container:

```bash
docker compose down
```

> **Note:** During Labs 1–4, you will run the agent directly with `uvicorn` rather than Docker. The Docker setup becomes relevant in Lab 6 (containerization and isolation as a defense). The commands to interact with the agent are identical either way — it always listens on port 8000.

---

## Section 5: Verify Your Setup

Before moving to Lab 1, confirm that FastAPI is working correctly by running a minimal application.

### 5.1 Write the Verification App

**Step 24.** Open `agent/app.py` and add the following content. This is a temporary verification app — you will replace it with the actual agent in Lab 1:

```python
"""
agent/app.py — Verification entry point (LAB 0 only)

This will be replaced with the full agent application in Lab 1.
"""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="AI Security Lab — Agent",
    description="Vulnerable AI agent chatbot (for educational purposes)",
    version="0.1.0",
)


class HealthResponse(BaseModel):
    status: str
    message: str
    lab: str


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.

    In a real system, this would also check downstream dependencies
    (database connectivity, LLM API reachability). An attacker can
    probe this endpoint to fingerprint the application — in Lab 2
    you will see how verbose health checks leak system information.
    """
    return HealthResponse(
        status="ok",
        message="Agent is running. Environment setup verified.",
        lab="LAB0-SETUP",
    )


@app.post("/chat")
async def chat_placeholder(body: dict):
    """
    Placeholder chat endpoint — replaced in Lab 1.
    """
    return {
        "response": "Setup verified. The real agent will be built in Lab 1.",
        "input_received": body,
    }
```

### 5.2 Run the Application

**Step 25.** Start the FastAPI development server. Make sure your virtual environment is still active (you should see `(.venv)` in your prompt):

```bash
uvicorn agent.app:app --reload --host 127.0.0.1 --port 8000
```

Flag explanations:
- `agent.app:app` — Python module path to the FastAPI instance. Reads as: "in the `agent` package, in the `app` module, the object named `app`."
- `--reload` — Automatically restart the server when source files change. Use this in development only.
- `--host 127.0.0.1` — Bind only to localhost. Never bind to `0.0.0.0` in a lab environment unless you specifically intend to expose the server to your network.
- `--port 8000` — The port to listen on.

Expected startup output:

```
INFO:     Will watch for changes in these directories: ['/Users/.../ai-security-lab']
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [12345] using WatchFiles
INFO:     Started server process [12346]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

### 5.3 Verify with curl

**Step 26.** Open a second terminal window (keep the server running in the first). In the new window, run:

```bash
curl -s http://127.0.0.1:8000/health | python3 -m json.tool
```

Expected output:

```json
{
    "status": "ok",
    "message": "Agent is running. Environment setup verified.",
    "lab": "LAB0-SETUP"
}
```

**Step 27.** Test the placeholder chat endpoint:

```bash
curl -s -X POST http://127.0.0.1:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, agent!"}' \
  | python3 -m json.tool
```

Expected output:

```json
{
    "response": "Setup verified. The real agent will be built in Lab 1.",
    "input_received": {
        "message": "Hello, agent!"
    }
}
```

**Step 28.** Check the interactive API documentation that FastAPI generates automatically:

```
http://127.0.0.1:8000/docs
```

Open this URL in a browser. You should see Swagger UI with two endpoints listed: `GET /health` and `POST /chat`.

> **Security note:** This auto-generated documentation is enabled by default in FastAPI. In production, it should be disabled or access-controlled. In Lab 3 you will see how an attacker can use the `/docs` endpoint to enumerate all available routes and their schemas. The configuration to disable it is `FastAPI(docs_url=None, redoc_url=None)`.

**Step 29.** Stop the server by pressing `Ctrl+C` in the terminal where uvicorn is running.

### 5.4 Verify pytest

**Step 30.** Run the (currently empty) test suite to confirm pytest is configured correctly:

```bash
pytest tests/ -v
```

Expected output:

```
========================= test session starts ==========================
platform darwin -- Python 3.11.x, pytest-8.x.x, pluggy-1.x.x
rootdir: /Users/.../ai-security-lab
collected 0 items

========================= no tests ran in 0.01s =========================
```

"No tests ran" is the correct output at this point — the test files are empty. If pytest reports an error finding the `tests/` directory or fails to import, something is misconfigured.

---

## Section 6: Lab Overview and Learning Progression

### 6.1 The Full Lab Series

| Lab | Title | Phase | Estimated Time |
|-----|-------|-------|----------------|
| LAB 0 | Environment Setup | Setup | 45–60 min |
| LAB 1 | Building the Vulnerable Agent | Build | 90–120 min |
| LAB 2 | Prompt Injection Attacks | Break | 60–90 min |
| LAB 3 | Sensitive Data Disclosure | Break | 45–60 min |
| LAB 4 | Excessive Agency Exploitation | Break | 60–90 min |
| LAB 5 | Custom Defenses | Defend (custom) | 90–120 min |
| LAB 6 | Enterprise Defense Tools | Defend (enterprise) | 90–120 min |

Total estimated time: 8–11 hours across all labs.

### 6.2 Phase-by-Phase Description

**Phase 1 — Build (Lab 1)**

You will construct a realistic AI agent chatbot using FastAPI and Claude. The agent has access to tools: it can query a SQLite database containing simulated user records and financial data, read files, and make outbound HTTP requests. The agent is intentionally built with security mistakes — verbose error messages, no input validation, overly permissive tool access, secrets in the system prompt — because you need a realistic target before you can practice attacking and defending.

The learning outcome: you will understand the architecture of an LLM-powered agent well enough to reason about its attack surface.

**Phase 2 — Break (Labs 2–4)**

You will attack the agent you built, using three of the OWASP Top 10 for LLM Applications vulnerability classes:

- **Lab 2 — Prompt Injection:** You will craft user messages that override the system prompt, cause the agent to reveal its instructions, and make the agent take actions it was not supposed to take. You will also attempt indirect prompt injection — hiding malicious instructions in documents that the agent retrieves and processes.

- **Lab 3 — Sensitive Data Disclosure:** You will probe the agent's knowledge of its own configuration, extract API keys and database credentials embedded in the system prompt, and observe how verbose error messages leak implementation details that an attacker can use to plan further attacks.

- **Lab 4 — Excessive Agency:** You will exploit the agent's tool access. Because the agent has database write permissions it doesn't need for its stated purpose, you will social-engineer it into modifying records. You will demonstrate why least-privilege applies to AI agents exactly as it applies to service accounts in IAM.

The learning outcome: you will have hands-on intuition for how LLM vulnerabilities differ from classical web vulnerabilities, and why traditional WAF rules are insufficient to stop them.

**Phase 3 — Defend (Custom) (Lab 5)**

You will implement defenses by hand, without reaching for a library. This phase is deliberately low-level because you need to understand the mechanics of a defense before you can evaluate whether an enterprise tool is implementing it correctly.

Defenses you will build:
- Input validation that detects prompt injection patterns using regex and keyword matching
- Output filtering that scans responses for PII patterns (SSNs, email addresses, credit card numbers) before returning them to the user
- RBAC that enforces tool-level permissions based on the user's role, using the same mental model you already have from IAM work
- Rate limiting that tracks request frequency per user and blocks abuse
- An audit logger that records every tool invocation with its parameters, so you can trace exactly what the agent did during an attack

The learning outcome: you will understand the limitations of rule-based defenses and be able to articulate why each custom defense can be bypassed by a sophisticated attacker.

**Phase 4 — Defend (Enterprise Tools) (Lab 6)**

You will replace or augment your custom defenses with three enterprise-grade AI security libraries:

- **LLM Guard:** A scanning library that runs both inputs and outputs through a suite of classifiers — prompt injection detectors, toxicity filters, PII scanners, and more. You will integrate it as middleware in the FastAPI request pipeline.

- **Microsoft Presidio:** A PII detection and anonymization engine that uses named-entity recognition (NER) models rather than regex. You will compare its detection rate against your regex-based custom implementation on a benchmark of PII-containing messages.

- **Guardrails AI:** A framework for defining output contracts using a schema-based approach. You will write a "guard" that enforces that the agent's responses always conform to a defined structure and never contain certain prohibited patterns.

The comparison harness in `defenses/comparison.py` will let you run the same attack payloads through both your custom defenses and the enterprise libraries, measure the detection rate of each, and visualize the trade-offs.

The learning outcome: you will be able to make an informed recommendation about which defense layer is appropriate for a given threat model, and understand the operational cost (latency, false positive rate) of each approach.

### 6.3 Security Concepts Covered

This lab series covers the following from the OWASP Top 10 for LLM Applications (2025):

| OWASP LLM Category | Lab(s) |
|---------------------|--------|
| LLM01: Prompt Injection | Lab 2 |
| LLM02: Sensitive Information Disclosure | Lab 3 |
| LLM06: Excessive Agency | Lab 4 |
| LLM03: Supply Chain (RAG poisoning variant) | Lab 5 |
| LLM04: Data and Model Poisoning | Lab 5 |
| LLM10: Unbounded Consumption (DoS) | Lab 6 |

IAM concepts that map directly to AI security problems you will encounter:

| IAM Concept | AI Security Equivalent |
|-------------|----------------------|
| Least privilege for service accounts | Restricting which tools an agent can invoke |
| Role-based access control | Scoping agent capabilities by authenticated user role |
| Audit logging / SIEM integration | Logging every tool invocation and LLM call |
| Secret rotation | Preventing API key disclosure in system prompts |
| Input validation / WAF | Prompt injection filtering on user input |
| Defense in depth | Layering custom guards + enterprise libraries + RBAC |

### 6.4 How to Navigate the Labs

Each lab (1–6) has its own `LAB{N}-*.md` file in the `ai-security-lab/` directory. Each lab assumes you have completed all previous labs. The attack scripts in `attacks/` are designed to be run against the agent as-built at that point in the series — running a Lab 4 attack script against the Lab 1 agent will produce different results than expected.

If you get stuck, the most useful debugging tool is the uvicorn server log. Every request, error, and exception is printed there. Read the traceback from bottom to top — the bottom line is the actual error, the lines above it are the call chain that led there.

---

## Section 7: Checkpoint

Before proceeding to Lab 1, confirm that all of the following are true:

- [ ] `python3 --version` shows 3.11 or higher
- [ ] `source .venv/bin/activate` activates the virtual environment without errors
- [ ] `pip install -r requirements.txt` completed without errors
- [ ] `fastapi`, `llm_guard`, `presidio_analyzer`, and `guardrails` all import successfully
- [ ] `ANTHROPIC_API_KEY` is set in your environment
- [ ] `uvicorn agent.app:app --reload` starts the server on port 8000
- [ ] `curl http://127.0.0.1:8000/health` returns `{"status": "ok", ...}`
- [ ] `pytest tests/ -v` runs without import errors (reporting 0 tests is correct)
- [ ] The full directory tree is present (verified with `find ai-security-lab -type f | sort`)

If any item is unchecked, do not proceed to Lab 1. Resolve the setup issue now — every subsequent lab builds directly on this foundation.

---

## Appendix A: Common Setup Errors

**Error: `ModuleNotFoundError: No module named 'fastapi'`**

Cause: The virtual environment is not activated.
Fix: Run `source .venv/bin/activate` and confirm `(.venv)` appears in your prompt.

**Error: `ImportError: cannot import name 'AnalyzerEngine' from 'presidio_analyzer'`**

Cause: Presidio installed incompletely, often due to a network interruption.
Fix: `pip install --force-reinstall presidio-analyzer presidio-anonymizer`

**Error: `Address already in use: [Errno 48]` when starting uvicorn**

Cause: A previous uvicorn process is still running.
Fix: Find and kill it: `lsof -ti:8000 | xargs kill -9`

**Error: `permission denied` on `touch` commands (macOS)**

Cause: The parent directory is owned by root or another user.
Fix: Confirm you are working in your home directory (`~/Documents/claude/`) and not in `/usr/local/` or similar.

**Error: `llm_guard` installs but model downloads fail at runtime**

Cause: LLM Guard downloads transformer models on first use, not at install time.
Fix: Ensure you have an internet connection when running the lab scripts for the first time. Models are cached in `~/.cache/huggingface/` after the first download.

---

## Appendix B: Deactivating and Reactivating the Environment

Every time you return to work on this project in a new terminal session, you must re-activate the virtual environment:

```bash
cd ~/Documents/claude/ai-security-lab
source .venv/bin/activate
```

To deactivate when you are done:

```bash
deactivate
```

To confirm the environment is active at any time:

```bash
which python
# Should print: .../ai-security-lab/.venv/bin/python
```

---

*AI Security Lab Series — LAB 0 of 6*
*Build → Break → Defend → Test*
