from dotenv import load_dotenv
import ollama
import os

load_dotenv()

# Graph Database
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# ollama's module-level ollama.chat() has no timeout parameter and sits on
# top of an httpx client with timeout=None (unbounded wait) by default -
# under real contention (multiple concurrent requests hitting one local
# model) a call can hang forever instead of failing fast. Every call site
# should use OLLAMA_CLIENT instead of the bare ollama.chat()/ollama module
# function so a stuck/overloaded model raises instead of hanging - callers
# already catch and degrade on exceptions (guardrail fails closed;
# orchestration/pipeline.py wraps every stage into a clean PipelineError).
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "60"))
OLLAMA_CLIENT = ollama.Client(timeout=OLLAMA_TIMEOUT)

