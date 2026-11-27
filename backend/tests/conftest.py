import os
import sys
from pathlib import Path

# Tests never call a real LLM or Qdrant Cloud.
for key in ("GROQ_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "QDRANT_URL", "LLM_PROVIDER"):
    os.environ.pop(key, None)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
