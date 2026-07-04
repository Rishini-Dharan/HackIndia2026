"""
Q-Guardian OS — Stateful Vector Memory (Qdrant Client & Gemini Embeddings)

Saves and retrieves security context, historical operator actions,
system loads, and conversational messages to and from Qdrant.
Falls back to a local in-memory Qdrant database if connection to the cloud instance fails.
Uses Gemini's text-embedding-004 API for ultra-fast high-quality vector embeddings,
or falls back to deterministic local hashing vectors.
"""

import os
import hashlib
import numpy as np
import httpx
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

# Qdrant Config
QDRANT_URL = os.getenv("QDRANT_URL", "")
QDRANT_API_KEY = os.getenv("QDRANT_API_KEY", "")

# Gemini API Config (for high-quality embeddings)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# OpenAI Config (optional fallback)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Determine embedding dimensions
if GEMINI_API_KEY:
    print("[QDRANT] Gemini API Key detected. Using Gemini gemini-embedding-2 (3072 dimensions).")
    EMBEDDING_DIM = 3072
elif OPENAI_API_KEY:
    print("[QDRANT] OpenAI API Key detected. Using OpenAI text-embedding-3-small (1536 dimensions).")
    EMBEDDING_DIM = 1536
else:
    print("[QDRANT] No embedding key found. Using deterministic local hashing (384 dimensions).")
    EMBEDDING_DIM = 384

COLLECTION_NAME = "qguardian_memory"

# Setup Qdrant Client with fallback
qdrant_client = None
if QDRANT_URL and QDRANT_API_KEY:
    try:
        print(f"[QDRANT] Attempting connection to remote instance: {QDRANT_URL}")
        client_candidate = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY, timeout=5)
        # Ping the collections to test connection
        client_candidate.get_collections()
        qdrant_client = client_candidate
        print("[QDRANT] Connected to Qdrant Cloud cluster successfully.")
    except Exception as e:
        print(f"[QDRANT] Remote connection failed: {e}. Falling back to local in-memory instance.")

if qdrant_client is None:
    print("[QDRANT] Initializing local in-memory Qdrant instance.")
    qdrant_client = QdrantClient(":memory:")

# Initialize collection if not exists
try:
    collections = qdrant_client.get_collections().collections
    collection_names = [c.name for c in collections]
    if COLLECTION_NAME not in collection_names:
        qdrant_client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=EMBEDDING_DIM, distance=Distance.COSINE),
        )
        print(f"[QDRANT] Collection '{COLLECTION_NAME}' created with size {EMBEDDING_DIM}")
    else:
        print(f"[QDRANT] Collection '{COLLECTION_NAME}' already exists.")
except Exception as e:
    print(f"[QDRANT] Warning initializing collection: {e}")


def _get_hashing_embedding(text: str, dimensions: int = 384) -> list[float]:
    """
    Deterministic Feature Hashing Vectorizer.
    Generates a dense normalized float vector representing the text.
    Zero-dependencies, zero-download, fast, and works offline.
    """
    vec = np.zeros(dimensions, dtype=np.float32)
    words = text.lower().split()
    if not words:
        return vec.tolist()
    for word in words:
        for i in range(3):
            h = hashlib.sha256(f"{word}_{i}".encode('utf-8')).hexdigest()
            val = int(h, 16)
            idx = val % dimensions
            sign = -1 if (val // dimensions) % 2 == 0 else 1
            vec[idx] += sign
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec.tolist()


def get_gemini_embedding(text: str, api_key: str) -> list[float]:
    """Generates embedding using Google Generative Language API (gemini-embedding-2)."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-2:embedContent?key={api_key}"
    payload = {
        "model": "models/gemini-embedding-2",
        "content": {
            "parts": [{"text": text}]
        }
    }
    resp = httpx.post(url, json=payload, timeout=8)
    resp.raise_for_status()
    # Path: embedding.values
    return resp.json()["embedding"]["values"]


def get_embedding(text: str) -> list[float]:
    """Generates embedding vector based on configured APIs."""
    if GEMINI_API_KEY:
        try:
            return get_gemini_embedding(text, GEMINI_API_KEY)
        except Exception as e:
            print(f"[QDRANT] Gemini embedding failed: {e}. Falling back...")
            
    if OPENAI_API_KEY:
        try:
            headers = {
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            }
            payload = {
                "input": text,
                "model": "text-embedding-3-small"
            }
            resp = httpx.post("https://api.openai.com/v1/embeddings", headers=headers, json=payload, timeout=8)
            if resp.status_code == 200:
                return resp.json()["data"][0]["embedding"]
        except Exception as e:
            print(f"[QDRANT] OpenAI embedding failed: {e}. Falling back...")
            
    # Hashing fallback. Adjust dimension based on current collection expectation if running locally
    return _get_hashing_embedding(text, dimensions=EMBEDDING_DIM)


def add_memory(text: str, category: str, metadata: dict = None) -> bool:
    """Adds a new event or operator action to vector memory."""
    try:
        vector = get_embedding(text)
        payload = {
            "text": text,
            "category": category,
            **(metadata or {})
        }
        
        import random
        point_id = random.randint(1, 10000000)
        
        qdrant_client.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=point_id,
                    vector=vector,
                    payload=payload
                )
            ]
        )
        return True
    except Exception as e:
        print(f"[QDRANT] Error adding memory: {e}")
        return False


def search_memory(query: str, limit: int = 5, category: str = None) -> list[dict]:
    """Searches vector database for relevant state facts/events."""
    try:
        vector = get_embedding(query)
        
        from qdrant_client.models import Filter, FieldCondition, MatchValue
        query_filter = None
        if category:
            query_filter = Filter(
                must=[
                    FieldCondition(
                        key="category",
                        match=MatchValue(value=category)
                    )
                ]
            )
            
        results = qdrant_client.query_points(
            collection_name=COLLECTION_NAME,
            query=vector,
            limit=limit,
            query_filter=query_filter
        )
        
        return [hit.payload for hit in results.points]
    except Exception as e:
        print(f"[QDRANT] Error searching memory: {e}")
        return []


def clear_memories():
    """Wipes all points in the collection (useful for clearing session)."""
    try:
        qdrant_client.delete_collection(COLLECTION_NAME)
        qdrant_client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=EMBEDDING_DIM, distance=Distance.COSINE),
        )
        print("[QDRANT] Collection reset successfully.")
    except Exception as e:
        print(f"[QDRANT] Error resetting collection: {e}")
