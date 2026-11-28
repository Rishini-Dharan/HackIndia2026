from fastapi.testclient import TestClient

import main
import qdrant_memory


def test_health_reports_memory_store():
    with TestClient(main.app) as client:
        assert client.get("/health").json()["memory_store"] == "in-memory"


def test_collection_name_includes_vector_size():
    assert qdrant_memory.COLLECTION_NAME == f"qguardian_memory_{qdrant_memory.EMBEDDING_DIM}"
