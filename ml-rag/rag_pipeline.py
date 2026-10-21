"""
rag_pipeline.py
Role 4 (ML/RAG Engineer, Dagi) — RAG Pipeline
Stores historical incidents in Qdrant and retrieves similar past cases.

This is the "Memory" of the SOC AI Agent. When a new alert arrives,
we embed its description and retrieve the top-k most similar past
incidents. The LLM then uses these as context when generating a briefing.
"""

import uuid
import pandas as pd
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "incident_reports"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"   # 384-dim, fast on CPU
VECTOR_SIZE = 384
CSV_PATH = "historical_alerts.csv"


# ---------------------------------------------------------------------------
# INITIALIZE CLIENTS
# ---------------------------------------------------------------------------
client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
model = SentenceTransformer(EMBEDDING_MODEL)


# ---------------------------------------------------------------------------
# STEP 1: CREATE COLLECTION
# ---------------------------------------------------------------------------
def create_collection():
    """
    Create the Qdrant collection that will store incident embeddings.
    If it already exists, it's skipped (idempotent).
    """
    collections = client.get_collections().collections
    existing = [c.name for c in collections]

    if COLLECTION_NAME in existing:
        print(f"[SKIP] Collection '{COLLECTION_NAME}' already exists.")
        return

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )
    print(f"[OK] Collection '{COLLECTION_NAME}' created.")


# ---------------------------------------------------------------------------
# STEP 2: EMBED AND INGEST
# ---------------------------------------------------------------------------
def ingest_incidents(csv_path: str = CSV_PATH):
    """
    Load the CSV, embed each incident description, and insert into Qdrant.

    Each embedding is a 384-dimensional vector representing the semantic
    meaning of the incident description.
    """
    df = pd.read_csv(csv_path)
    print(f"[INFO] Loaded {len(df)} incidents from {csv_path}")

    points = []
    for _, row in df.iterrows():
        # Combine alert_type + description for richer embedding
        text_to_embed = f"{row['alert_type']}: {row['description']}"

        # Convert to vector (list of 384 floats)
        embedding = model.encode(text_to_embed).tolist()

        # Create a Qdrant point (ID + vector + metadata payload)
        point = PointStruct(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, row["alert_id"])),
            vector=embedding,
            payload={
                "alert_id": row["alert_id"],
                "alert_type": row["alert_type"],
                "severity": row["severity"],
                "resolution": row["resolution"],
                "description": row["description"],
            },
        )
        points.append(point)

    # Batch upsert (faster than one-by-one)
    client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"[OK] Inserted {len(points)} incidents into Qdrant.")


# ---------------------------------------------------------------------------
# STEP 3: RETRIEVE SIMILAR INCIDENTS
# ---------------------------------------------------------------------------
def search_similar(query: str, top_k: int = 3) -> list[dict]:
    """
    Given a new alert description, return the top_k most similar
    historical incidents from Qdrant.

    This is the 'Retrieval' in Retrieval-Augmented Generation (RAG).
    """
    query_vector = model.encode(query).tolist()

    # NOTE: Newer qdrant-client (>=1.10) renamed .search() to .query_points()
    response = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=top_k,
    )

    return [
        {
            "score": round(hit.score, 4),
            "alert_id": hit.payload["alert_id"],
            "alert_type": hit.payload["alert_type"],
            "severity": hit.payload["severity"],
            "resolution": hit.payload["resolution"],
            "description": hit.payload["description"],
        }
        for hit in response.points
    ]


# ---------------------------------------------------------------------------
# MAIN (for manual testing)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("RAG PIPELINE — Ingestion & Retrieval Test")
    print("=" * 60)

    # Step 1: Create the collection
    create_collection()

    # Step 2: Ingest the incidents
    ingest_incidents()

    # Step 3: Test retrieval
    print("\n" + "=" * 60)
    print("TEST 1: PowerShell + external IP")
    print("=" * 60)
    results = search_similar("PowerShell connected to external IP and downloaded payload")
    for r in results:
        print(f"  [{r['score']}] {r['alert_id']} | {r['alert_type']} | {r['resolution']}")

    print("\n" + "=" * 60)
    print("TEST 2: Failed login attempts")
    print("=" * 60)
    results = search_similar("Multiple failed login attempts from same user account")
    for r in results:
        print(f"  [{r['score']}] {r['alert_id']} | {r['alert_type']} | {r['resolution']}")

    print("\n" + "=" * 60)
    print("TEST 3: Ransomware encryption")
    print("=" * 60)
    results = search_similar("Files encrypted with locked extension and ransom note dropped")
    for r in results:
        print(f"  [{r['score']}] {r['alert_id']} | {r['alert_type']} | {r['resolution']}")