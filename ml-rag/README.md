# ML/RAG Module — SOC AI Agent

**Author:** Dagmawi
**Status:** MVP Complete  
**Last Updated:** October 8, 2026

---

## Overview

The **ML/RAG Module** is responsible for adding machine learning and retrieval-augmented generation capabilities to the SOC AI Agent.

It provides two core capabilities:

1. **Retrieval-Augmented Generation (RAG)**  
   Retrieves relevant historical security incidents from **Qdrant Vector Database** and provides them as additional context for the LLM.

2. **False-Positive Classification**  
   Uses an **XGBoost classifier** to predict whether an alert is likely **benign or malicious**, helping SOC analysts prioritize alerts and identify candidates for automated closure.

---

## Architecture

```text
                    Incoming Alert
                          │
                          ▼
                ┌───────────────────┐
                │   ML/RAG Module   │
                └─────────┬─────────┘
                          │
             ┌────────────┴────────────┐
             │                         │
             ▼                         ▼
     ┌─────────────────┐      ┌─────────────────┐
     │  XGBoost Model  │      │   RAG Pipeline  │
     │                 │      │                 │
     │ Benign/Malicious│      │ Query Qdrant    │
     │ Classification  │      │ for similar     │
     └────────┬────────┘      │ incidents       │
              │               └────────┬────────┘
              │                        │
              ▼                        ▼
      Classification             Similar Historical
          Result                   Incidents
              │                        │
              └───────────┬────────────┘
                          │
                          ▼
                    ┌─────────────┐
                    │ LLM / Agent │
                    │   Context   │
                    └──────┬──────┘
                           │
                           ▼
                  Investigation Result
```

---

## 1. RAG Pipeline

The RAG component retrieves historical incidents that are semantically similar to the incoming alert.

### Workflow

```text
Incoming Alert
      │
      ▼
Generate Embedding
      │
      ▼
Search Qdrant
      │
      ▼
Retrieve Similar Incidents
      │
      ▼
Build Context
      │
      ▼
Provide Context to LLM
```

### Purpose

Historical incidents can provide useful context when investigating a new alert.

For example:

```text
New Alert:
Suspicious PowerShell execution
        │
        ▼
Qdrant Search
        │
        ├── Previous PowerShell C2 incident
        ├── Previous legitimate PowerShell maintenance
        └── Previous malicious PowerShell download
        │
        ▼
LLM receives historical context
        │
        ▼
Improved investigation/recommendation
```

The RAG system therefore allows the agent to use previous investigations as contextual evidence rather than relying only on the LLM's general knowledge.

---

## 2. False-Positive Classifier

The classification component uses **XGBoost** to predict whether an alert is:

- `Benign`
- `Malicious`

The classifier is intended to help prioritize incoming alerts and identify alerts that may be safely auto-closed when confidence is sufficiently high.

### Workflow

```text
Incoming Alert
      │
      ▼
Feature Extraction
      │
      ▼
XGBoost Classifier
      │
      ├───────────────┐
      ▼               ▼
   Benign          Malicious
      │               │
      ▼               ▼
Check Confidence    Investigate
      │
      ▼
High-confidence
Benign?
      │
   ┌──┴──┐
  Yes    No
   │      │
   ▼      ▼
Auto-     Human /
Close     Agent Review
```

---

## Model Output

The classifier produces a prediction and confidence score.

Example:

```json
{
  "prediction": "benign",
  "confidence": 0.94
}
```

A high-confidence benign prediction can be considered for automatic closure according to the project's configured threshold.

> **Important:** Auto-closure should use a conservative confidence threshold and should be validated against false-negative rates before being enabled in production.

---

## Evaluation

The classifier is evaluated using a confusion matrix and standard classification metrics.

Example:

```text
                  Predicted
                Benign  Malicious

Actual Benign      1        2
Actual Malicious   1        6
```

From this example:

| Metric | Result |
|---|---:|
| Accuracy | 70% |
| Precision | 75% |
| Recall | 85.7% |

For a SOC environment, **recall is particularly important** because a false negative represents a malicious alert incorrectly classified as benign.

---

## Technology Stack

| Component | Technology |
|---|---|
| Machine Learning | XGBoost |
| Vector Database | Qdrant |
| RAG | Retrieval-Augmented Generation |
| LLM | Project-configured LLM |
| Language | Python |

---

## Role in the SOC AI Agent

The ML/RAG module sits between incoming security alerts and the agent's reasoning layer.

Its primary responsibilities are:

```text
Alert
  │
  ├──► ML Classification
  │       └──► Benign / Malicious
  │
  └──► RAG Retrieval
          └──► Similar Historical Incidents
                    │
                    ▼
              Agent / LLM
                    │
                    ▼
          Investigation & Response
```

This allows the SOC AI Agent to combine:

- **Machine learning predictions**
- **Historical incident knowledge**
- **Vector similarity search**
- **LLM reasoning**
- **SOC investigation context**

---

## Current Status

### MVP — Complete

- [x] XGBoost classification pipeline
- [x] Benign/Malicious prediction
- [x] Confidence scoring
- [x] Confusion matrix evaluation
- [x] Qdrant vector search
- [x] Historical incident retrieval
- [x] RAG context generation
- [x] Integration-ready output for the SOC agent

---

## Future Improvements

### Machine Learning

- Expand the training dataset
- Add more realistic SOC telemetry
- Improve feature engineering
- Address class imbalance
- Tune XGBoost hyperparameters
- Perform cross-validation
- Evaluate precision, recall, F1-score and ROC-AUC
- Monitor false negatives
- Calibrate prediction confidence

### RAG

- Improve incident chunking
- Add metadata filtering
- Add MITRE ATT&CK metadata
- Improve embedding quality
- Add hybrid search
- Evaluate retrieval precision/recall
- Add source attribution to retrieved incidents

### SOC Automation

- Introduce conservative auto-close thresholds
- Add human-in-the-loop review
- Log model decisions
- Track false positives and false negatives
- Implement model/version tracking
- Continuously update the historical incident database

---

## Security Considerations

The classifier should **not automatically close alerts solely because the model predicts `Benign`**.

Before enabling automatic closure, the system should establish an acceptable false-negative rate and use a conservative confidence threshold.

High-risk alerts should remain subject to investigation regardless of the ML prediction.

---

## Module Goal

The ultimate goal of this module is to help the SOC AI Agent answer:

> **"Have we seen something like this before, and how likely is this alert to represent a real security incident?"**

By combining **XGBoost classification** with **historical incident retrieval through Qdrant**, the module provides the agent with both a predictive signal and relevant historical context for faster SOC investigations.

## Files in This Module

| File | Purpose |
|---|---|
| `rag_pipeline.py` | RAG pipeline — embed + ingest + retrieve |
| `historical_alerts.csv` | 50 historical incidents (training + RAG data) |
| `train_classifier.py` | Trains the XGBoost classifier |
| `classifier_inference.py` | Inference API for the trained classifier |
| `fp_classifier.pkl` | Trained XGBoost model (generated) |
| `alert_type_encoder.pkl` | Fitted LabelEncoder (generated) |
| `requirements.txt` | Python dependencies |
| `README.md` | This file |