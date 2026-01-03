# 🛡️ Hybrid WAAP Simulator: Adaptive WAF & Conceptual RASP

### *Next-Gen Zero-Day Defense using Cross-Attention Transformers & Runtime Protection*

## 📖 Overview

The **Hybrid WAAP (Web Application & API Protection) Simulator** is a dual-layer security framework designed to mitigate the "False Negative" problem in traditional WAFs.

Unlike standard regex-based firewalls, this project fuses **Deep Learning (Perimeter Defense)** with **RASP (Execution Defense)** to create a self-healing security pipeline. It features a novel **"Inspector" Architecture**—a BERT-based model using **Cross-Attention** to scan distinct HTTP components (URL, Headers, Body) for subtle anomaly patterns, providing state-of-the-art detection with full explainability.

## 🚀 Key Innovation: The "Inspector" Architecture

Most AI WAFs treat an HTTP request as a single long string. We take a **Multi-View** approach:

1. **Segmentation:** The request is split into 8 independent feature columns (`Method`, `URL`, `User-Agent`, `Cookie`, `Body`, etc.).
2. **The "Inspector" Query:** A learned, distinct vector (the "Inspector") uses **Cross-Attention** to scan these features simultaneously.
3. **Explainability:** The model outputs **Attention Weights**, allowing us to visualize exactly *which* part of the request triggered the block (e.g., *"Blocked due to 98% suspicion in the User-Agent field"*).

## 🏗️ System Architecture

### 🛡️ Layer 1: Adaptive WAF (Perimeter)

* **Model:** Distilled BERT (Student) trained via Knowledge Distillation from a `bert-base` Teacher.
* **Mechanism:** Cross-Attention Transformer.
* **Performance:** ~96.68% Accuracy on CSIC 2010 Dataset.
* **Optimization:** Model size reduced from **440MB → ~110MB** for real-time inference.

### 💉 Layer 2: Conceptual RASP (Internal)

* **Mechanism:** Python Decorator-based instrumentation (`@rasp_policy_decorator`).
* **Function:** Hooks into sensitive application functions (e.g., Database Queries).
* **Defense:** Inspects payloads *at the point of execution*. If a sophisticated attack bypasses the WAF (Layer 1), the RASP agent catches the malicious SQL syntax before it executes.

## 🛠️ Tech Stack

* **Core AI:** PyTorch, Hugging Face Transformers (`bert-base-uncased`, `bert-small`).
* **Backend:** Flask (Python).
* **Data Processing:** Pandas, Scikit-Learn.
* **Visualization:** Matplotlib, Seaborn (for Attention Heatmaps).
* **Techniques:** Knowledge Distillation, Cross-Attention, Dynamic Quantization.

## 📊 Results & Explainability

The system provides real-time feedback on *why* a request was blocked.

| Metric | Performance |
| --- | --- |
| **Accuracy** | 97.96% (Teacher), 96.68% (Student) |
| **Inference Time** | < 20ms |
| **Model Size** | 110 MB (Compressed) |

**Sample Attention Output:**

> *Request Blocked. The Inspector focused 92% attention on the `Payload` column containing SQL injection patterns.*

## ⚡ Quick Start

1. **Clone the Repository**
```bash
git clone https://github.com/yourusername/hybrid-waap-simulator.git
cd hybrid-waap-simulator

```


2. **Install Dependencies**
```bash
pip install torch transformers flask pandas scikit-learn

```


3. **Run the Simulator**
```bash
python app.py

```


*Access the dashboard at `http://localhost:5000*`

## 🔮 Future Work

* **Reinforcement Learning:** allowing the RASP agent to auto-label blocked requests to retrain the WAF (Feedback Loop).
* **GraphQL Support:** extending the tokenizer to handle nested GraphQL queries.

--- 
jay piyushbhai joshi
*Created by [Your Name]*
