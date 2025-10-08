 [cite\_start]It rebrands the system as a **Hybrid WAAP (Web Application and API Protection)**, incorporating the RASP agent as the critical second layer of defense and directly addressing the limitations (False Negatives) identified in your synopsis[cite: 13, 14].

-----

# 🛡️⚛️ Hybrid WAAP (Adaptive WAF + Conceptual RASP)

This project implements a cutting-edge **Hybrid Web Application and API Protection (WAAP)**. It integrates a high-accuracy, deep-learning perimeter defense (the Adaptive WAF) with an in-application execution monitor (the Conceptual RASP Agent) to provide comprehensive protection against both known attack patterns and zero-day execution flaws.

[cite\_start]The system is designed to provide **Adaptive Resilience** [cite: 38] [cite\_start]by having a self-learning WAF that is backed by a final, un-bypassable RASP layer, resulting in a robust, self-learning prototype[cite: 36].

## 🛡️ Key Hybrid Features

  * **Two-Stage Hybrid Architecture (WAAP):** The system implements a complete defense chain:
    1.  [cite\_start]**Stage 1 (Perimeter):** The Adaptive WAF (DistilBERT + XAI Rules) classifies the HTTP request based on its payload and headers[cite: 17].
    2.  [cite\_start]**Stage 2 (Execution):** If the WAF **ALLOWS** the request, the **Conceptual RASP Agent** monitors the application's critical functions, blocking malicious code *before* it executes[cite: 16].
  * [cite\_start]**RASP for False Negative (FN) Mitigation:** The RASP layer is the primary defense against the **41 False Negatives** [cite: 13, 33] recorded by the WAF model, ensuring protection against obfuscated payloads that bypass the perimeter defense.
  * [cite\_start]**Adaptive Human-in-the-Loop (HITL):** Requests with ambiguous scores ($\mathbf{0.50 \le S \le 0.95}$) are routed for human review [cite: 19][cite\_start], enabling continuous model retraining and rapid patching of the static rules[cite: 21, 34].
  * [cite\_start]**High Performance:** Uses the efficient **DistilBERT** variant to ensure real-time response times[cite: 32].

## 🚀 Project Structure

The RASP logic is conceptually integrated directly into the `app.py` as Python decorators and policy checks on a simulated sensitive function.

```
hybrid_waap/
├── app.py                      # Flask application, WAF prediction, and RASP logic
├── best_student_waf_model.pt   # **Trained PyTorch Model Checkpoint** (WAF ML)
├── waf_xai_rules.txt           # **XAI Decision Tree Rules** (WAF Fast Filter)
└── README.md
```

## ⚙️ Installation and Setup

1.  **Prerequisites:** Python 3.10+ (Python 3.11 was used during development).
2.  **Dependencies:** Install all necessary libraries:
    ```bash
    (venv) pip install flask numpy torch transformers scikit-learn
    ```
3.  **Model Files:** The application requires the trained model files (`best_student_waf_model.pt` and `waf_xai_rules.txt`). If these files are missing, the WAF will fail to initialize and switch to a rule-based **DEMO MODE**.

## ▶️ Running the WAAP Simulator

Start the Flask server:

```bash
(venv) python app.py
```

The console output will confirm the operating mode and provide the server URL:

```
============================================================
🛡️ ⚛️ HYBRID WAAP SIMULATOR (WAF + RASP) STARTING
============================================================
Mode: DEMO (Simulated WAF rules for demonstration)
Server: http://127.0.0.1:5000
```

Open your browser and navigate to `http://127.0.0.1:5000` to access the simulator interface.

## 🧠 WAAP Defense Chain Logic

[cite\_start]The system functions as a sequential security pipeline, ensuring **Superior Security**[cite: 37]:

### Stage 1: Adaptive WAF Decision (Perimeter)

The WAF (ML/XAI) filters traffic based on the anomaly score ($S$):

| Anomaly Score (S) | WAF Decision | Action | Next Step |
| :--- | :--- | :--- | :--- |
| **S \> 0.95** | **BLOCK** | High Confidence Attack | Traffic Dropped. **RASP is not engaged.** |
| **0.50 ≤ S ≤ 0.95** | **HUMAN REVIEW** | Ambiguous/Adaptive Region | Traffic Dropped/Held. **RASP is not engaged.** |
| **S \< 0.50** | **ALLOW** | High Confidence Normal | **Traffic passed to RASP layer.** |

### Stage 2: Conceptual RASP Policy (Execution)

Only traffic that the WAF **ALLOWS** proceeds to the application backend, where the RASP agent provides the final check:

| WAF Outcome | RASP Action (Conceptual) | Final Outcome | Security Benefit |
| :--- | :--- | :--- | :--- |
| **ALLOW** | **BLOCK** | **RASP BLOCK** | Catches WAF False Negatives/Bypass attempts. |
| **ALLOW** | **ALLOW** | **FINAL ALLOW** | Request is clean at both the perimeter and execution layers. |
