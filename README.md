# adaptive-_firewall
Adaptive WAF Simulator (DistilBERT + XAI)
This project implements an Adaptive Web Application Firewall (WAF) Simulator using a two-stage machine learning architecture. It combines a powerful, deep-learning language model (DistilBERT) with explainable AI (XAI) rules derived from the model's feature space to create a WAF that is both highly accurate and highly performant.

The system is designed to produce three distinct outcomes for every request: BLOCK, ALLOW, or HUMAN REVIEW (for ambiguous, adaptive cases).

🛡️ Key Features
Two-Stage Architecture: Requests are first processed by a Fast XAI Rule Filter (for high-confidence decisions) and only passed to the Full DistilBERT ML Model if the outcome is ambiguous.

Explainable AI (XAI): Uses a simple Decision Tree (extracted from the deep learning model's feature space) for instant, explainable, and high-confidence filtering.

Adaptive Thresholds: Implements a Human Review Queue for requests falling into the ambiguous probability range (e.g., 0.50≤Score≤0.95), facilitating continuous model improvement and adaptation.

Single-File Flask App: The core WAF logic is contained within a single app.py file for easy deployment and testing.

🚀 Project Structure
adaptive waf/
├── app.py                      # Flask application and WAF prediction logic
├── best_student_waf_model.pt   # **Trained PyTorch Model Checkpoint** (Required)
├── waf_xai_rules.txt           # **XAI Decision Tree Rules** (Required for Fast Filter)
└── README.md                   # This file

⚙️ Installation and Setup
1. Prerequisites
Python 3.10 or higher (Python 3.11 was used during development)

pip for package management

2. Clone Repository & Navigate
First, navigate to your desired directory and clone this project:

git clone [YOUR_REPOSITORY_URL]
cd adaptive\ waf

3. Create and Activate Virtual Environment
It is highly recommended to use a virtual environment to manage dependencies.

# Create the environment
python -m venv venv

# Activate the environment (using PowerShell)
.\venv\Scripts\Activate.ps1

# OR Activate the environment (using Command Prompt/CMD)
venv\Scripts\activate

4. Install Dependencies
Install all necessary libraries, including PyTorch, Hugging Face transformers, and scikit-learn (which is needed to load the LabelEncoder saved in the model checkpoint):

(venv) pip install flask numpy torch transformers scikit-learn

⚠️ Critical Step: Model Files
The application requires the trained model files to be present. Download the following files and place them directly into the root of the project directory (adaptive waf/):

best_student_waf_model.pt

waf_xai_rules.txt

If these files are missing, the WAF will fail to initialize and show a "Model is not loaded" error.

▶️ Running the WAF Simulator
Once all dependencies and model files are installed, start the Flask server:

(venv) python app.py

The console output will confirm the model and XAI rules are loaded successfully, and provide the server URL:

✅ WAF Model 'StudentDistilBERT' loaded successfully!
✅ XAI Rules file 'waf_xai_rules.txt' found. Fast filter enabled.
...
* Running on [http://127.0.0.1:5000](http://127.0.0.1:5000)

Open your browser and navigate to http://127.0.0.1:5000 to access the WAF simulator interface.

🧠 WAF Decision Logic
The app.py uses the following thresholds on the anomaly score (probability of attack, where 1.0 is highest confidence) to determine the action:

Anomaly Score (S)

Decision

Action

S>0.95

BLOCK

High Confidence Attack

0.50≤S≤0.95

HUMAN REVIEW

Ambiguous/Adaptive Region

S<0.50

ALLOW

High Confidence Normal

The XAI Rule Filter accelerates this process by quickly resolving requests that fall clearly into the high-confidence BLOCK or ALLOW zones, avoiding the full ML model calculation when possible.
UI:-
Screenshot (14).png
