import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import os
import json
import re
from flask import Flask, request, jsonify, render_template_string

# --- 1. Model Configuration ---
BEST_MODEL_PATH = 'best_student_waf_model.pt'
XAI_RULES_PATH = 'waf_xai_rules.txt'
TOKENIZER_NAME = 'bert-base-uncased'
MAX_LENGTH = 512
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# Adaptive WAF Thresholds
BLOCK_THRESHOLD = 0.95
REVIEW_THRESHOLD = 0.50

# --- 2. PyTorch Model Definition ---
class StudentDistilBERT(nn.Module):
    def __init__(self, model_name='distilbert-base-uncased', num_classes=2, dropout=0.1):
        super(StudentDistilBERT, self).__init__()
        try:
            from transformers import DistilBertModel
            self.distilbert = DistilBertModel.from_pretrained(model_name)
        except:
            self.distilbert = None
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(768, num_classes)
        
    def forward(self, input_ids, attention_mask):
        if self.distilbert is None:
            raise RuntimeError("DistilBERT model not loaded")
        outputs = self.distilbert(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs.last_hidden_state[:, 0]
        pooled_output_dropped = self.dropout(pooled_output)
        logits = self.classifier(pooled_output_dropped)
        return logits, pooled_output

# --- 3. Flask Application Setup ---
app = Flask(__name__)
model = None
tokenizer = None
xai_rules_loaded = False
demo_mode = False  # Flag for demo/fallback mode

def load_waf_model():
    """Initializes and loads the trained DistilBERT model and tokenizer."""
    global model, tokenizer, xai_rules_loaded, demo_mode

    try:
        print(f"🔍 Checking for model file: {BEST_MODEL_PATH}")
        print(f"📂 Current directory: {os.getcwd()}")
        print(f"📁 Files in directory: {os.listdir('.')}")
        
        if not os.path.exists(BEST_MODEL_PATH):
            print(f"❌ Model file '{BEST_MODEL_PATH}' not found. Switching to DEMO MODE.")
            demo_mode = True
            return False
        
        print(f"✅ Model file found! Size: {os.path.getsize(BEST_MODEL_PATH)} bytes")
        print(f"🔄 Loading tokenizer...")
        
        from transformers import BertTokenizer
        tokenizer = BertTokenizer.from_pretrained(TOKENIZER_NAME)
        print(f"✅ Tokenizer loaded successfully!")
        
        print(f"🔄 Loading model checkpoint...")
        checkpoint = torch.load(BEST_MODEL_PATH, map_location=DEVICE, weights_only=False)
        print(f"✅ Checkpoint loaded! Keys: {list(checkpoint.keys())}")
        
        num_classes = len(checkpoint['label_encoder'].classes_)
        print(f"📊 Number of classes: {num_classes}")
        print(f"🏷️ Classes: {checkpoint['label_encoder'].classes_}")
        
        print(f"🔄 Initializing model architecture...")
        model = StudentDistilBERT(num_classes=num_classes)
        
        print(f"🔄 Loading model weights...")
        model.load_state_dict(checkpoint['model_state_dict'])
        model.to(DEVICE)
        model.eval()
        
        print(f"✅ WAF Model loaded successfully on {DEVICE}!")
        print(f"🔧 Model architecture: {checkpoint.get('model_architecture', 'Unknown')}")
        
        if os.path.exists(XAI_RULES_PATH):
            xai_rules_loaded = True
            print(f"✅ XAI Rules file '{XAI_RULES_PATH}' found. Fast filter enabled.")
        else:
            print(f"⚠️ XAI Rules file '{XAI_RULES_PATH}' not found. Using full ML only.")

        return True

    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print(f"⚠️ Make sure 'transformers' library is installed: pip install transformers")
        demo_mode = True
        return False
    except KeyError as e:
        print(f"❌ KeyError loading checkpoint: {e}")
        print(f"⚠️ The checkpoint file may be corrupted or from a different version.")
        demo_mode = True
        return False
    except Exception as e:
        print(f"❌ Unexpected error loading model: {type(e).__name__}: {e}")
        import traceback
        print(f"📋 Full traceback:")
        traceback.print_exc()
        print(f"⚠️ Switching to DEMO MODE with rule-based detection.")
        demo_mode = True
        return False

is_model_loaded = load_waf_model()

# --- 4a. XAI Fast Rule Execution Logic ---
def execute_xai_rules(cls_features_tensor):
    """Executes XAI Decision Tree rules on CLS features."""
    if not xai_rules_loaded:
        return 'ML_REQUIRED'

    f512 = cls_features_tensor[0, 512].item()
    f120 = cls_features_tensor[0, 120].item()
    f680 = cls_features_tensor[0, 680].item()
    f421 = cls_features_tensor[0, 421].item()
    f33 = cls_features_tensor[0, 33].item()

    if f512 <= -0.01:
        if f120 <= 0.0:
            return 'ALLOW_XAI'
        else:
            if f680 <= 0.0:
                return 'ALLOW_XAI'
            else:
                return 'ML_REQUIRED'
    else:
        if f421 <= 0.01:
            if f33 <= -0.01:
                return 'BLOCK_XAI'
            else:
                return 'ML_REQUIRED'
        else:
            return 'BLOCK_XAI'

# --- 4b. Demo Mode Detection ---
def demo_detect_threat(request_data: dict):
    """Simple rule-based threat detection for demo mode."""
    combined_text = (
        f"{request_data.get('Method', '')} "
        f"{request_data.get('User-Agent', '')} "
        f"{request_data.get('URL', '')} "
        f"{request_data.get('cookie', '')} "
        f"{request_data.get('content', '')}"
    ).lower()
    
    # SQL Injection patterns
    sql_patterns = [
        r'union\s+select', r'or\s+1\s*=\s*1', r';\s*drop\s+table',
        r'--', r'\/\*', r'xp_cmdshell', r'exec\s*\(', r'\'\s+or\s+\''
    ]
    
    # XSS patterns
    xss_patterns = [
        r'<script', r'javascript:', r'onerror\s*=', r'onload\s*=',
        r'<iframe', r'alert\s*\(', r'document\.cookie'
    ]
    
    # Path traversal
    path_patterns = [r'\.\./', r'\.\.\\', r'%2e%2e']
    
    # Command injection
    cmd_patterns = [r';\s*cat\s+', r';\s*ls\s+', r'\|\s*nc\s+', r'&&\s*whoami']
    
    all_patterns = sql_patterns + xss_patterns + path_patterns + cmd_patterns
    
    threat_count = sum(1 for pattern in all_patterns if re.search(pattern, combined_text))
    
    if threat_count >= 2:
        return 1.0, "Multiple attack patterns detected"
    elif threat_count == 1:
        return 0.75, "Suspicious pattern detected"
    elif len(combined_text) > 500:
        return 0.60, "Unusually large request"
    else:
        return 0.15, "Request appears normal"

# --- 4c. WAF Prediction Logic ---
def get_waf_decision(request_data: dict):
    """Predicts classification using Two-Stage Adaptive WAF."""
    
    # Demo Mode Fallback
    if demo_mode:
        anomaly_prob, reason = demo_detect_threat(request_data)
        
        if anomaly_prob > BLOCK_THRESHOLD:
            return {
                "status": "SUCCESS",
                "decision": "BLOCK (Demo Rule Match)",
                "anomaly_score": f"{anomaly_prob:.4f}",
                "color": "red-700",
                "message_detail": f"DEMO MODE: {reason}. Train and load the model for full ML detection."
            }
        elif anomaly_prob >= REVIEW_THRESHOLD:
            return {
                "status": "SUCCESS",
                "decision": "HUMAN REVIEW (Demo - Ambiguous)",
                "anomaly_score": f"{anomaly_prob:.4f}",
                "color": "orange-500",
                "message_detail": f"DEMO MODE: {reason}. Would be sent for human review in production."
            }
        else:
            return {
                "status": "SUCCESS",
                "decision": "ALLOW (Demo Rule Match)",
                "anomaly_score": f"{anomaly_prob:.4f}",
                "color": "green-700",
                "message_detail": f"DEMO MODE: {reason}. Train and load the model for full ML detection."
            }
    
    # Full ML Mode
    if not is_model_loaded or model is None or tokenizer is None:
        return {
            "status": "ERROR",
            "decision": "UNAVAILABLE",
            "message": "WAF Model is not loaded. Cannot perform prediction."
        }
    
    combined_text = (
        f"Method: {request_data.get('Method', '')} "
        f"User-Agent: {request_data.get('User-Agent', '')} "
        f"URL: {request_data.get('URL', '')} "
        f"cookie: {request_data.get('cookie', '')} "
        f"content: {request_data.get('content', '')}"
    ).strip()
    
    encoding = tokenizer(
        combined_text,
        truncation=True,
        padding='max_length',
        max_length=MAX_LENGTH,
        return_tensors='pt'
    )

    input_ids = encoding['input_ids'].to(DEVICE)
    attention_mask = encoding['attention_mask'].to(DEVICE)

    with torch.no_grad():
        logits, cls_features = model(input_ids, attention_mask)

    # Stage 1: XAI Rules
    xai_decision = execute_xai_rules(cls_features)
    
    if xai_decision == 'BLOCK_XAI':
        return {
            "status": "SUCCESS",
            "decision": "BLOCK (XAI Fast Rule Match)",
            "anomaly_score": "1.0000",
            "color": "red-700",
            "message_detail": "Decision made instantly by lightweight XAI rule engine (Stage 1)."
        }
    elif xai_decision == 'ALLOW_XAI':
        return {
            "status": "SUCCESS",
            "decision": "ALLOW (XAI Fast Rule Match)",
            "anomaly_score": "0.0000",
            "color": "green-700",
            "message_detail": "Decision made instantly by lightweight XAI rule engine (Stage 1)."
        }
    
    # Stage 2: Full ML
    probs = F.softmax(logits, dim=1)
    anomaly_prob = probs[0, 0].item()
    
    if anomaly_prob > BLOCK_THRESHOLD:
        decision = "BLOCK (High Confidence Anomaly)"
        color = "red-700"
        message_detail = f"DistilBERT Stage 2 decision. Score > {BLOCK_THRESHOLD}."
    elif anomaly_prob >= REVIEW_THRESHOLD:
        decision = "HUMAN REVIEW (Ambiguous/Adaptive)"
        color = "orange-500"
        message_detail = f"Ambiguous request (Score {REVIEW_THRESHOLD}-{BLOCK_THRESHOLD}). Sent to analyst queue."
    else:
        decision = "ALLOW (High Confidence Normal)"
        color = "green-700"
        message_detail = f"DistilBERT Stage 2 decision. Score < {REVIEW_THRESHOLD}."

    return {
        "status": "SUCCESS",
        "decision": decision,
        "anomaly_score": f"{anomaly_prob:.4f}",
        "color": color,
        "message_detail": message_detail
    }

# --- 5. Flask Routes ---
@app.route('/', methods=['GET'])
def index():
    """Renders the HTML form for WAF testing."""
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Adaptive DistilBERT WAF Emulator</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .card { box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); }
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
    </style>
</head>
<body class="gradient-bg min-h-screen p-4 md:p-8">

    <div class="w-full max-w-5xl mx-auto bg-white card rounded-2xl p-8 md:p-12">
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-4xl font-extrabold text-gray-900 mb-2">🛡️ Adaptive WAF Simulator</h1>
                <p class="text-gray-600">Two-stage hybrid detection: XAI rules + DistilBERT deep learning</p>
            </div>
            <div class="text-right">
                <span class="inline-block px-4 py-2 rounded-full text-sm font-bold {{ 'bg-green-100 text-green-800' if not demo_mode else 'bg-yellow-100 text-yellow-800' }}">
                    {{ 'ML ACTIVE' if not demo_mode else 'DEMO MODE' }}
                </span>
            </div>
        </div>

        {% if demo_mode %}
        <div class="mb-6 p-4 bg-yellow-50 border-l-4 border-yellow-400 rounded-lg">
            <p class="font-semibold text-yellow-800">⚠️ Demo Mode Active</p>
            <p class="text-sm text-yellow-700 mt-1">Using rule-based detection. Train your model and place <code class="bg-yellow-100 px-1 rounded">best_student_waf_model.pt</code> in the app directory for full ML capabilities.</p>
        </div>
        {% endif %}

        <form id="waf-form" class="space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label for="Method" class="block text-sm font-semibold text-gray-700 mb-2">HTTP Method</label>
                    <input type="text" id="Method" name="Method" value="GET" class="w-full rounded-lg border-2 border-gray-200 focus:border-indigo-500 focus:ring-0 p-3 transition">
                </div>
                <div>
                    <label for="URL" class="block text-sm font-semibold text-gray-700 mb-2">Request URL Path</label>
                    <input type="text" id="URL" name="URL" value="/index.php?id=1" class="w-full rounded-lg border-2 border-gray-200 focus:border-indigo-500 focus:ring-0 p-3 transition">
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label for="User-Agent" class="block text-sm font-semibold text-gray-700 mb-2">User-Agent</label>
                    <input type="text" id="User-Agent" name="User-Agent" value="Mozilla/5.0" class="w-full rounded-lg border-2 border-gray-200 focus:border-indigo-500 focus:ring-0 p-3 transition">
                </div>
                <div>
                    <label for="cookie" class="block text-sm font-semibold text-gray-700 mb-2">Cookie Header</label>
                    <input type="text" id="cookie" name="cookie" value="" class="w-full rounded-lg border-2 border-gray-200 focus:border-indigo-500 focus:ring-0 p-3 transition">
                </div>
            </div>

            <div>
                <label for="content" class="block text-sm font-semibold text-gray-700 mb-2">Request Body / Payload</label>
                <textarea id="content" name="content" rows="5" class="w-full rounded-lg border-2 border-gray-200 focus:border-indigo-500 focus:ring-0 p-3 transition font-mono text-sm" placeholder="Enter attack payload here..."></textarea>
                <p class="text-xs text-gray-500 mt-2">💡 Try: <code class="bg-gray-100 px-2 py-1 rounded">1 UNION SELECT 1,2,3 FROM users</code> or <code class="bg-gray-100 px-2 py-1 rounded">&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
            </div>

            <button type="submit" class="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-bold py-4 px-6 rounded-xl hover:from-indigo-700 hover:to-purple-700 transform hover:scale-105 transition-all duration-200 shadow-lg">
                🔍 Analyze Request
            </button>
        </form>

        <div id="result-box" class="mt-8 p-6 rounded-xl border-2 border-gray-200 hidden">
            <h3 class="text-2xl font-bold mb-4 text-gray-800">🎯 WAF Decision</h3>
            <div class="space-y-4">
                <div class="flex items-center gap-3">
                    <span class="text-sm font-semibold text-gray-600">Decision:</span> 
                    <span id="decision-text" class="text-base font-bold px-4 py-2 rounded-lg"></span>
                </div>
                <div class="flex items-center gap-3">
                    <span class="text-sm font-semibold text-gray-600">Anomaly Score:</span> 
                    <span id="anomaly-score" class="font-mono text-xl font-bold text-gray-900"></span>
                </div>
                <div class="bg-gray-50 p-4 rounded-lg">
                    <p id="message-text" class="text-sm text-gray-700 leading-relaxed"></p>
                </div>
            </div>
        </div>
    </div>

    <script>
        const form = document.getElementById('waf-form');
        const resultBox = document.getElementById('result-box');
        const decisionText = document.getElementById('decision-text');
        const anomalyScore = document.getElementById('anomaly-score');
        const messageText = document.getElementById('message-text');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(form);
            const requestData = Object.fromEntries(formData.entries());

            resultBox.classList.add('hidden');
            decisionText.textContent = 'Analyzing...';
            decisionText.className = 'text-base font-bold px-4 py-2 rounded-lg bg-gray-300 text-gray-700';

            try {
                const response = await fetch('/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(requestData)
                });

                const result = await response.json();

                if (result.status === 'ERROR') {
                    decisionText.textContent = 'ERROR';
                    decisionText.className = 'text-base font-bold px-4 py-2 rounded-lg bg-red-700 text-white';
                    messageText.textContent = result.message;
                    anomalyScore.textContent = 'N/A';
                } else {
                    decisionText.textContent = result.decision;
                    anomalyScore.textContent = result.anomaly_score;
                    decisionText.className = `text-base font-bold px-4 py-2 rounded-lg bg-${result.color} text-white`;
                    messageText.textContent = result.message_detail;
                }

                resultBox.classList.remove('hidden');

            } catch (error) {
                console.error('Error:', error);
                decisionText.textContent = 'NETWORK ERROR';
                decisionText.className = 'text-base font-bold px-4 py-2 rounded-lg bg-red-900 text-white';
                messageText.textContent = 'Failed to connect to WAF engine.';
                resultBox.classList.remove('hidden');
            }
        });
    </script>
</body>
</html>
"""
    return render_template_string(html_template, demo_mode=demo_mode)

@app.route('/predict', methods=['POST'])
def predict():
    """Endpoint to receive request data and return WAF decision."""
    data = request.get_json()
    if data is None:
        return jsonify({"status": "ERROR", "message": "Invalid JSON input."}), 400
        
    decision = get_waf_decision(data)
    return jsonify(decision)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  ADAPTIVE WAF SIMULATOR STARTING")
    print("="*60)
    print(f"Mode: {'FULL ML' if not demo_mode else 'DEMO (Rule-based)'}")
    print(f"Device: {DEVICE}")
    print(f"Server: http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)