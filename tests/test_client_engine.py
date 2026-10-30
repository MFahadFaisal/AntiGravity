import pytest
import os
import subprocess
import json
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
JS_ENGINE_PATH = os.path.join(PROJECT_ROOT, "browser_agent", "antigravity_client_engine.js")
ONNX_PATH = os.path.join(PROJECT_ROOT, "ai_engine", "antigravity_url_model.onnx")

def test_js_client_engine_exists():
    assert os.path.exists(JS_ENGINE_PATH), "antigravity_client_engine.js must be generated"
    assert os.path.getsize(JS_ENGINE_PATH) > 100_000, "JS engine bundle must contain embedded model weights"

def test_js_client_engine_prediction():
    node_script = f"""
    const Engine = require('{JS_ENGINE_PATH}');
    const urls = [
        {{ url: 'https://www.apple.com/iphone/', expected: 'safe' }},
        {{ url: 'http://paypal-security-update-center.com/login.php?verify=1', expected: 'block' }},
        {{ url: 'http://192.168.1.100/admin/auth.php', expected: 'block' }}
    ];

    const results = urls.map(u => ({{
        url: u.url,
        expected: u.expected,
        actual: Engine.predict(u.url).status,
        score: Engine.predict(u.url).url_score,
        vecLen: Engine.extractFeaturesVector(u.url).length
    }}));

    console.log(JSON.stringify(results));
    """

    res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    results = json.loads(res.stdout)

    for item in results:
        assert item["vecLen"] == 32, f"Feature vector length must be 32, got {item['vecLen']}"
        assert item["actual"] == item["expected"], f"URL {item['url']} expected {item['expected']}, got {item['actual']}"

def test_onnx_model_inference():
    import onnxruntime as ort

    assert os.path.exists(ONNX_PATH), "antigravity_url_model.onnx must exist"
    sess = ort.InferenceSession(ONNX_PATH)

    input_name = sess.get_inputs()[0].name
    assert sess.get_inputs()[0].shape == [None, 32], "Input tensor shape must be [None, 32]"

    # Test batch evaluation
    dummy_input = np.zeros((3, 32), dtype=np.float32)
    outs = sess.run(None, {input_name: dummy_input})

    assert len(outs) >= 1, "ONNX model must generate output tensors"
    # Output 0 is labels [batch_size], Output 1 is probabilities [batch_size, 2]
    assert outs[0].shape[0] == 3
