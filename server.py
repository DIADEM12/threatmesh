from flask import Flask, jsonify, send_file, request
import json
import subprocess
import os
import threading

app = Flask(__name__)
pipeline_lock = threading.Lock()

def read_json(filepath, default):
    try:
        with open(filepath) as f:
            return json.load(f)
    except FileNotFoundError:
        return default

@app.route('/')
def index():
    return send_file('frontend/index.html')

@app.route('/api/log')
def get_log():
    return jsonify(read_json('transaction_log.json', []))

@app.route('/api/events')
def get_events():
    return jsonify(read_json('events.json', []))

@app.route('/api/listings')
def get_listings():
    return jsonify(read_json('marketplace/listings.json', []))

@app.route('/api/scanner')
def get_scanner():
    return jsonify(read_json('scanner_state.json', {"enabled": False}))

@app.route('/api/wallets')
def get_wallets():
    return jsonify(read_json('wallets.json', {}))

@app.route('/api/run', methods=['POST'])
def run_pipeline():
    body = request.get_json() or {}
    mode = body.get('mode', 'push')

    def run():
        with pipeline_lock:
            env = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
            if mode == 'push':
                with open('pipeline_mode.json', 'w') as f:
                    json.dump({'mode': 'push'}, f)
                for agent in ['sensor', 'enrichment', 'verification']:
                    subprocess.run(['python', f'agents/{agent}_agent.py'], env=env)
                subprocess.run(['python', 'agents/consumer_agent.py', 'push'], env=env)
            elif mode == 'pull':
                subprocess.run(['python', 'agents/consumer_agent.py', 'pull'], env=env)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'status': 'ok'})

@app.route('/api/scanner/toggle', methods=['POST'])
def toggle_scanner():
    body = request.get_json() or {}
    enabled = body.get('enabled', False)
    with open('scanner_state.json', 'w') as f:
        json.dump({'enabled': enabled}, f)
    return jsonify({'enabled': enabled})

if __name__ == '__main__':
    print('ThreatMesh dashboard running at http://localhost:8000')
    app.run(host='0.0.0.0', port=8000, threaded=True, debug=False)