from flask import Flask, request, jsonify, render_template
import subprocess
import signal

app = Flask(__name__)
process = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start():
    global process
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    if process is not None:
        return jsonify({"error": "First stop the previous process"}), 400

    process = subprocess.Popen(
        ["sudo", "./Blitzping/out/blitzping", f"--dest-ip={ip}", "--af-xdp"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    output = []
    for line in process.stdout:
        if line.strip().endswith("Locked memory.") :
            return jsonify({"status": "started", "output": line.strip()})
        else :
            return jsonify({"status": "Invalid IP", "output": line.strip()})
        
@app.route("/stop", methods=["POST"])
def stop():
    global process
    if process is None:
        return jsonify({"error": "Not running"}), 400
    process.send_signal(signal.SIGINT)
    process = None
    return jsonify({"status": "stopped"})

@app.route("/traceroute", methods=["POST"])
def traceroute():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    try:
        result = subprocess.run(
            ["sudo", "./mytraceroute/mytraceroute", ip],
            capture_output=True, text=True, timeout=15
        )
        return jsonify({
            "status": "done",
            "output": result.stdout or result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Traceroute timed out"}), 500

if __name__ == "__main__":
    app.run(debug=True)
