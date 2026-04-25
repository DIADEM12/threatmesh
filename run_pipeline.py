import sys
import os
import subprocess
import time
import json

LOG_FILE = "transaction_log.json"

def run_agent(agent_name, args=""):
    """Run a single agent and return its output"""
    cmd = ["python", f"agents/{agent_name}_agent.py"]
    if args:
        cmd.append(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"[ERROR] {agent_name} agent failed:")
        print(result.stderr)
        return False
    return True

def run_push_pipeline():
    """
    MODE 1 - PUSH: Sensor detects threat and sells it downstream.
    Flow: Sensor -> Enrichment -> Verification -> Consumer
    """
    print("=" * 55)
    print("PUSH MODE - Sensor detected threat, initiating sale")
    print("=" * 55)

    # Set pipeline to push mode
    with open("pipeline_mode.json", "w") as f:
        json.dump({"mode": "push"}, f)

    # Run each agent in sequence
    for agent in ["sensor", "enrichment", "verification"]:
        success = run_agent(agent)
        if not success:
            return False
        time.sleep(1)

    # Consumer runs in push mode (default)
    success = run_agent("consumer", "push")
    return success

def run_pull_pipeline():
    """
    MODE 2 - PULL: Consumer requests intel update.
    Flow: Consumer -> Verification -> Enrichment -> Sensor
          then back: Sensor -> Enrichment -> Verification -> Consumer
    """
    print("=" * 55)
    print("PULL MODE - Consumer requesting intel update")
    print("=" * 55)

    # Consumer kicks off the pull request
    # This internally triggers verification -> enrichment -> sensor
    success = run_agent("consumer", "pull")
    return success

def load_log():
    try:
        with open(LOG_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def print_summary(log):
    """Print final summary of all pipeline runs"""
    print("\n" + "=" * 55)
    print("THREATMESH PIPELINE SUMMARY")
    print("=" * 55)

    push_runs = [r for r in log if r.get("mode") == "push"]
    pull_runs = [r for r in log if r.get("mode") == "pull"]
    purchases = [r for r in log if r.get("action") == "purchased"]
    no_updates = [r for r in log if r.get("action") == "no_update"]

    total_spent = sum(r.get("sale_price", 0) for r in purchases)
    total_spent += sum(r.get("query_fee_paid", 0) for r in log)

    print(f"Total pipeline runs   : {len(log)}")
    print(f"Push mode runs        : {len(push_runs)}")
    print(f"Pull mode runs        : {len(pull_runs)}")
    print(f"Successful purchases  : {len(purchases)}")
    print(f"No update responses   : {len(no_updates)}")
    print(f"Total USDC spent      : ${total_spent:.4f}")
    print(f"Equivalent gas cost   : ~${len(log) * 3 * 0.50:.2f} on Ethereum")
    print(f"Savings               : 99%+")

    if purchases:
        print("\nRevenue distribution across all purchases:")
        total_sensor = sum(r["revenue_share"]["sensor"] for r in purchases)
        total_enrichment = sum(r["revenue_share"]["enrichment"] for r in purchases)
        total_verification = sum(r["revenue_share"]["verification"] for r in purchases)
        print(f"  Sensor Agent      : ${total_sensor:.4f} USDC (50%)")
        print(f"  Enrichment Agent  : ${total_enrichment:.4f} USDC (30%)")
        print(f"  Verification Agent: ${total_verification:.4f} USDC (20%)")

    print("=" * 55)

if __name__ == "__main__":
    # How many of each mode to run
    PUSH_RUNS = 20
    PULL_RUNS = 10

    print("Starting ThreatMesh marketplace pipeline...\n")
    print(f"Running {PUSH_RUNS} push mode cycles and {PULL_RUNS} pull mode cycles\n")

    # Run push cycles
    for i in range(1, PUSH_RUNS + 1):
        print(f"\n--- Push Run {i}/{PUSH_RUNS} ---")
        run_push_pipeline()
        time.sleep(2)

    # Run pull cycles
    for i in range(1, PULL_RUNS + 1):
        print(f"\n--- Pull Run {i}/{PULL_RUNS} ---")
        run_pull_pipeline()
        time.sleep(2)

    # Print final summary
    log = load_log()
    print_summary(log)