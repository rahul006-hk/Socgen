import subprocess
import sys
import os

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"

def run_command(command, description):
    print(f"\n{description}...")
    try:
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        process = subprocess.Popen(command, shell=True, env=env)
        process.communicate()
        if process.returncode != 0:
            print(f"❌ Error during: {description}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to execute {description}: {e}")
        sys.exit(1)

def main():
    print("=" * 60)
    print(" SOCGEN DRIFTSHIELD AUTOMATED LIFECYCLE INITIALIZER  ")
    print("=" * 60)

    
    run_command(
        f'"{sys.executable}" -m pip install streamlit pandas scikit-learn plotly networkx pytest',
        "Installing enterprise framework dependencies"
    )

    print("\n🧹 Flushing local Streamlit cache architectures...")
    try:
        subprocess.run("streamlit cache clear", shell=True, input=b"y\n", stdout=subprocess.DEVNULL)
        print("✅ Cache cleared successfully.")
    except Exception:
        pass  

    run_command(
        f'"{sys.executable}" generate-data.py',
        "Running corporate data generator (generate-data.py)"
    )

    run_command(
        f'"{sys.executable}" engine.py',
        "Executing analysis prediction matrix (engine.py)"
    )

    run_command(
        f'"{sys.executable}" -m pytest tests/ -q',
        "Executing automated quality verification test suite (tests/)"
    )

  
    run_command(
        "streamlit run app.py",
        "Launching Driftshield UI Console (app.py)"
    )

if __name__ == "__main__":
    main()