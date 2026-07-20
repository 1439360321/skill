def run_ping_safe(host):
    import subprocess
    allowed = {"localhost", "127.0.0.1", "8.8.8.8"}
    if host not in allowed:
        raise ValueError("Host not allowed")
    subprocess.run(["ping", "-c", "4", host], check=True)