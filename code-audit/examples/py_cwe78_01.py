def run_ping(host):
    import os
    os.system(f"ping -c 4 {host}")