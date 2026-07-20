def run_backup(filename):
    import subprocess
    subprocess.call(f"tar -czf backup.tar.gz {filename}", shell=True)