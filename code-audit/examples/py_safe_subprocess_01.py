def run_backup_safe(filename):
    import subprocess
    import os
    safe_name = os.path.basename(filename)
    subprocess.run(["tar", "-czf", "backup.tar.gz", safe_name], check=True)