def read_file_safe(filename):
    import os
    safe_path = os.path.normpath(os.path.join("/var/data", filename))
    if not safe_path.startswith("/var/data"):
        raise ValueError("Path traversal detected")
    with open(safe_path, "r") as f:
        return f.read()