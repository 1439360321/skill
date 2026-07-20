def read_file(filename):
    with open(f"/var/data/{filename}", "r") as f:
        return f.read()