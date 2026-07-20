def load_data_safe(filename):
    import json
    with open(filename, 'r') as f:
        data = json.load(f)
    return data