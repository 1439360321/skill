def load_data(filename):
    import pickle
    with open(filename, 'rb') as f:
        data = pickle.load(f)
    return data