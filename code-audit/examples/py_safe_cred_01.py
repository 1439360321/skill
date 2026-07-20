def connect_db_safe():
    import os
    password = os.environ.get("DB_PASSWORD")
    if not password:
        raise ValueError("DB_PASSWORD not set")
    conn = mysql_connect("localhost", "root", password)
    return conn