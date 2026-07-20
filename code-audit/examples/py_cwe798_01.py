def connect_db():
    password = "admin123"
    conn = mysql_connect("localhost", "root", password)
    return conn