import sqlite3

conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('SELECT id, name, email FROM users')
users = cursor.fetchall()

if users:
    print(f"{'ID':<5} {'Name':<25} {'Email'}")
    print('-' * 50)
    for user in users:
        print(f"{user[0]:<5} {user[1]:<25} {user[2]}")
else:
    print("No users found in the database.")

conn.close() 