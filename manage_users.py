import sqlite3
from werkzeug.security import generate_password_hash

def connect_db():
    return sqlite3.connect('users.db')

def view_users():
    conn = connect_db()
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

def add_user():
    name = input('Enter name: ')
    email = input('Enter email: ')
    password = input('Enter password: ')
    hashed_password = generate_password_hash(password)
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
        conn.commit()
        print('User added successfully!')
    except sqlite3.IntegrityError:
        print('Error: Email already exists.')
    conn.close()

def update_user():
    user_id = input('Enter user ID to update: ')
    print('What do you want to update?')
    print('1. Name')
    print('2. Email')
    choice = input('Enter choice (1/2): ')
    conn = connect_db()
    cursor = conn.cursor()
    if choice == '1':
        new_name = input('Enter new name: ')
        cursor.execute('UPDATE users SET name = ? WHERE id = ?', (new_name, user_id))
        conn.commit()
        print('Name updated successfully!')
    elif choice == '2':
        new_email = input('Enter new email: ')
        try:
            cursor.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user_id))
            conn.commit()
            print('Email updated successfully!')
        except sqlite3.IntegrityError:
            print('Error: Email already exists.')
    else:
        print('Invalid choice.')
    conn.close()

def delete_user():
    user_id = input('Enter user ID to delete: ')
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    if cursor.rowcount:
        print('User deleted successfully!')
    else:
        print('User not found.')
    conn.close()

def main():
    while True:
        print('\nUser Management Menu:')
        print('1. View all users')
        print('2. Add a new user')
        print('3. Update a user')
        print('4. Delete a user')
        print('5. Exit')
        choice = input('Enter your choice: ')
        if choice == '1':
            view_users()
        elif choice == '2':
            add_user()
        elif choice == '3':
            update_user()
        elif choice == '4':
            delete_user()
        elif choice == '5':
            print('Goodbye!')
            break
        else:
            print('Invalid choice. Please try again.')

if __name__ == '__main__':
    main() 