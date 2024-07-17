import bcrypt
from getpass import getpass

# Simulated database of users with hashed passwords
users = {
    'george': bcrypt.hashpw(b'123qweasd', bcrypt.gensalt()),
    'narutopta14': bcrypt.hashpw(b'123qweasd', bcrypt.gensalt())
}

def login():
    username = input("Enter username: ")
    password = getpass("Enter password: ")

    stored_hashed_password = users.get(username)

    if not stored_hashed_password:
        print("Incorrect details")
        return

    if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        print("Login successful!")
    else:
        print("Incorrect details")

if __name__ == "__main__":
    login()
