import boto3
import uuid
import hashlib
import getpass
from datetime import datetime

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("Users")
print("Table status:", table.table_status)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user():
    print("\n---- Register New User ----")
    username = input("Username: ").strip()
    password = get_password()
    email = input("Email Address: ").strip()

    write_user(username, password, email)
    print("New User Registered!\nUsername: {}\nPassword: {}\nEmail: {}".format(username, password, email))

def get_password():
    while True:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm Password:")

        if confirm == password:
            return hash_password(password)
        else:
            print("\nPasswords do not match. Please try again.")

def write_user(username, password, email):
    user_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()
    modified_at = created_at

    table.put_item(Item={
        "UserID": user_id,
        "username": username,
        "email": email,
        "password_hash": password,
        "created_at": created_at,
        "modified_at": modified_at,
        "last_login": ""
    })

    print("User successfully registered and saved to DynamoDB.")

def main():
    while True:
        print("\n1. Register\n2. Exit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            register_user()
        elif choice == "2":
            print("Goodbye.")
            break
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    main()