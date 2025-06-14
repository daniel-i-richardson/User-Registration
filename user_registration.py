import boto3
import uuid
import hashlib
import getpass
from datetime import datetime, timezone

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
    created_at = datetime.now(timezone.utc).isoformat()
    modified_at = created_at

    table.put_item(Item={
        "username": username,
        "UserID": user_id,
        "email": email,
        "password_hash": password,
        "created_at": created_at,
        "modified_at": modified_at,
        "last_login": ""
    })

    print("User successfully registered and saved to DynamoDB.")

def login_user():
    username = input("Username: ")
    password = hash_password(getpass.getpass("Password: "))
    response = None
    
    successful_login, message = test_credentials(username, password)

    if successful_login:
        try:
            response = table.get_item(Key={"username": username})
            print("Response received from database")
        except:
            print("Unable to connect to DB")
    else:
        print(message)
        return
    
    user = response.get("Item")
    update_last_login(username)
    print(message)
    print("Username: {}\nEmail Address:{}".format(user["username"], user["email"]))
    
    

def test_credentials(username, password):
    response = None
    try:
        response = table.get_item(
            Key={"username": username},
            ProjectionExpression="username, password_hash"
        )
    except:
        return False, "Unable to connect to database"

    user = response.get("Item")
    if user:
        if user["password_hash"] == password:
            return True, "User credentials verified."
        else:
            return False, "Incorrect password. Please try again."
    else:
        return False, "Username not found"
    
def update_last_login(username):
        table.update_item(
            Key={"username": username},
            UpdateExpression="SET last_login = :timestamp",
            ExpressionAttributeValues={
                ":timestamp": datetime.now(timezone.utc).isoformat()
            }
        )



def main():
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    main()