import boto3
import uuid
import hashlib
import getpass
from datetime import datetime, timezone

dynamodb = boto3.resource("dynamodb")
user_table = dynamodb.Table("Users")
login_attempts_table = dynamodb.Table("LoginAttempts")
print("Table status:", user_table.table_status)

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
    created_at = get_current_datetime()
    modified_at = created_at

    user_table.put_item(Item={
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
            response = user_table.get_item(Key={"username": username})
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
        response = user_table.get_item(
            Key={"username": username},
            ProjectionExpression="username, password_hash"
        )
    except:
        return False, "Unable to connect to database"

    user = response.get("Item")
    if user:
        if user["password_hash"] == password:
            update_login_attempts(username)
            return True, "User credentials verified."
        else:
            update_login_attempts(username, "InvalidPassword")
            return False, "Incorrect password. Please try again."
    else:
        update_login_attempts(username, "InvalidUsername")
        return False, "Username not found"
    
def update_last_login(username):
        user_table.update_item(
            Key={"username": username},
            UpdateExpression="SET last_login = :timestamp",
            ExpressionAttributeValues={
                ":timestamp": get_current_datetime()
            }
        )

def update_login_attempts(username, failure_reason=""):
    success = True
    if failure_reason != "":
        success = False

    login_attempts_table.put_item(Item={
        "AttemptID": str(uuid.uuid4()),
        "username": username,
        "timestamp": get_current_datetime(),
        "success": success,
        "failure_reason": failure_reason
    })

def get_current_datetime():
    return datetime.now(timezone.utc).isoformat()

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