import csv
import bcrypt
import re
import requests
import os
import sys
import logging

logging.basicConfig(
    filename='application.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

CSV_FILE = "regno.csv"

API_KEY = "QWPEEH6XBR4GTHVT"
BASE_URL = "https://www.alphavantage.co/query"

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_valid_password(password):
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[@$!%*#?&]", password))

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

def load_user_data():
    if not os.path.exists(CSV_FILE):
        return []
    with open(CSV_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        return list(reader)

def save_user_data(users):
    with open(CSV_FILE, mode='w', newline='') as file:
        fieldnames = ['email', 'password', 'security_question']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(users)

def register():
    print("Register New Account")
    email = input("Enter your email: ")
    if not is_valid_email(email):
        print("Invalid email format!")
        logging.warning("Attempted registration with invalid email format.")
        return

    password = input("Enter a strong password: ")
    if not is_valid_password(password):
        print("Password must be at least 8 characters long, include an uppercase letter, lowercase letter, number, and special character.")
        logging.warning(f"Attempted registration with weak password for {email}.")
        return

    security_question = input("What is your favorite color (for password recovery): ")

    hashed_password = hash_password(password)

    user_data = load_user_data()
    user_data.append({"email": email, "password": hashed_password.decode('utf-8'), "security_question": security_question})
    save_user_data(user_data)
    print("Registration successful!")
    logging.info(f"New user registered: {email}")

def login():
    email = input("Enter your email: ")
    if not is_valid_email(email):
        print("Invalid email format!")
        logging.warning(f"Invalid login attempt with invalid email format: {email}")
        return False
    
    password = input("Enter your password: ")
    
    users = load_user_data()
    user = next((user for user in users if user['email'] == email), None)

    if user and check_password(user['password'].encode('utf-8'), password):
        print("Login successful!")
        logging.info(f"User logged in: {email}")
        return True
    else:
        print("Invalid email or password.")
        logging.warning(f"Failed login attempt for {email}.")
        return False

def forgot_password():
    print("Forgot Password")
    email = input("Enter your registered email: ")
    users = load_user_data()
    user = next((user for user in users if user['email'] == email), None)

    if user:
        answer = input("Security Question - What is your favorite color? ")
        if answer == user['security_question']:
            new_password = input("Enter a new password: ")
            if is_valid_password(new_password):
                user['password'] = hash_password(new_password).decode('utf-8')
                save_user_data(users)
                print("Password reset successful!")
                logging.info(f"Password reset for {email}")
            else:
                print("Invalid password format.")
                logging.warning(f"Password reset attempt with invalid password for {email}.")
        else:
            print("Incorrect answer to the security question.")
            logging.warning(f"Incorrect answer to security question for {email}.")
    else:
        print("No account found with that email.")
        logging.warning(f"Password reset attempt for non-existent email: {email}")

def get_stock_data(ticker_symbol):
    params = {
        'function': 'TIME_SERIES_INTRADAY',
        'symbol': ticker_symbol,
        'interval': '1min',
        'apikey': API_KEY
    }
    
    try:
        response = requests.get(BASE_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            if "Time Series (1min)" in data:
                latest_time = list(data["Time Series (1min)"])[0]
                stock_info = data["Time Series (1min)"][latest_time]
                print(f"Stock: {ticker_symbol.upper()}")
                print(f"Current Price: {stock_info['1. open']}")
                print(f"High Price: {stock_info['2. high']}")
                print(f"Low Price: {stock_info['3. low']}")
                print(f"Previous Close: {stock_info['4. close']}")
                print(f"Volume: {stock_info['5. volume']}")
                logging.info(f"Stock data retrieved for {ticker_symbol}.")
            else:
                print("No data found for the ticker symbol.")
                logging.warning(f"No stock data found for {ticker_symbol}.")
        else:
            print("Failed to retrieve data. Check your network or API key.")
            logging.error(f"Failed API request for {ticker_symbol}. Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        logging.error(f"Network error while fetching stock data for {ticker_symbol}: {e}")

def start_application():
    attempts = 0
    max_attempts = 5

    while attempts < max_attempts:
        choice = input("1. Login\n2. Register\n3. Forgot Password\n4. Exit\nChoose an option: ")

        if choice == '1':
            if login():
                ticker_symbol = input("Enter the stock ticker symbol (e.g., AAPL): ")
                get_stock_data(ticker_symbol)
                break
            else:
                attempts += 1
                print(f"Attempts remaining: {max_attempts - attempts}")
                logging.warning(f"Failed login attempt {attempts}/{max_attempts}.")
                if attempts == max_attempts:
                    print("Maximum login attempts exceeded. Exiting.")
                    logging.error("Maximum login attempts reached. User locked out.")
                    sys.exit()
        elif choice == '2':
            register()
        elif choice == '3':
            forgot_password()
        elif choice == '4':
            print("Goodbye!")
            logging.info("Application exited by the user.")
            sys.exit()
        else:
            print("Invalid option. Please try again.")
            logging.warning("Invalid menu option selected.")

if __name__ == "__main__":
    start_application()
