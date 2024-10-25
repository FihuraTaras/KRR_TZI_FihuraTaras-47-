import imaplib
import email
import re
import base64
from Crypto.Cipher import AES
import sqlite3


# 1. Функція отримання поштового трафіку
def get_mail_traffic(server, email_address, password):
    mail = imaplib.IMAP4_SSL(server)
    mail.login(email_address, password)
    mail.select("inbox")

    result, data = mail.search(None, "ALL")
    email_ids = data[0].split()

    emails = []
    for email_id in email_ids:
        result, message_data = mail.fetch(email_id, "(RFC822)")
        raw_email = message_data[0][1]
        msg = email.message_from_bytes(raw_email)
        emails.append(msg)

    return emails


# 2. Функція шифрування вмісту листа
def encrypt_email_content(email_content, secret_key):
    cipher = AES.new(secret_key.encode('utf-8'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(email_content.encode('utf-8'))

    return base64.b64encode(ciphertext).decode('utf-8'), cipher.nonce


# 3. Функція аналізу вмісту листа
def analyze_email(email_content, keywords):
    for keyword in keywords:
        if re.search(keyword, email_content, re.IGNORECASE):
            return True  # Лист відповідає ознакам
    return False  # Лист не відповідає ознакам


# 4. Функція прийняття рішення
def make_decision(is_spam):
    if is_spam:
        print("Лист помічений як спам і буде відхилений.")
        return "rejected"
    else:
        print("Лист прийнятий і буде збережений.")
        return "accepted"


# 5. Функція збереження результатів
def store_email(email_id, content, result):
    conn = sqlite3.connect('mail_analysis.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS emails
                      (id INTEGER PRIMARY KEY, content TEXT, result TEXT)''')

    cursor.execute("INSERT INTO emails (id, content, result) VALUES (?, ?, ?)",
                   (email_id, content, result))
    conn.commit()
    conn.close()


# Основна функція, що реалізує весь процес
def main():
    server = 'imap.gmail.com'
    email_address = 'your_email@example.com'
    password = 'your_password'
    secret_key = 'your_secret_key'  # Має бути довжиною 16, 24 або 32 символи для AES
    keywords = ["спам", "фішинг", "реклама"]  # Ключові слова для пошуку

    # Отримання листів
    emails = get_mail_traffic(server, email_address, password)

    # Обробка кожного листа
    for i, email_message in enumerate(emails):
        email_content = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')

        # Шифрування вмісту листа
        encrypted_message, nonce = encrypt_email_content(email_content, secret_key)

        # Аналіз листа на відповідність ознакам
        is_spam = analyze_email(email_content, keywords)

        # Прийняття рішення
        decision = make_decision(is_spam)

        # Збереження результатів
        store_email(i, encrypted_message, decision)


if __name__ == '__main__':
    main()

