import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2  # pip install pycryptodome
import secretstorage  # pip install secretstorage
import sqlite3
from datetime import datetime, timedelta

from typing import Union


def get_chrome_datetime(chromedate: str) -> Union[str, datetime]:
    """
    Convert the Chrome datetime to a human-readable format
    """
    if not chromedate:
        return 'Session'
    if chromedate != 86400000000:
        return datetime(1601, 1, 1) + timedelta(microseconds=int(chromedate))


def get_encrypted_cookies(path_to_db: str) -> list:
    """
    Get the encrypted cookies from the Chrome SQLite database
    """
    cookies = []
    db = sqlite3.connect(path_to_db)
    cursor = db.cursor()
    cursor.execute('SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value FROM cookies')
    for host_key, path_to_db, is_secure, expires_utc, cookie_key, value, encrypted_value in cursor.fetchall():
        cookie = {}
        cookie['host_key'] = host_key
        cookie['path'] = path_to_db
        cookie['value'] = value
        cookie['name'] = cookie_key
        cookie['is_secure'] = is_secure
        cookie['expires_utc'] = get_chrome_datetime(expires_utc)
        cookie['encrypted_value'] = encrypted_value
        cookies.append(cookie)
    db.close()
    return cookies


def decrypt_cookies(cookies: list, key: bytes) -> list:
    for cookie in cookies:
        # If there is a not encrypted value or if the encrypted value doesn't start with the 'v1[01]' prefix
        if cookie['value'] or (cookie['encrypted_value'][:3] not in {b"v10", b"v11"}):
            continue
        else:
            encrypted_value = cookie['encrypted_value']
            decrypted_value = decrypt(encrypted_value, key)
            cookie['value'] = decrypted_value
    return cookies


def get_chrome_password() -> bytes:
    """
    Get the user's Chrome password from the gnome keyring

    On Ubuntu, Chrome no longer use 'peanuts' as password,
    instead it's stored in gnome keyring.
    """
    bus = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(bus)
    for item in collection.get_all_items():
        if item.get_label() == 'Chrome Safe Storage':
            return item.get_secret()
    else:
        raise Exception('Chrome password not found!')


def strip_padding(decrypted_value: bytes) -> str:
    """
    Strip padding from decrypted value.
    Remove number indicated by padding.

    Example: if last is '\x0e' then ord('\x0e') == 14, so take off 14.
    """
    last = decrypted_value[-1]
    if isinstance(last, int):
        return decrypted_value[:-last].decode("utf8")
    return decrypted_value[:-ord(last)].decode("utf8")


def get_encryption_key() -> bytes:
    """
    Generate the encryption key from the settings found in Chrome Safe Storage
    It uses the PBKDF2 key derivation function to create a 16-byte key.
    """
    # Default values used by both Chrome and Chromium in OSX and Linux
    salt = b'saltysalt'
    length = 16
    # On Mac, replace password with your password from Keychain
    # On Linux other than Ubuntu, replace password with 'peanuts'.
    # On Ubuntu check the keyring for chrome password
    password = get_chrome_password()
    # 1003 on Mac, 1 on Linux
    iterations = 1
    # Key derivation according to the PKCS#5 standard (v2.0).
    key = PBKDF2(password, salt, length, iterations)
    return key


def decrypt(encrypted_value: bytes, key: bytes) -> str:
    """
    Decrypt the encrypted_value using the AES decryption algorithm in CBC mode
    """
    # Trim off the 'v10' or 'v11' that Chrome/ium prepends
    encrypted_value = encrypted_value[3:]
    init_vector = b' ' * 16
    cipher = AES.new(key, AES.MODE_CBC, IV=init_vector)
    return strip_padding(cipher.decrypt(encrypted_value))


def print_cookies(cookies: list[dict]) -> None:
    for cookie in cookies:
        print(f'''
              Host: {cookie["host_key"]}
              Path: {cookie["path"]}
              Name: {cookie["name"]}
              Value: {cookie["value"]}
              Secure: {cookie["is_secure"]}
              Expires: {cookie["expires_utc"]}
              ''')


def main():
    encryption_key = get_encryption_key()
    user_name = os.environ.get('USERNAME')
    chrome_cookies_path = f'/home/{user_name}/.config/google-chrome/Default/Cookies'
    encrypted_cookies = get_encrypted_cookies(chrome_cookies_path)
    decrypted_cookies = decrypt_cookies(encrypted_cookies, encryption_key)
    print_cookies(decrypted_cookies)


if __name__ == '__main__':
    main()
