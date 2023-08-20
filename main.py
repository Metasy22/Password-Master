import hmac
from hashlib import sha256

import pyperclip
from getpass import getpass


CHARACTERS: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
C_LENGTH: int = CHARACTERS.__len__()
SPECIAL: str = "#$%&!_=?"
S_LENGTH: int = SPECIAL.__len__()


SECRET_KEY: bytes = bytes.fromhex("YOUR PRIVATE HEX KEY")


def pseudo_random_bytes(string: str) -> list[int]:
    return list(hmac.new(SECRET_KEY, string.encode(), sha256).digest())


def pepper(password: str) -> str:
    _password = list(password)
    
    for i in pseudo_random_bytes(password):
        percent = i / 255

        if percent < .1 or .45 < percent < .55 or .9 < percent < 1:
            _password[i % _password.__len__()] = SPECIAL[i % S_LENGTH]
    
    return "".join(_password)


def salt(password: str) -> str:
    return password + "".join(map(
        lambda n: CHARACTERS[(n ** 2) % C_LENGTH], 
        pseudo_random_bytes(password)[::4]
    ))


def get_password(note: str, sub_password: str) -> str:
    _data = list(hmac.new(SECRET_KEY, note.encode() + sub_password.encode(), sha256).digest())
    _password = ""

    for i in range(0, len(_data), 2):
        byte = _data[i]
        next_byte = _data[i + 1]

        _password += CHARACTERS[(byte * next_byte) % C_LENGTH]

    return _password


def main():
    print("PWD Generator & Master\n")

    while True:  # mainloop
        note: str = input("[Important input] Note:" + '\t' * 2)
        sub_password: str = getpass("[Important input] Sub Password:\t")

        pyperclip.copy(
            pepper(salt(get_password(note, sub_password)))
        )

        print("[Info] Password copied!")


if __name__ == "__main__":
    main()
