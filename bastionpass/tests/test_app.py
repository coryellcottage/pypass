from keyring.errors import NoKeyringError
from cryptography.fernet import Fernet
from bastionpass.app import BastionPass
from bastionpass.utils import *
from pathlib import Path
import subprocess
import pytest
import toga
import json
import os


os.environ["TOGA_BACKEND"] = "toga_dummy"

bastion_pass_object = BastionPass(app_id="id", formal_name="name")
bastion_pass_object.app.paths.data.mkdir(parents=True, exist_ok=True)

def test_recover_key():
    print("Testing recover_key...")

    assert recover_key("afraid!/ boat/ 1/ !/ -/".replace(" ", "").split("/")) == "Ab1!-"

def test_add_to_screen():
    print("Testing add_to_screen...")

    add_to_screen(
        (
            toga.Button(text="test"),
            toga.Label(text="test", style=toga.style.Pack(margin_top=10))
        ),
        toga.Box()
    )

    add_to_screen(
        (
            toga.TextInput(),
            toga.Label(text="test", style=toga.style.Pack(margin_top=10))
        ),
        toga.Box(),
        clear_screen=True
    )

def test_load_env():
    print("Testing load_env...")

    Path(bastion_pass_object.app.paths.data, ".env").write_text("")

    assert load_env(env_path=Path(bastion_pass_object.app.paths.data, ".env"),
                    env_object=os.environ) == "Invalid data type saved"

    assert load_env(env_path=Path("env_file"),
                    env_object=os.environ) == "Env path doesn't exist"

    with open(Path(bastion_pass_object.app.paths.data, ".env"), mode="w") as env_file:
        json.dump(
            obj={
                "MAIN_KEY": Fernet.generate_key().decode()
            },
            fp=env_file
        )

    assert load_env(
        env_path=Path(bastion_pass_object.app.paths.data, ".env"),
        env_object=os.environ
    ) == "Loaded environment"

    Path(bastion_pass_object.app.paths.data, ".env").unlink(missing_ok=True)

def test_check_password():
    print("Testing check_password...")

    password = "password"
    cipher = Fernet(Fernet.generate_key())

    assert check_password(entered_password="password", saved_password=cipher.encrypt(password.encode()).decode(), password_cipher=cipher) == "Correct password entered"
    assert check_password(entered_password="password1", saved_password=cipher.encrypt(password.encode()).decode(), password_cipher=cipher) == "Incorrect password entered"

def test_load_user_data():
    print("Testing load_user_data")

    data_path = BastionPass(formal_name="name", app_id="id").paths.data

    test_main_key = Fernet.generate_key()
    test_user_key = Fernet.generate_key()
    test_data = {
        "user": Fernet(test_main_key).encrypt(b"test").decode(),
        "key": Fernet(test_main_key).encrypt(test_user_key).decode(),
        "data": {
            "service": {
                "username": {
                    "password": Fernet(test_user_key).encrypt(b"test_password").decode(),
                    "key": Fernet(test_user_key).encrypt(Fernet.generate_key()).decode()
                }
            }
        },
        "servers": {}
    }

    assert load_user_data(Path(data_path, "passwords_file")) == "Password file path doesn't exist"

    Path(data_path ,"passwords_file").write_text("")
    assert load_user_data(Path(data_path ,"passwords_file")) == "Invalid data saved"

    with open(Path(data_path, "passwords_file"), mode="w") as passwords_file:
        json.dump(
            obj=test_data,
            fp=passwords_file
        )

    print(f"Data type from load_user_data: {type(load_user_data(Path(data_path, 'passwords_file')))}")

    assert load_user_data(Path(data_path, "passwords_file")) == test_data

    Path(data_path, "passwords_file").unlink(missing_ok=True)

def test_create_user():
    data_path = bastion_pass_object.app.paths.data
    test_user = "user"
    test_password = "password"
    test_cipher = Fernet(Fernet.generate_key())

    assert create_new_user(user_data_path=Path(data_path, test_user), user=test_user, password=test_password, main_cipher=test_cipher) == "Successfully created new user"
    assert create_new_user(user_data_path=Path(data_path, test_user), user=test_user, password=test_password, main_cipher=test_cipher) == "User already exists"

    Path(data_path, test_user, ".passwords.json").unlink(missing_ok=True)
    Path(data_path, test_user).rmdir()

def test_copy_to_clipboard():
    toga.App.app.main_loop()

    if toga.platform.current_platform == "android":
        from org.beeware.android import MainActivity

        setattr(toga.App.app._impl, "native", MainActivity.singletonThis)

    assert copy_to_clipboard("Test text") == "Successfully copied to clipboard"

def test_get_main_key():
    Path(toga.App.app.paths.data, ".env").write_text("{}")

    try:
        decryption_key = get_main_key()

    except NoKeyringError:
        if toga.platform.current_platform == "linux":
            subprocess.run("dbus-run-session -- briefcase dev --test", shell=True)

    else:
        print(f"Decryption key is of type: {type(decryption_key)}")

        if toga.platform.current_platform == "android":
            from java import jclass
            assert isinstance(decryption_key, jclass("android.security.keystore2.AndroidKeyStoreSecretKey")) == True

        else:
            encrypted_text = Fernet(decryption_key).encrypt(b"Some text")
            assert Fernet(decryption_key).decrypt(encrypted_text).decode() == "Some text"

def test_encrypt_and_decrypt_data():
    try:
        encrypted_data = encrypt_data(data_to_encrypt="Test Text")
        assert decrypt_data(data_to_decrypt=encrypted_data["encrypted_data"], iv=encrypted_data["iv_used"]) == "Test Text"

    except NoKeyringError:
        subprocess.run("dbus-run-session -- briefcase dev --test", shell=True)

def test_offset_and_deoffset_string():
    offset_data, offset_number = offset_string(string_to_offset="Test String")

    assert offset_data == offset_string(string_to_offset="Test String", data_offset=offset_number)[0]
    assert deoffset_string(string_to_deoffset=offset_data, data_offset=offset_number) == "Test String"

def test_import_from_file():
    with open(Path(bastion_pass_object.app.paths.data, "import_from_file.txt"), mode="w") as data_file:
        data_file.write("service1\nusername1\npassword1\n\nservice2\nusername2\npassword2\n")

    imported_data = import_from_file(Path(bastion_pass_object.app.paths.data, "import_from_file.txt"), file_pattern=["service", "username", "password", "ignore"])

    assert imported_data == {"service1": {"username1": "password1"}, "service2": {"username2": "password2"}}

def test_create_backup_phrase():
    backup_wordlist = {
        "A": "afraid",
        "B": "boat",
        "C": "calculation",
        "D": "drive",
        "E": "expense",
        "F": "feed",
        "G": "ground",
        "H": "human",
        "I": "interrupt",
        "J": "juice",
        "K": "keep",
        "L": "live",
        "M": "mother",
        "N": "necessity",
        "O": "observe",
        "P": "pocket",
        "Q": "question",
        "R": "return",
        "S": "strap",
        "T": "truth",
        "U": "university",
        "V": "various",
        "W": "way",
        "X": "xenomorphically",
        "Y": "yard",
        "Z": "zebra",
    }

    assert [word.replace(" ", "") for word in create_backup_phrase("testphrase", backup_wordlist)] == ["truth", "expense", "strap", "truth", "pocket", "human", "return", "afraid", "strap", "expense"]
