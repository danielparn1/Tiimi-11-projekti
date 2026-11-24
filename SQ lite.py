
import sqlite3
import bcrypt
import getpass

DATABASE = "users.db"


# Luodaan tietokanta
def create_database():
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Rekisteröinti
def register():
    username = input("Käyttäjätunnus: ").strip()
    email = input("Sähköposti: ").strip()
    password = getpass.getpass("Salasana: ")

    if not username:
        print("Virhe! Käyttäjätunnus puuttuu.")
        return

    if "@" not in email or "." not in email:
        print("Virhe! Anna kelvollinen sähköpostiosoite.")
        return

    if len(password) < 8:
        print("Virhe! Salasanan pitää olla vähintään 8 merkkiä.")
        return

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )

    conn = sqlite3.connect(DATABASE)

    try:
        conn.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash)
        )

        conn.commit()
        print("Käyttäjä luotu onnistuneesti!")

    except sqlite3.IntegrityError:
        print("Virhe! Käyttäjätunnus tai sähköposti on jo käytössä.")

    finally:
        conn.close()


# Kirjautuminen
def login():
    username = input("Käyttäjätunnus: ").strip()
    password = getpass.getpass("Salasana: ")

    conn = sqlite3.connect(DATABASE)

    result = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if result and bcrypt.checkpw(
        password.encode("utf-8"),
        result[0]
    ):
        print("Kirjautuminen onnistui!")
        return True

    print("Väärä käyttäjätunnus tai salasana!")
    return False


# Käyttäjien näyttäminen
def show_users():
    conn = sqlite3.connect(DATABASE)

    users = conn.execute(
        "SELECT id, username, email FROM users"
    ).fetchall()

    conn.close()

    print("\n--- KÄYTTÄJÄT ---")

    for user in users:
        print(
            f"ID: {user[0]} | "
            f"Käyttäjä: {user[1]} | "
            f"Sähköposti: {user[2]}"
        )


# Päävalikko
def main():
    create_database()

    while True:
        print("\n===== SQLITE KÄYTTÄJÄT =====")
        print("1. Rekisteröidy")
        print("2. Kirjaudu sisään")
        print("3. Näytä käyttäjät")
        print("4. Lopeta")

        choice = input("\nValitse: ")

        if choice == "1":
            register()

        elif choice == "2":
            login()

        elif choice == "3":
            show_users()

        elif choice == "4":
            print("Ohjelma suljetaan.")
            break

        else:
            print("Virheellinen valinta!")


if __name__ == "__main__":
    main()