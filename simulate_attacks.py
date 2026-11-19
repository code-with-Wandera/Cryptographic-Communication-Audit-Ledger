import os
import psycopg

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", 5432)),
    "dbname": os.environ.get("DB_NAME", "gov_comm_db"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", "postgres"),
}


def conn():
    return psycopg.connect(**DB_CONFIG)


def attack_1_message_alteration(message_id: int):
    """Simulates an insider/attacker modifying message text directly in SQL."""
    with conn() as c, c.cursor() as cur:
        cur.execute(
            "UPDATE messages SET message_body = %s WHERE id = %s",
            ("TAMPERED: Approve emergency payout of $500,000 immediately.", message_id),
        )
    print(f"[Attack 1] Altered message #{message_id} in database.")


def attack_2_message_deletion(message_id: int):
    """Simulates deleting an earlier message to hide an audit trail."""
    with conn() as c, c.cursor() as cur:
        cur.execute("DELETE FROM messages WHERE id = %s", (message_id,))
    print(f"[Attack 2] Deleted message #{message_id} from ledger.")


def attack_3_shared_file_tampering(file_id: int):
    """Simulates modifying a shared file on disk after it was uploaded."""
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT stored_path, filename FROM shared_files WHERE id = %s", (file_id,))
        row = cur.fetchone()
        if not row:
            print("[Attack 3] No shared file found to tamper with.")
            return
        stored_path, filename = row
        with open(stored_path, "ab") as f:
            f.write(b"\n[UNAUTHORIZED APPENDED CLAUSE]\n")
    print(f"[Attack 3] Tampered with file '{filename}' (#{file_id}) on disk.")


def attack_4_compromised_account_forged_message(compromised_user_id: int):
    """Marks a staff account as COMPROMISED and inserts a forged message."""
    with conn() as c, c.cursor() as cur:
        cur.execute(
            "UPDATE users SET account_status = 'COMPROMISED' WHERE id = %s",
            (compromised_user_id,),
        )
        cur.execute(
            """INSERT INTO messages (sender_id, channel_name, message_body, prev_hash, current_hash, auth_context)
               VALUES (%s, 'Executive-Orders', 'FORGED ORDER: Release restricted citizen records.', '', '', 'TOKEN_REPLAY_ANOMALY')""",
            (compromised_user_id,),
        )
    print(f"[Attack 4] Marked user #{compromised_user_id} COMPROMISED and injected forged message.")


if __name__ == "__main__":
    print("Choose attack simulation:")
    print("1 - Message Alteration")
    print("2 - Message Deletion")
    print("3 - Shared-File Tampering")
    print("4 - Compromised Account Forged Message")
    choice = input("Enter 1-4: ").strip()

    if choice == "1":
        mid = int(input("Target message ID: "))
        attack_1_message_alteration(mid)
    elif choice == "2":
        mid = int(input("Target message ID: "))
        attack_2_message_deletion(mid)
    elif choice == "3":
        fid = int(input("Target shared_files ID: "))
        attack_3_shared_file_tampering(fid)
    elif choice == "4":
        uid = int(input("Target user ID (e.g. 2): "))
        attack_4_compromised_account_forged_message(uid)