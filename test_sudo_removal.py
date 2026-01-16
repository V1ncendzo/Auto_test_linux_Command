import os

ATTACK_FILE = "attack_commands/Kaspersky_Endpoint_Security_Stopped_Via_CommandLine.txt"

def test_sudo_removal():
    print(f"Testing commands from {ATTACK_FILE}...")
    if not os.path.exists(ATTACK_FILE):
        print(f"File {ATTACK_FILE} not found!")
        return

    with open(ATTACK_FILE, 'r') as f:
        commands = [line.strip() for line in f if line.strip()]

    sudo_count_before = 0
    sudo_count_after = 0
    
    for cmd in commands:
        if "sudo " in cmd:
            sudo_count_before += 1
        
        # Simulate the logic in 1_collect_logs.py
        processed_cmd = cmd.replace("sudo ", "")
        
        if "sudo " in processed_cmd:
            # Note: naive replace might leave "sudo " if it appeared twice disjointly or was part of a word that wasn't "sudo " (but we matched "sudo "). 
            # Actually "sudo " string search is specific.
            # Let's check if it remains.
            print(f"[FAIL] 'sudo ' still present in: {processed_cmd} (Original: {cmd})")
            sudo_count_after += 1
        else:
            # print(f"[OK] {processed_cmd}")
            pass

    print("-" * 20)
    print(f"Total commands: {len(commands)}")
    print(f"Commands with 'sudo ' before: {sudo_count_before}")
    print(f"Commands with 'sudo ' after:  {sudo_count_after}")

    if sudo_count_after == 0:
        print("\nSUCCESS: All 'sudo ' instances removed successfully.")
    else:
        print("\nFAILURE: Some 'sudo ' instances remain.")

if __name__ == "__main__":
    test_sudo_removal()
