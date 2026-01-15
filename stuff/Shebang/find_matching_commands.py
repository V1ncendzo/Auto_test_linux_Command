import re

# Read output file
with open(r"d:\Downloads in D\Data Amides\Auto_test_linux_Command\stuff\Shebang\output_requests_Linux Base64 Encoded Shebang In CLI.txt", "r", encoding="utf-8") as f:
    output_content = f.read()

# Expected baseline output (just "Simulating Malicious Payload")
baseline_output = "Simulating Malicious Payload"

# Parse output file to find commands with exact matching output
# Split by separator line
blocks = output_content.split("##################################################")

matching_cmds = []
failed_cmds = []

for block in blocks:
    block = block.strip()
    if not block or "CMD" not in block:
        continue
    
    # Extract CMD number and command
    cmd_match = re.search(r'CMD (\d+): (.*?)(?:\n|$)', block)
    if not cmd_match:
        continue
    
    cmd_num = int(cmd_match.group(1))
    cmd = cmd_match.group(2).strip()
    
    # Check if output matches baseline exactly
    if "-Output:" in block:
        output_section = block.split("-Output:")[1]
        # Stop at -Error: or end of block
        if "-Error:" in output_section:
            output_section = output_section.split("-Error:")[0]
        output_text = output_section.strip().split("\n")[0].strip()
        
        if output_text == baseline_output:
            matching_cmds.append((cmd_num, cmd))
        else:
            failed_cmds.append((cmd_num, cmd, f"Different output: {output_text[:50]}"))
    elif "-Error:" in block:
        error_section = block.split("-Error:")[1].strip().split("\n")[0]
        failed_cmds.append((cmd_num, cmd, f"Error: {error_section[:50]}"))

print(f"Total commands executed: 358")
print(f"Commands with EXACT baseline output: {len(matching_cmds)}")
print(f"Commands that failed/different output: {len(failed_cmds)}")
print()

# Save clean result
with open(r"d:\Downloads in D\Data Amides\Auto_test_linux_Command\stuff\Shebang\successful_commands.txt", "w", encoding="utf-8") as f:
    f.write(f"Commands that produce EXACT baseline output: {baseline_output}\n")
    f.write(f"Total matching: {len(matching_cmds)} out of 358\n")
    f.write("="*80 + "\n\n")
    
    for cmd_num, cmd in matching_cmds:
        f.write(f"{cmd}\n")

print("Successful commands saved to: successful_commands.txt")
print("\nFirst 10 matching commands:")
for i, (cmd_num, cmd) in enumerate(matching_cmds[:10]):
    print(f"  {cmd_num}: {cmd[:80]}...")
