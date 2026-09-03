import re
with open('main.py') as f:
    lines = f.readlines()
found = False
for i, line in enumerate(lines, 1):
    stripped = line.rstrip('\n')
    dq = stripped.count('"')
    if dq % 2 == 1 and '"""' not in stripped and not stripped.strip().startswith('#'):
        print(f'Line {i}: odd dq={dq}: {stripped[:120]}')
        found = True
if not found:
    print("No unclosed string literals found")
