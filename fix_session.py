with open('keyboard_monitor/gui.py', encoding='utf-8') as f:
    content = f.read()
old = '''        session_id = session_text.rsplit(\"-\", 1)[-1].strip() if \"-\" in session_text else None'''
new = '''        session_id = None
        import re
        m = re.search(r'(S-[0-9A-F]{12})', session_text)
        if m:
            session_id = m.group(1)'''
content = content.replace(old, new)
with open('keyboard_monitor/gui.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('done')