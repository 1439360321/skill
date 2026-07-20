def execute_sandboxed(user_code):
    safe_builtins = {'print': print, 'len': len, 'range': range}
    safe_globals = {'__builtins__': safe_builtins}
    exec(user_code, safe_globals, {})