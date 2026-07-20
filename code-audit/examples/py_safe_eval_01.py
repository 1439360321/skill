def calculate_safe(expression):
    import ast
    import operator
    allowed = {ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Constant}
    try:
        tree = ast.parse(expression, mode='eval')
        for node in ast.walk(tree):
            if type(node) not in allowed:
                raise ValueError("Unsafe expression")
        return eval(expression, {"__builtins__": {}}, {})
    except Exception:
        raise ValueError("Invalid expression")