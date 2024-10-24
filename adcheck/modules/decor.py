from io import StringIO
import functools
import sys


def admin_required(func):
    @functools.wraps(func)
    def wrapper(obj):
        if obj.is_admin:
            return func(obj)
        else:
            pass
    return wrapper

def capture_stdout(func):
    def wrapper(*args, **kwargs):
        stdout_backup = sys.stdout
        sys.stdout = StringIO()
        
        func(*args, **kwargs)
        
        captured_output = sys.stdout.getvalue()
        sys.stdout = stdout_backup
        
        return captured_output
    return wrapper