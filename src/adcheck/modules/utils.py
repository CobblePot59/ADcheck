import functools


def admin_required(func):
    @functools.wraps(func)
    def wrapper(obj):
        if obj.is_admin:
            return func(obj)
        else:
            pass
    return wrapper