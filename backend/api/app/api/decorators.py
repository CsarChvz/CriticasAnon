from functools import wraps
from flask_httpauth import HTTPBasicAuth

from api.app.api.errors import unauthorized
auth = HTTPBasicAuth()

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not auth.current_user.can(permission):
                return unauthorized('Insufficient permissions')
            return f(*args, **kwargs)
        return decorated_function
    return decorator