from ..main import main
from flask import jsonify, request
from ..api import api
from  ..exceptions import ValidationError

@api.errorhandler(ValidationError)
def validation_error(e):
    return (jsonify({'error': 'validation error', 'message': e.args[0]}), 400)

def forbidden(message):
    response = jsonify({'error': 'forbidden', 'mesage': message})
    response.status_code = 403
    return response


def unauthorized(message):
    response = jsonify({'error': 'unauthorized', 'message': message})
    response.status_code = 401
    return response