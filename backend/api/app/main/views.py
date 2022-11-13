from datetime import datetime
from flask import request, jsonify, url_for, g, current_app
from . import main
from .. import db
from ..models import User, Role
from flask_login import login_required
from ..decorators import admin_required


# Ruta principal de la api
@main.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'Welcome to the API!'})

@main.route('/user/<username>', methods=['GET'])
def get_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'username': user.username, 'email': user.email})
    else:
        return jsonify({'message': 'User not found'})

@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    # Obtener los datos del form y luego editar el perfil del usuario en la tabla Profile
    #user = User.query.filter_by(username=username).first()
    return jsonify({'username': "user.username"})

@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    data = request.get_json()
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'The profile has been updated.'})
