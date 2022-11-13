from flask import render_template, jsonify, request, redirect, url_for, flash
from flask_login import logout_user, login_required, login_user, current_user
from .. import db

from . import auth

@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    return jsonify({'message': 'Login successful'}), 200

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200


@auth.route('/register', methods=['GET', 'POST'])
def register():
    data = request.get_json()
    return jsonify({'message': 'Registration successful'}), 200

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return jsonify({'message': 'Unconfirmed'}), 300


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    #send_email(current_user.email, 'Confirm Your Account',
    #           'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))