# app/auth/routes.py
from .. import db
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash
from .models import db, User, Userlogs
from flask_jwt_extended import JWTManager


from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token

from app.auth.models import User, Userlogs
from .controllers import register_user, authenticate_user, request_otp, generate_access_token, verify_otp



auth_bp = Blueprint('auth', __name__)



@auth_bp.route('/token', methods=['GET'])
# def get_token():
#     client_secret = request.args.get('client_secret')
#     grant_type = request.args.get('grant_type')
#     client_id = request.args.get('client_id')
#     return generate_access_token(client_id, client_secret)

def get_token():
    client_secret = request.args.get('client_secret')
    client_id = request.args.get('client_id')

    if not client_secret or not client_id:
        return jsonify({'message': 'Missing client_id or client_secret'}), 400

    return generate_access_token(client_id, client_secret)



@auth_bp.route('/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     email = data.get('email')
#     password = data.get('password')
#     return register_user(username, email, password)

def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Call register_user function with provided data
    return register_user(username, email, password)



@auth_bp.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     return authenticate_user(username, password)

# Testing connect logs to DB

def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    # Set token expiration to 7 days
    expires_in_seconds = 7 * 24 * 3600  # 7 days in seconds
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(seconds=expires_in_seconds))
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in_seconds)

    # Log the successful login attempt
    login_log = Userlogs(
        username=user.username,
        email=user.email,
        access_token=access_token,
        expires_in=expires_in_seconds,
        token_type='bearer',
        status_code=200,
        active=True,
        timestamp=datetime.utcnow()
    )
    db.session.add(login_log)
    db.session.commit()

    return jsonify({
        'message': 'Login successful',
        'status': 200,
        'data': {
            'jwt': {
                'access_token': access_token,
                'token_type': 'bearer',
                'expires_in': expires_in_seconds
            }
        }
    }), 200


@auth_bp.route('/otp/request', methods=['POST'])
def handle_request_otp():
    data = request.get_json()
    email = data.get('email')
    return request_otp(email)

@auth_bp.route('/otp/verify', methods=['POST'])
def handle_verify_otp():
    return verify_otp()