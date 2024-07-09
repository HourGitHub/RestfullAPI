# app/auth/controllers.py

from datetime import datetime, timedelta
from flask import jsonify, request
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from .models import TokenRequestLog, User, OTP
from .. import db


def generate_access_token(client_id, client_secret):
    # Validate client credentials
    if not (client_id == 'NylRQyGZUgLRMmFWcJbmF6Bf' and client_secret == 'cigyyFvmqyuGEsQypLTFBXutRcImkrjOisPm'):
        return jsonify({'message': 'Invalid client credentials'}), 401

    # Generate JWT access token
    access_token = create_access_token(identity=client_id)
    # expires_in = 7 * 24 * 3600
    expires_in = 3600 
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    # Log the token request
    token_request_log = TokenRequestLog(
        access_token=access_token,
        expires=expires,
        active=True,  # Set this as appropriate based on your logic
        request_time=datetime.utcnow()
    )
    db.session.add(token_request_log)
    db.session.commit()

    return jsonify({
        'message': 'success',
        'status': 200,
        'data': {
            'jwt': {
                'access_token': access_token,
                'token_type': 'bearer',
                'expires_in': expires_in
            }
        }
    }), 200



def register_user(username, email, password):
    if not username or not email or not password:
        return jsonify({'message': 'Username, email, and password are required'}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email already exists'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    new_user = User(username=username, email=email, password=hashed_password)

    # Add new user to session
    db.session.add(new_user)

    try:
        # Commit changes to the database
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        # Handle database commit errors
        db.session.rollback()
        return jsonify({'message': 'Failed to register user', 'error': str(e)}), 500



def authenticate_user(username, password):
    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        print(f'User {username} not found')
        return jsonify({'message': 'Invalid username or password'}), 401

    if not check_password_hash(user.password, password):
        print(f'Invalid password for user {username}')
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.id)
    print(f'User {username} logged in successfully')
    return jsonify({
        'message': 'success',
        'status': 200,
        'data': {
            'jwt': {
                'access_token': access_token,
                'token_type': 'bearer',
                'expires_in': 3600  # Optional: Token expiration time in seconds
            }
        }
    }), 200


# Function to request an OTP
def request_otp(email):
    if not email:
        return jsonify({'message': 'Email is required'}), 400

    # Check if the email already has an active OTP
    existing_otp = OTP.query.filter_by(email=email).first()

    if existing_otp and existing_otp.expires_at >= datetime.utcnow():
        # If there's an active OTP already, you might want to handle this case
        return jsonify({'message': 'An active OTP already exists for this email'}), 400

    # Generate new OTP
    otp_code = generate_otp_code()
    expires_at = datetime.utcnow() + timedelta(minutes=2)

    try:
        if existing_otp:
            # Update existing OTP record
            existing_otp.otp_code = otp_code
            existing_otp.expires_at = expires_at
        else:
            # Create new OTP record
            new_otp = OTP(email=email, otp_code=otp_code, expires_at=expires_at)
            db.session.add(new_otp)

        db.session.commit()

        # Example: Send OTP code via email (replace with your email sending logic)
        send_otp_email(email, otp_code)

        return jsonify({
            'message': 'success',
            'status': 200,
            'data': {
                'message': 'OTP code sent successfully. Please check your email.',
                'expires_at': expires_at.isoformat() + 'Z',  # ISO 8601 format
                'otp_code': otp_code
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to send OTP', 'error': str(e)}), 500

# Function to generate a random 4-digit OTP code
def generate_otp_code():
    import secrets
    return str(secrets.randbelow(10000)).zfill(4)

# Example function to send OTP code via email (replace with your email sending logic)
def send_otp_email(email, otp_code):
    print(f"Sending OTP {otp_code} to {email}")

    # Example using Flask-Mail (if you're using it)
    # mail.send_message(
    #     subject='OTP Verification Code',
    #     recipients=[email],
    #     body=f'Your OTP code is: {otp_code}'
    # )

# Function to verify an OTP
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp_code = data.get('otp_code')

    if not email or not otp_code:
        return jsonify({'message': 'Email and OTP code are required'}), 400

    # Retrieve the OTP record from the database
    otp_record = OTP.query.filter_by(email=email).first()
    if not otp_record:
        return jsonify({'message': 'OTP record not found'}), 404

    # Verify the OTP code
    if otp_record.otp_code != otp_code:
        return jsonify({'message': 'Invalid OTP code'}), 401

    # Clear the OTP code after successful verification
    otp_record.otp_code = None  # Set OTP code to None to mark it as used
    otp_record.verify_datetime = datetime.utcnow()  # Record verification time if needed
    otp_record.verify_status = True  # Update verification status as needed
    otp_record.active = False  # Deactivate OTP record after verification

    try:
        db.session.commit()
        return jsonify({'message': 'OTP code verified successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to verify OTP code', 'error': str(e)}), 500
    
