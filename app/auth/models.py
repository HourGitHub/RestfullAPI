from .. import db
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from datetime import datetime, timedelta

import app

class User(db.Model):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    email = Column(String(120), unique=True, nullable=False)



class Userlogs(db.Model):
    __tablename__ = 'userlogs'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    email = Column(String(120), nullable=False)
    access_token = Column(String(200))  # Adjust length as necessary
    expires_in = Column(Integer)  # Adjust data type as necessary
    token_type = Column(String(50))  # Adjust length as necessary
    status_code = Column(Integer)  # Adjust data type as necessary
    active = Column(Boolean, default=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<Userlogs(username='{self.username}', action='{self.action}', timestamp='{self.timestamp}')>"





class OTP(db.Model):
    __tablename__ = 'otplogs'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    request_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    verify_otp_code = db.Column(db.String(6), nullable=True)
    verify_datetime = db.Column(db.DateTime, nullable=True)
    verify_status = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)

    def __init__(self, email, otp_code, expires_at):
        self.email = email
        self.otp_code = otp_code
        self.expires_at = expires_at

    def can_request_otp(self):
        """Checks if the user can request another OTP within the daily limit (optional)."""
        # Implement your logic to check daily request limit here
        # This example doesn't implement daily limit checking

        return True  # Replace with your daily limit check logic

    def record_otp_request(self):
        """Updates the request time for the current OTP entry."""
        self.request_time = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def deactivate(self):
        """Marks the OTP as inactive."""
        self.active = False
        db.session.add(self)
        db.session.commit()



class TokenRequestLog(db.Model):
    __tablename__ = 'token_request_log'

    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(200), nullable=False)
    request_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<TokenRequestLog(access_token='{self.access_token}', request_time='{self.request_time}', expires='{self.expires}', active='{self.active}')>"
    
    