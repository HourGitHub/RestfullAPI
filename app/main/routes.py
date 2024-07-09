from flask import Blueprint

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return 'Main Blueprint Index'

# Similar structure for auth_bp in auth/routes.py
