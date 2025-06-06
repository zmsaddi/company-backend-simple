from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta, datetime
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-string-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
jwt = JWTManager(app)
CORS(app, origins=["*"], supports_credentials=True)

# Simple in-memory data store (for demo purposes)
users_db = {
    'admin@company.com': {
        'id': '1',
        'email': 'admin@company.com',
        'password': 'admin123',
        'first_name': 'Admin',
        'last_name': 'User',
        'role': 'admin',
        'is_active': True
    }
}

employees_db = [
    {
        'id': '1',
        'employee_id': 'EMP001',
        'first_name': 'أحمد',
        'last_name': 'محمد',
        'email': 'ahmed@company.com',
        'phone': '+966501234567',
        'department': 'تقنية المعلومات',
        'position': 'مطور برمجيات',
        'salary': 8000.00,
        'hire_date': '2023-01-15',
        'is_active': True
    },
    {
        'id': '2',
        'employee_id': 'EMP002',
        'first_name': 'فاطمة',
        'last_name': 'علي',
        'email': 'fatima@company.com',
        'phone': '+966507654321',
        'department': 'الموارد البشرية',
        'position': 'أخصائي موارد بشرية',
        'salary': 6500.00,
        'hire_date': '2023-02-01',
        'is_active': True
    },
    {
        'id': '3',
        'employee_id': 'EMP003',
        'first_name': 'خالد',
        'last_name': 'السعد',
        'email': 'khalid@company.com',
        'phone': '+966509876543',
        'department': 'المبيعات',
        'position': 'مدير مبيعات',
        'salary': 9500.00,
        'hire_date': '2022-11-10',
        'is_active': True
    }
]

inventory_db = [
    {
        'id': '1',
        'item_code': 'ITM001',
        'name': 'لابتوب Dell Latitude',
        'description': 'لابتوب للعمل المكتبي',
        'category': 'أجهزة كمبيوتر',
        'quantity': 25,
        'unit_price': 3500.00,
        'supplier': 'شركة التقنية المتقدمة',
        'location': 'المستودع الرئيسي',
        'minimum_stock': 5
    },
    {
        'id': '2',
        'item_code': 'ITM002',
        'name': 'طابعة HP LaserJet',
        'description': 'طابعة ليزر للمكاتب',
        'category': 'أجهزة طباعة',
        'quantity': 12,
        'unit_price': 1200.00,
        'supplier': 'مؤسسة الطباعة الحديثة',
        'location': 'المستودع الرئيسي',
        'minimum_stock': 3
    }
]

# Authentication routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = users_db.get(email)
        if not user or user['password'] != password:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create access token
        access_token = create_access_token(
            identity=user['id'],
            additional_claims={
                'email': user['email'],
                'role': user['role']
            }
        )
        
        return jsonify({
            'message': 'Login successful',
            'token': access_token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'role': user['role']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500

# Dashboard route
@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats():
    try:
        stats = {
            'total_employees': len([emp for emp in employees_db if emp['is_active']]),
            'total_inventory_items': len(inventory_db),
            'low_stock_items': len([item for item in inventory_db if item['quantity'] <= item['minimum_stock']]),
            'total_inventory_value': sum(item['quantity'] * item['unit_price'] for item in inventory_db),
            'recent_activities': [
                {'type': 'employee_added', 'description': 'تم إضافة موظف جديد', 'timestamp': '2024-06-06T10:30:00Z'},
                {'type': 'inventory_updated', 'description': 'تم تحديث المخزون', 'timestamp': '2024-06-06T09:15:00Z'},
                {'type': 'report_generated', 'description': 'تم إنشاء تقرير شهري', 'timestamp': '2024-06-06T08:45:00Z'}
            ]
        }
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': 'Failed to fetch dashboard stats', 'details': str(e)}), 500

# Employees routes
@app.route('/api/employees', methods=['GET'])
@jwt_required()
def get_employees():
    try:
        return jsonify({'employees': employees_db}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to fetch employees', 'details': str(e)}), 500

@app.route('/api/employees', methods=['POST'])
@jwt_required()
def add_employee():
    try:
        data = request.get_json()
        new_employee = {
            'id': str(len(employees_db) + 1),
            'employee_id': f"EMP{len(employees_db) + 1:03d}",
            'first_name': data.get('first_name'),
            'last_name': data.get('last_name'),
            'email': data.get('email'),
            'phone': data.get('phone'),
            'department': data.get('department'),
            'position': data.get('position'),
            'salary': float(data.get('salary', 0)),
            'hire_date': data.get('hire_date'),
            'is_active': True
        }
        employees_db.append(new_employee)
        return jsonify({'message': 'Employee added successfully', 'employee': new_employee}), 201
    except Exception as e:
        return jsonify({'error': 'Failed to add employee', 'details': str(e)}), 500

# Inventory routes
@app.route('/api/inventory', methods=['GET'])
@jwt_required()
def get_inventory():
    try:
        return jsonify({'inventory': inventory_db}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to fetch inventory', 'details': str(e)}), 500

@app.route('/api/inventory', methods=['POST'])
@jwt_required()
def add_inventory_item():
    try:
        data = request.get_json()
        new_item = {
            'id': str(len(inventory_db) + 1),
            'item_code': f"ITM{len(inventory_db) + 1:03d}",
            'name': data.get('name'),
            'description': data.get('description'),
            'category': data.get('category'),
            'quantity': int(data.get('quantity', 0)),
            'unit_price': float(data.get('unit_price', 0)),
            'supplier': data.get('supplier'),
            'location': data.get('location'),
            'minimum_stock': int(data.get('minimum_stock', 0))
        }
        inventory_db.append(new_item)
        return jsonify({'message': 'Inventory item added successfully', 'item': new_item}), 201
    except Exception as e:
        return jsonify({'error': 'Failed to add inventory item', 'details': str(e)}), 500

# Health check endpoint
@app.route('/api/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Company Management System API is running',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization token is required'}), 401

# Root route
@app.route('/')
def root():
    return jsonify({
        'message': 'Company Management System API',
        'version': '2.0.0',
        'status': 'running',
        'endpoints': {
            'auth': '/api/auth/login',
            'dashboard': '/api/dashboard/stats',
            'employees': '/api/employees',
            'inventory': '/api/inventory',
            'health': '/api/health'
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

