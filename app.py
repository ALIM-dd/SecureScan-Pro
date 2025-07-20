#!/usr/bin/env python3
 """
SecureScan Pro - Main Application Entry Point
Professional Web Security Scanner - Production Ready

Author: SecureScan Pro Team
License: Commercial License - See LICENSE file
Website: https://securescan-pro.com
 """

import os
import sys
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

# Import application modules
from web.app import app, db, celery
from core.vulnerability_scanner import SecurityScanner
from core.report_generator import ReportGenerator
from compliance.ethical_compliance import EthicalComplianceManager
from licensing.subscription_manager import SubscriptionManager
from localization.translations import translation_manager, get_user_language

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/securescan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize Sentry for error tracking
if os.environ.get('SENTRY_DSN'):
    sentry_sdk.init(
        dsn=os.environ.get('SENTRY_DSN'),
        integrations=[
            FlaskIntegration(transaction_style='endpoint'),
            SqlalchemyIntegration(),
        ],
        traces_sample_rate=1.0,
        environment=os.environ.get('FLASK_ENV', 'production')
    )

# Initialize core components
security_scanner = SecurityScanner()
report_generator = ReportGenerator()
ethical_compliance = EthicalComplianceManager()
subscription_manager = SubscriptionManager()

# Configure Flask application
app.wsgi_app = ProxyFix(app.wsgi_app, x=1, proto=1, host=1, prefix=1)
CORS(app, resources={r."/api/*": {"origins": "*"}})

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "10 per minute"]
)


@app.before_request
def before_request():
    """Pre-request processing for security and compliance."""
    # Log request for audit trail
    logger.info(f"Request: {request.method} {request.url} from {request.remote_addr}")
    
    # Set user language for localization
    user_language = get_user_language(request)
    translation_manager.set_current_language(user_language)
    
    # Security headers
    @app.after_request
    def after_request(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'`
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';"
        return response


@app.route('/')
def index():
    """Main landing page with multi-language support."""
    language = get_user_language(request)
    return render_template('index.html', language=language)


@app.route('/api/v1/scan', methods=['POST'])
@limiter.limit("5 per minute")
def start_scan():
    """Start a new security scan."""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or not data.get('url'):
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        scan_type = data.get('scan_type', 'basic')
        language = data.get('language', 'en')
        
        # Ethical compliance check
        compliance_result = ethical_compliance.validate_scan_request(url)
        if not compliance_result['valid']:
            return jsonify({'error': compliance_result['message']}), 403
        
        # Check subscription limits
        user_id = request.headers.get('X-User-ID')
        if user_id:
            subscription_check = subscription_manager.check_scan_limit(user_id)
            if not subscription_check['allowed']:
                return jsonify({'error': subscription_check['message']}), 429
        
        # Start scan asynchronously
        scan_task = security_scanner.start_scan.delay(
            url=url,
            scan_type=scan_type,
            language=language,
            user_id=user_id
        )
        
        return jsonify({
            'scan_id': scan_task.id,
            'status': 'started',
            'message': 'Scan started successfully'
        }), 202
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and progress."""
    try:
        scan_status = security_scanner.get_scan_status(scan_id)
        return jsonify(scan_status)
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/v1/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get completed scan results."""
    try:
        results = security_scanner.get_scan_results(scan_id)
        if not results:
            return jsonify({'error': 'Scan results not found'}), 404
        
        return jsonify(results)
    except Exception as e:
        logger.error(f"Error getting scan results: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/report', methods=['POST'])
def generate_report():
    """Generate a professional security report."""
    try:
        data = request.get_json()
        
        scan_id = data.get('scan_id')
        report_format = data.get('format', 'pdf')
        language = data.get('language', 'en')
        
        if not scan_id:
            return jsonify({'error': 'Scan ID is required'}), 400
        
        # Generate report asynchronously
        report_task = report_generator.generate_report.delay(
            scan_id=scan_id,
            format=report_format,
            language=language
        )
        
        return jsonify({
            'report_id': report_task.id,
            'status': 'generating',
            'message': 'Report generation started'
        }), 202
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/subscription', methods=['GET'])
def get_subscription_info():
    """Get user subscription information."""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 401
        
        subscription_info = subscription_manager.get_user_subscription(user_id)
        return jsonify(subscription_info)
    except Exception as e:
        logger.error(f"Error getting subscription info: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Check database connection
        db.engine.execute('SELECT 1')
        
        # Check Redis connection
        celery.control.inspect().stats()
        
        return jsonify({
            'status': 'healthy', 
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


@app.errorhandler(404)
def not_found(error):
    """404 error handler."""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(429)
def rate_limit_handler(error):
    """Rate limit error handler."""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429


@app.errorhandler(500)
def internal_error(error):
    """500 error handler."""
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Start application
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    logger.info(f"Starting SecureScan Pro on port {port}")
    logger.info(f"Debug mode: {debug}")
    logger.info(f"Environment: {os.environ.get('FLASK_ENV', 'development')}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
