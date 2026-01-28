# app.py - PRODUCTION-READY VERSION with FastSpring Categories & SECURITY ENHANCEMENTS
import os
import requests
import json
import secrets
import time
import re
from urllib.parse import unquote
from datetime import datetime
from html import escape
from flask import Flask, request, jsonify, render_template, redirect
from flask_cors import CORS, cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import traceback
from langchain_community.vectorstores import Chroma
from langchain_community.document_loaders import TextLoader, DirectoryLoader
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain.text_splitter import MarkdownTextSplitter, MarkdownHeaderTextSplitter
from langchain.schema.document import Document
import jwt
from functools import wraps
import subprocess
from pathlib import Path

# ==============================
# 🚀 PRODUCTION CONFIGURATION
# ==============================

# Production environment detection
IS_PRODUCTION = os.getenv('IS_PRODUCTION', 'false').lower() == 'true'

# Configure logging based on environment
if IS_PRODUCTION:
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s: %(message)s")
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# ==============================
# 🛡️ SECURITY ENHANCEMENTS
# ==============================

# 🔒 1. HTTPS ENFORCEMENT (High Priority)
if IS_PRODUCTION:
    @app.before_request
    def force_https():
        if request.headers.get('X-Forwarded-Proto') != 'https':
            return redirect(request.url.replace('http://', 'https://'), code=301)

# ✅ CONDITIONAL CORS - Production Ready
if not IS_PRODUCTION:
    CORS(app)
    logger.info("🔧 DEVELOPMENT: CORS enabled for all origins")
else:
    # Production CORS (more restrictive)
    allowed_origins = os.getenv('ALLOWED_ORIGINS', '').split(',')
    if allowed_origins and allowed_origins[0]:  # If specific origins provided
        CORS(app, origins=[origin.strip() for origin in allowed_origins if origin.strip()])
        logger.warning(f"🔒 PRODUCTION: CORS enabled for specific origins: {allowed_origins}")
    else:
        # No CORS in production (same-origin only)
        logger.warning("🔒 PRODUCTION: CORS disabled - same-origin requests only")

# 🛡️ 2. SECURITY HEADERS (High Priority)
if IS_PRODUCTION:
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

# 🚧 3. RATE LIMITING (Medium Priority)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"] if IS_PRODUCTION else ["1000 per hour"],
    storage_uri="memory://"
)

# ✅ PRODUCTION CONFIGURATIONS
if IS_PRODUCTION:
    app.config['DEBUG'] = False
    app.config['TESTING'] = False
    os.environ['FLASK_ENV'] = 'production'
else:
    app.config['DEBUG'] = True
    logger.info("🔧 DEVELOPMENT: Debug mode enabled")

# Import configuration
from config import OPENAI_API_KEY, FASTSPRING_API_USER, FASTSPRING_API_PASSWORD, FS_ACCOUNT_ENDPOINT_URL, FS_ORDER_ENDPOINT_URL

# ✅ Auth0 Configuration
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN', 'login.songwish.ca')

# FastSpring Products API endpoint
FS_PRODUCTS_ENDPOINT_URL = "https://api.fastspring.com/products"

# ==============================
# 🔍 4. ENHANCED INPUT VALIDATION
# ==============================

def validate_query_input(data):
    """Enhanced query validation"""
    if not data or not isinstance(data, dict):
        return "Invalid request format"
    
    query = data.get("query", "").strip()
    if not query:
        return "Query cannot be empty"
    
    # Length validation
    if len(query) > 2000:
        return "Query too long (max 2000 characters)"
    
    # Basic content validation
    dangerous_patterns = [
        '<script', 'javascript:', 'DROP TABLE', 'DELETE FROM', 
        'INSERT INTO', 'UPDATE SET', '<iframe', 'eval(', 'document.cookie'
    ]
    query_lower = query.lower()
    if any(pattern.lower() in query_lower for pattern in dangerous_patterns):
        return "Invalid query content detected"
    
    # Check for excessive special characters (possible injection attempt)
    special_char_count = len(re.findall(r'[<>"\';{}]', query))
    if special_char_count > 10:
        return "Query contains too many special characters"
    
    return None

def sanitize_string(text, max_length=1000):
    """Sanitize string input"""
    if not text:
        return ""
    
    # Truncate if too long
    text = str(text)[:max_length]
    
    # Escape HTML
    text = escape(text)
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    return text.strip()

# 🔧 5. REQUEST LOGGING (Security Monitoring)
if IS_PRODUCTION:
    @app.before_request
    def log_request_info():
        # Log suspicious requests
        user_agent = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Log potentially suspicious patterns
        if any(word in user_agent.lower() for word in ['bot', 'crawler', 'scanner']):
            logger.warning(f"Bot request from {ip_address}: {user_agent}")
        
        # Log authentication attempts
        if request.endpoint in ['lookup_account', 'query'] and request.method == 'POST':
            logger.info(f"API request to {request.endpoint} from {ip_address}")

# ==============================
# ✅ CONDITIONAL DECORATOR
# ==============================

def conditional_cross_origin():
    """Apply cross_origin only in development"""
    def decorator(f):
        if not IS_PRODUCTION:
            return cross_origin()(f)
        return f
    return decorator

# ==============================
# ✅ FASTSPRING-BASED PRODUCT FUNCTIONS
# ==============================

def get_product_category(product_details: dict) -> str:
    """Get category directly from FastSpring product data"""
    return product_details.get('attributes', {}).get('category', 'Other')

def is_product_free(product_path: str, price_value: float) -> bool:
    """Determine if a product is free/trial"""
    free_indicators = ['trial', 'free']
    return (price_value == 0.0 or 
            any(indicator in product_path.lower() for indicator in free_indicators))

def get_product_tags(product_details: dict, product_path: str, price_value: float) -> list:
    """Generate tags for a product using FastSpring data"""
    tags = []
    
    # Add category as tag (from FastSpring)
    category = get_product_category(product_details)
    tags.append(category.lower().replace(' ', '-'))
    
    # Add free/trial tags
    if is_product_free(product_path, price_value):
        if 'trial' in product_path.lower():
            tags.append('trial')
        else:
            tags.append('free')
    else:
        tags.append('paid')
    
    # Add specific product type tags
    if 'remidi' in product_path.lower():
        tags.append('midi-sampler')
        tags.append('vst')
    elif 'rechannel' in product_path.lower():
        tags.append('midi-effect')
        tags.append('vst')
    elif 'jazz' in product_path.lower():
        tags.append('jazz')
        tags.append('midi-files')
    elif 'sample-loops' in product_path.lower():
        tags.append('loops')
        tags.append('samples')
    
    return tags

# ==============================
# AUTH0 FUNCTIONS
# ==============================

def get_public_key(token):
    """Get Auth0 public key for JWT verification"""
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        
        jwks_url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
        response = requests.get(jwks_url)
        jwks = response.json()
        
        for key in jwks["keys"]:
            if key["kid"] == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        
        return None
    except Exception as e:
        logger.error(f"Failed to get public key: {e}")
        return None

def get_user_email_from_token(auth_header):
    """Extract user email from Auth0 token"""
    if not auth_header:
        return None
    
    try:
        token = auth_header.replace("Bearer ", "")
        key = get_public_key(token)
        if not key:
            logger.error("Could not get public key for token")
            return None
        
        payload = jwt.decode(
            token, 
            key, 
            algorithms=["RS256"], 
            audience="https://api.songwish.ca"
        )
        
        user_email = payload.get("email")
        
        if user_email:
            logger.info(f"✅ Token verified for user: {user_email}")
            return user_email
        else:
            logger.error("No email found in token")
            return None
            
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip authentication for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return jsonify({}), 200
            
        auth_header = request.headers.get("Authorization")
        user_email = get_user_email_from_token(auth_header)
        
        if not user_email:
            return jsonify({"error": "Authentication required"}), 401
        
        request.user_email = user_email
        return f(*args, **kwargs)
    
    return decorated_function

# ==============================
# ROUTE MAPPING & CONFIGURATION  
# ==============================

ROUTE_MAPPING = {
    "About.md": "/about",
    "privacy_policy.md": "/privacy-policy", 
    "refund_policy.md": "/refund-policy",
    "terms_and_conditions.md": "/terms-and-conditions",
    "marketing_policy.md": "/marketing-policy",
    "cookie_policy.md": "/cookie-policy",
    "support.md": "/support",
    "reMIDI_4_installation_instructions.md": "/remidi-4-installation",
    "reMIDI_4_user_manual.md": "/user-manuals/remidi-4-user-manual",
    "remidi4copy.md": "/products/remidi-4",
    "rechannelcopy.md": "/products/rechannel",
    "sampleloops1copy.md": "/products/sw-select-sample-loops-vol-1",
    "sampleloops2copy.md": "/products/sw-select-sample-loops-vol-2",
    "jazzcompletecopy.md": "/products/sw-jazz-complete-volumes-1-11",
    "songwish_landing_page.md": "/",
}

def get_all_route_mappings():
    """Get all available routes for navigation"""
    return {
        "/": "Home page with product showcase and features",
        "/about": "About SongWish company and team information", 
        "/support": "Customer support and help center",
        "/products": "All products overview page",
        "/products/plugins": "Audio plugins category page",
        "/products/sample-packs": "Sample packs category page", 
        "/products/free-downloads": "Free downloads and trials",
        "/products/deals": "Current deals and promotions",
        "/products/remidi-4": "reMIDI 4 MIDI plugin details and purchase",
        "/products/rechannel": "ReChannel audio plugin details",
        "/products/sw-select-sample-loops-vol-1": "Sample Loops Volume 1 pack",
        "/products/sw-select-sample-loops-vol-2": "Sample Loops Volume 2 pack", 
        "/products/sw-jazz-complete-volumes-1-11": "Complete Jazz sample collection",
        "/account": "User account dashboard (requires login)",
        "/user-manuals": "User manuals and documentation hub",
        "/user-manuals/remidi-4-user-manual": "Complete reMIDI 4 user manual",
        "/remidi-4-installation": "reMIDI 4 installation guide",
        "/privacy-policy": "Privacy policy and data handling",
        "/refund-policy": "Refund and return policy", 
        "/terms-and-conditions": "Terms of service and conditions",
        "/marketing-policy": "Marketing and communication policy",
        "/cookie-policy": "Cookie usage and consent policy",
        "/checkout": "Product purchase and payment page",
        "/products/purchase-success": "Order confirmation page"
    }

# ==============================
# FASTSPRING API INTEGRATION
# ==============================

def retrieve_fastspring_data(params=None):
    """Fetch data from FastSpring API with improved error handling"""
    headers = {
        "accept": "application/json",
        "User-Agent": "SongWish-API/1.0"
    }

    if not params:
        url = FS_ACCOUNT_ENDPOINT_URL
    elif len(params) == 1:
        (raw_key, value) = list(params.items())[0]
        value = unquote(value.strip())
        if raw_key.lower() == "order":
            raw_key = "orders"
        key = raw_key.lower()
        if key == "orders":
            url = f"{FS_ORDER_ENDPOINT_URL}/{value}"
        elif key == "email":
            url = f"{FS_ACCOUNT_ENDPOINT_URL}?email={value}"
        elif key in ["accountid", "account"]:
            url = f"{FS_ACCOUNT_ENDPOINT_URL}/{value}"
        else:
            url = f"{FS_ACCOUNT_ENDPOINT_URL}/{value}"
    else:
        url = FS_ACCOUNT_ENDPOINT_URL

    try:
        logger.info(f"FastSpring API call: {url}")
        
        response = requests.get(
            url, 
            auth=(FASTSPRING_API_USER, FASTSPRING_API_PASSWORD), 
            headers=headers,
            timeout=30,
            verify=True
        )
        
        logger.info(f"FastSpring response: {response.status_code}")
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": f"Not found: {url}"}
        else:
            logger.error(f"FastSpring API error {response.status_code}: {response.text}")
            return {"error": f"HTTP {response.status_code}: {response.text}"}
            
    except requests.exceptions.Timeout:
        logger.error("FastSpring API request timed out")
        return {"error": "Request timed out - FastSpring API may be slow"}
    except requests.exceptions.ConnectionError as e:
        logger.error(f"FastSpring API connection error: {e}")
        return {"error": f"Connection error: Unable to reach FastSpring API"}
    except requests.exceptions.RequestException as e:
        logger.error(f"FastSpring API request error: {e}")
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        logger.error(f"FastSpring API unexpected error: {e}")
        return {"error": f"Unexpected error: {str(e)}"}

def extract_language_content(data, preferred_lang='en'):
    """Extract content from FastSpring's language-specific data structure"""
    if not data:
        return ""
    
    if isinstance(data, dict):
        if preferred_lang in data:
            return data[preferred_lang]
        if 'default' in data:
            return data['default']
        if data:
            return list(data.values())[0]
        return ""
    
    return str(data) if data else ""

def get_all_available_products():
    """✅ UPDATED: Get current product catalog with live prices, deals, and FASTSPRING CATEGORIES"""
    try:
        headers = {"accept": "application/json", "User-Agent": "SongWish-API/1.0"}
        
        logger.info("Fetching live product catalog with FastSpring categories")
        
        # Get list of product IDs
        response = requests.get(
            FS_PRODUCTS_ENDPOINT_URL, 
            auth=(FASTSPRING_API_USER, FASTSPRING_API_PASSWORD), 
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 200:
            logger.error(f"FastSpring products API error: {response.status_code}")
            return {"error": f"Failed to fetch catalog: HTTP {response.status_code}"}
        
        products_data = response.json()
        product_ids = products_data.get("products", [])
        
        if not product_ids:
            return {"error": "No products found in catalog"}
        
        logger.info(f"Found {len(product_ids)} products in catalog")
        
        # For catalog browsing, fetch details for each product to get live prices
        formatted_products = []
        for product_id in product_ids:
            try:
                product_url = f"{FS_PRODUCTS_ENDPOINT_URL}/{product_id}"
                product_response = requests.get(
                    product_url,
                    auth=(FASTSPRING_API_USER, FASTSPRING_API_PASSWORD),
                    headers=headers,
                    timeout=30
                )
                
                if product_response.status_code == 200:
                    product_response_data = product_response.json()
                    
                    if 'products' in product_response_data and len(product_response_data['products']) > 0:
                        product_details = product_response_data['products'][0]
                        
                        # Extract display name
                        display_name = extract_language_content(product_details.get("display", {}), 'en')
                        if not display_name:
                            display_name = product_id.replace('-', ' ').title()
                        
                        # Extract current pricing
                        pricing_data = product_details.get("pricing", {})
                        price_data = pricing_data.get("price", {})
                        usd_price = 0
                        
                        if isinstance(price_data, dict):
                            usd_price = price_data.get('USD', 0) or 0
                        
                        # Extract description
                        description_data = product_details.get("description", {})
                        summary_text = extract_language_content(description_data.get("summary", {}), 'en')
                        
                        # ✅ FIXED: Get category and tags using FastSpring data
                        product_path = product_details.get("product", product_id)
                        category = get_product_category(product_details)  # Pass product_details
                        tags = get_product_tags(product_details, product_path, usd_price)  # Pass product_details
                        is_free = is_product_free(product_path, usd_price)
                        
                        # Get other attributes
                        attributes_data = product_details.get("attributes", {})
                        download = attributes_data.get("download", "")
                        
                        formatted_product = {
                            "path": product_path,
                            "image": product_details.get("image", "/api/placeholder/200/120"),
                            "display": display_name,
                            "price": f"${usd_price:.2f}",
                            "total": f"${usd_price:.2f}",
                            "priceValue": usd_price,  # Numeric price for filtering
                            "description": {"summary": summary_text},
                            "discount": None,
                            "discountPercent": None,
                            # ✅ FIXED: Category from FastSpring via function
                            "attributes": {
                                "category": category,  # Now from get_product_category()
                                "download": download
                            },
                            "categories": [category],  # For compatibility
                            "tags": tags,  # Now from updated get_product_tags()
                            "active": True,
                            "available": True,
                            "trial": 'trial' in product_path.lower(),
                            "subscription": False,  # Assuming no subscriptions
                            "sku": product_details.get("sku", product_id),
                            "is_free": is_free  # Add free indicator
                        }
                        
                        # Handle current deals/discounts
                        if "discount" in pricing_data and pricing_data["discount"]:
                            discount_info = pricing_data["discount"]
                            formatted_product["discount"] = {"reason": discount_info.get("reason", "")}
                            discount_percent = discount_info.get("percentage", 0)
                            formatted_product["discountPercent"] = f"{discount_percent}%"
                            discount_amount = usd_price * (discount_percent / 100)
                            final_price = usd_price - discount_amount
                            formatted_product["total"] = f"${final_price:.2f}"
                            formatted_product["priceValue"] = final_price
                        
                        formatted_products.append(formatted_product)
                        logger.info(f"Catalog: {display_name} - {formatted_product['total']} - Category: {category}")
                        
            except Exception as e:
                logger.error(f"Error fetching catalog details for {product_id}: {e}")
                continue
        
        logger.info(f"Live catalog: {len(formatted_products)} products with FastSpring categories")
        return {"products": formatted_products}
        
    except Exception as e:
        logger.error(f"Error fetching live catalog: {e}")
        return {"error": f"Failed to fetch catalog: {str(e)}"}

def extract_account_products(email):
    """Extract customer account data from their order history"""
    try:
        # Get account data by email
        account_data = retrieve_fastspring_data({"email": email})
        if "error" in account_data:
            return {"error": account_data["error"]}

        accounts_data = account_data.get("accounts", [])
        if not accounts_data:
            return {"error": "No account found for this email address"}

        result = {
            "customer_info": {},
            "orders": [],
            "total_orders": 0,
            "total_products": 0,
            "total_files": 0,
            "total_licenses": 0,
            "account_summary": "",
            "owned_products": []
        }

        for account in accounts_data:
            # Extract customer information
            if not result["customer_info"]:
                contact = account.get("contact", {})
                address = account.get("address", {})
                result["customer_info"] = {
                    "account_id": account.get("account", "N/A"),
                    "email": contact.get("email", email),
                    "first_name": contact.get("first", "N/A"),
                    "last_name": contact.get("last", "N/A"),
                    "full_name": f"{contact.get('first', '')} {contact.get('last', '')}".strip(),
                    "country": account.get("country", "N/A"),
                    "city": address.get("city", "N/A"),
                    "region": address.get("region", "N/A"),
                    "postal_code": address.get("postalCode", "N/A")
                }

            # Create mapping of order IDs to charge information
            order_info_map = {}
            charges = account.get("charges", [])
            for charge in charges:
                if "order" in charge:
                    order_info_map[charge["order"]] = {
                        "date": charge.get("timestampDisplay", "N/A"),
                        "utc_timestamp": charge.get("timestamp", 0),
                        "reference": charge.get("orderReference", "N/A"),
                        "total": charge.get("total", 0),
                        "currency": charge.get("currency", "USD"),
                        "status": charge.get("status", "unknown")
                    }

            # Process each order (keeping existing code for brevity)
            orders_list = account.get("orders", [])
            logger.info(f"Processing {len(orders_list)} orders for {email}")
            
            for order_id in orders_list:
                try:
                    order_details = retrieve_fastspring_data({"orders": order_id})
                    if "error" in order_details:
                        logger.warning(f"Failed to get order details for {order_id}: {order_details['error']}")
                        continue
                    
                    order_info = order_info_map.get(order_id, {})
                    
                    # Convert UTC timestamp to readable date
                    utc_date = "N/A"
                    if order_info.get("utc_timestamp"):
                        try:
                            utc_date = datetime.utcfromtimestamp(order_info["utc_timestamp"] / 1000).strftime('%Y-%m-%d %H:%M:%S UTC')
                        except:
                            utc_date = "N/A"

                    order_data = {
                        "order_id": order_id,
                        "order_reference": order_info.get("reference", "N/A"),
                        "date": order_info.get("date", "N/A"),
                        "utc_date": utc_date,
                        "total": order_info.get("total", 0),
                        "currency": order_info.get("currency", "USD"),
                        "status": order_info.get("status", "unknown"),
                        "products": [],
                        "files": [],
                        "licenses": []
                    }

                    # Extract products from order items
                    items_list = order_details.get("items", [])
                    for item in items_list:
                        if isinstance(item, dict):
                            subtotal = item.get("subtotal", 0)
                            product = {
                                "display": item.get("display", "N/A"),
                                "product_id": item.get("product", "N/A"),
                                "quantity": item.get("quantity", 1),
                                "coupon": item.get("coupon", "N/A"),
                                "subtotal": subtotal,
                                "subtotal_display": item.get("subtotalDisplay", f"${subtotal:.2f}"),
                                "sku": item.get("sku", "N/A")
                            }
                            order_data["products"].append(product)
                            
                            # Add to owned products list
                            owned_product = {
                                "path": item.get("product", "N/A"),
                                "display": item.get("display", "N/A"),
                                "purchaseDate": order_info.get("date", "N/A"),
                                "orderId": order_id,
                                "orderReference": order_info.get("reference", "N/A"),
                                "price": subtotal,
                                "price_display": item.get("subtotalDisplay", f"${subtotal:.2f}"),
                                "currency": order_info.get("currency", "USD"),
                                "sku": item.get("sku", "N/A")
                            }
                            result["owned_products"].append(owned_product)

                            # Extract fulfillments (files and licenses)
                            fulfillments = item.get("fulfillments", {})
                            for fulfillment_key, fulfillment_value in fulfillments.items():
                                if fulfillment_key == "instructions":
                                    continue
                                    
                                if isinstance(fulfillment_value, list):
                                    for fulfillment_item in fulfillment_value:
                                        if isinstance(fulfillment_item, dict):
                                            fulfillment_type = fulfillment_item.get("type", "")
                                            
                                            if fulfillment_type == "file" and "file" in fulfillment_item:
                                                file_info = {
                                                    "display": fulfillment_item.get("display", "N/A"),
                                                    "file_url": fulfillment_item.get("file", "N/A"),
                                                    "product": product["display"],
                                                    "product_id": product["product_id"],
                                                    "size": fulfillment_item.get("size", 0),
                                                    "size_mb": round(fulfillment_item.get("size", 0) / (1024*1024), 1),
                                                    "type": fulfillment_type,
                                                    "fulfillment_key": fulfillment_key
                                                }
                                                order_data["files"].append(file_info)
                                                
                                            elif fulfillment_type == "license" and "license" in fulfillment_item:
                                                license_info = {
                                                    "display": fulfillment_item.get("display", "N/A"),
                                                    "license_key": fulfillment_item.get("license", "N/A"),
                                                    "product": product["display"],
                                                    "product_id": product["product_id"],
                                                    "type": fulfillment_type,
                                                    "fulfillment_key": fulfillment_key
                                                }
                                                order_data["licenses"].append(license_info)

                    result["orders"].append(order_data)
                    
                except Exception as e:
                    logger.error(f"Error processing order {order_id}: {e}")
                    continue

        # Calculate totals
        result["total_orders"] = len(result["orders"])
        result["total_products"] = sum(len(order["products"]) for order in result["orders"])
        result["total_files"] = sum(len(order["files"]) for order in result["orders"])
        result["total_licenses"] = sum(len(order["licenses"]) for order in result["orders"])

        # Create account summary
        customer = result["customer_info"]
        result["account_summary"] = f"""
CUSTOMER ACCOUNT INFORMATION FOR {customer['full_name']} ({customer['email']}):

Customer Details:
- Account ID: {customer['account_id']}
- Name: {customer['full_name']}
- Email: {customer['email']}
- Location: {customer['city']}, {customer['region']}, {customer['country']}

Account Summary:
- Total Orders: {result['total_orders']}
- Total Products Purchased: {result['total_products']}
- Total Download Files: {result['total_files']}
- Total License Keys: {result['total_licenses']}

PURCHASE HISTORY:
"""
        for order in result["orders"]:
            total_mb = sum([f['size_mb'] for f in order['files']])
            result["account_summary"] += f"""
Order #{order['order_reference']} (ID: {order['order_id']}):
- Date: {order['date']}
- Total: {order['currency']} {order['total']}
- Status: {order['status']}
- Products: {', '.join([f"{p['display']} ({p['subtotal_display']})" for p in order['products']])}
- Downloads: {len(order['files'])} files available ({total_mb} MB total)
- License Keys: {len(order['licenses'])} keys issued
"""

        logger.info(f"Account extraction complete for {email}: {result['total_orders']} orders, {result['total_products']} products")
        return result

    except Exception as e:
        logger.error(f"Error extracting account data for {email}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {"error": f"Failed to extract account data: {str(e)}"}

# ==============================
# RAG/AI SYSTEM WITH S3 CONTENT
# ==============================

# Clean content folder structure
docs_path = "content"
embedding = OpenAIEmbeddings(api_key=OPENAI_API_KEY)
vector_db_cache = None

def initialize_vector_db():
    """Initialize vector database with automatic S3 content fetching"""
    global vector_db_cache
    if vector_db_cache:
        return vector_db_cache
    
    # Ensure content directory exists
    if not os.path.exists(docs_path):
        os.makedirs(docs_path, exist_ok=True)
        logger.info(f"📁 Created content directory: {docs_path}")
    
    # 🔧 Self-healing content fetch from S3
    if not os.listdir(docs_path):  # folder exists but is empty
        logger.warning("📚 Content folder is empty, fetching from S3...")
        try:
            result = subprocess.run(["python", "scripts/fetch_docs.py"], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                logger.error(f"❌ Failed to fetch content from S3: {result.stderr}")
                return None
            logger.info("✅ Successfully fetched content from S3")
            logger.info(f"📄 Fetch output: {result.stdout}")
        except subprocess.TimeoutExpired:
            logger.error("❌ Content fetch timed out")
            return None
        except Exception as e:
            logger.error(f"❌ S3 content fetch error: {e}")
            return None
    
    # Load all .md files from content directory
    loader = DirectoryLoader(
        docs_path,
        glob="*.md",
        loader_cls=TextLoader,
        loader_kwargs={"encoding": "utf-8"},
    )
    documents = loader.load()
    
    # Add route metadata to each document
    enhanced_documents = []
    for doc in documents:
        filename = os.path.basename(doc.metadata.get('source', ''))
        route = ROUTE_MAPPING.get(filename, '')
        doc.metadata['route'] = route
        doc.metadata['type'] = 'content_markdown'
        enhanced_documents.append(doc)
        logger.info(f"📄 Loaded content: {filename} → {route}")
    
    if not enhanced_documents:
        logger.error("❌ No content documents loaded")
        return None
    
    # Split documents
    header_splitter = MarkdownHeaderTextSplitter(headers_to_split_on=[
        ("#", "header1"),
        ("##", "header2"),
        ("###", "header3"),
        ("####", "header4"),
    ])
    
    text_splitter = MarkdownTextSplitter(chunk_size=1500, chunk_overlap=50)
    
    chunks = []
    for doc in enhanced_documents:
        try:
            header_splits = header_splitter.split_text(doc.page_content)
            for split in header_splits:
                recursive_chunks = text_splitter.split_text(split.page_content)
                for chunk_text in recursive_chunks:
                    combined_metadata = {**doc.metadata, **split.metadata}
                    chunks.append(Document(page_content=chunk_text, metadata=combined_metadata))
        except Exception as e:
            logger.error(f"❌ Error processing content: {doc.metadata.get('source', 'unknown')}: {e}")
            continue
    
    logger.info(f"📚 Created {len(chunks)} content chunks from {len(enhanced_documents)} documents")
    
    try:
        vector_db_cache = Chroma.from_documents(chunks, embedding)
        logger.info("✅ Vector database initialized successfully with S3 content")
        return vector_db_cache
    except Exception as e:
        logger.error(f"❌ Failed to create vector database: {e}")
        return None

def build_personalized_prompt(context: str, query: str, account_data: str = "", owned_products: list = None, available_products: list = None, customer_info: dict = None) -> str:
    """Enhanced prompt with personalized greeting using customer's first name"""
    if owned_products is None:
        owned_products = []
    if available_products is None:
        available_products = []
    
    # Simple route context
    routes = get_all_route_mappings()
    route_context = "AVAILABLE NAVIGATION ROUTES:\n"
    for route, description in routes.items():
        route_context += f"- {route} : {description}\n"
    
    route_context += "\nNAVIGATION RULES:\n"
    route_context += "- Use simple markdown links: [visit reMIDI 4](/products/remidi-4)\n"
    route_context += "- Guide users to relevant products and pages\n"
    route_context += "- Focus on helping users find and buy products\n"
    
    # Enhanced system identity with personalization
    customer_name = ""
    if customer_info:
        first_name = customer_info.get('first_name', '').strip()
        if first_name and first_name != 'N/A':
            customer_name = first_name
    
    greeting_instruction = ""
    if customer_name:
        greeting_instruction = f"""
PERSONALIZATION:
- The customer's name is {customer_name}
- Use their first name in greetings: "Hi {customer_name}!" or "Hello {customer_name}!"
- Be warm and personal, like greeting a returning customer
- Make them feel recognized and valued
"""
    else:
        greeting_instruction = """
PERSONALIZATION:
- Customer is not logged in or no name available
- Use friendly generic greetings: "Hi there!" or "Hello!"
- Still be warm and welcoming
"""

    system_identity = f"""
You are the SongWish AI Shopping Assistant. Help users find and buy music production products.

{greeting_instruction}

CORE MISSION:
- Help users discover the right products for their needs
- Guide them to product pages where they can learn more and purchase
- Provide simple, helpful navigation through the store
- Focus on the shopping experience
- Be personal and friendly, especially with returning customers

PRODUCT RECOMMENDATIONS:
- When users ask about specific products, recommend them
- When users ask about capabilities or tools, suggest relevant products
- Always try to show users products that solve their problems
- Guide them to product pages for more details

SIMPLE NAVIGATION:
- Use clean markdown links: [visit reMIDI 4](/products/remidi-4)
- Keep responses focused on helping users shop and explore products
- Be friendly and helpful like a great shopping assistant

GREETING STYLE:
- Start responses with a personalized greeting when appropriate
- Use the customer's name if available
- Be conversational and welcoming
"""

    # Format available products
    products_for_prompt = ""
    if available_products:
        products_for_prompt = "AVAILABLE PRODUCTS TO RECOMMEND:\n"
        for product in available_products:
            name = product.get('display', 'Unknown')
            description = product.get('description', {}).get('summary', 'No description')
            price = product.get('total', 'N/A')
            category = product.get('attributes', {}).get('category', 'Other')
            discount_info = ""
            if product.get('discount') and product.get('discountPercent'):
                discount_info = f" (ON SALE: {product.get('discountPercent')} OFF)"
            products_for_prompt += f"- {name} [{category}]: {description} - {price}{discount_info}\n"
        products_for_prompt += "\nONLY recommend products from this list.\n"
    
    # Build enhanced template
    template = f"""
{system_identity}

{route_context}

{products_for_prompt}

KNOWLEDGE BASE CONTEXT:
{context}

{"CUSTOMER ACCOUNT DATA:" if account_data else ""}
{account_data}

CUSTOMER QUERY: {query}

Remember: You are a helpful shopping assistant. Be personal and welcoming, especially if you know the customer's name. Focus on helping users find and buy the right products. Use simple navigation links and recommend relevant products from our catalog.
"""
    return template.strip()

def extract_cited_sources(response_text: str, source_names: list) -> list:
    """Extract cited source names from response text"""
    cited_patterns = re.findall(r'\[Source (\d+)\]', response_text)
    cited_indices = []
    for pattern in cited_patterns:
        idx = int(pattern) - 1
        if 0 <= idx < len(source_names):
            cited_indices.append(idx)
    unique_indices = sorted(set(cited_indices))
    cited_sources = [source_names[i] for i in unique_indices]
    return cited_sources

# ==============================
# ✅ API ENDPOINTS WITH SECURITY ENHANCEMENTS
# ==============================

@app.route("/products/categories", methods=["GET", "OPTIONS"])
@limiter.limit("100 per minute")
@conditional_cross_origin()
def get_categories():
    """Get all available product categories from FastSpring"""
    if request.method == "OPTIONS" and not IS_PRODUCTION:
        return jsonify({}), 200
    
    try:
        # Get categories dynamically from FastSpring products
        products_result = get_all_available_products()
        if "error" in products_result:
            return jsonify({"error": products_result["error"]}), 500
        
        # Extract unique categories
        categories = list(set([
            product.get('attributes', {}).get('category', 'Other') 
            for product in products_result.get("products", [])
        ]))
        categories.sort()
        
        return jsonify({
            "categories": categories,
            "total": len(categories)
        }), 200
        
    except Exception as e:
        logger.error(f"Error in get_categories: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/products/category/<category_name>", methods=["GET", "OPTIONS"])
@limiter.limit("100 per minute")
@conditional_cross_origin()
def get_products_by_category(category_name):
    """Get products filtered by category"""
    if request.method == "OPTIONS" and not IS_PRODUCTION:
        return jsonify({}), 200
    
    try:
        # Get all products
        products_result = get_all_available_products()
        if "error" in products_result:
            return jsonify({"error": products_result["error"]}), 500
        
        # Filter by category
        all_products = products_result["products"]
        filtered_products = []
        
        for product in all_products:
            product_category = product.get('attributes', {}).get('category', 'Other')
            if product_category.lower() == category_name.lower():
                filtered_products.append(product)
        
        return jsonify({
            "products": filtered_products,
            "category": category_name,
            "total": len(filtered_products)
        }), 200
        
    except Exception as e:
        logger.error(f"Error in get_products_by_category: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/lookup_account", methods=["POST", "OPTIONS"])
@limiter.limit("10 per minute" if IS_PRODUCTION else "50 per minute")
@conditional_cross_origin()
@require_auth
def lookup_account():
    """🔒 Look up customer account - uses JWT validation"""
    if request.method == "OPTIONS" and not IS_PRODUCTION:
        return jsonify({}), 200
    
    try:
        # Email comes from JWT token validation in decorator
        user_email = request.user_email
        
        logger.info(f"🔒 Account lookup for {user_email}")
        
        account_data = extract_account_products(user_email)
        
        if "error" in account_data:
            return jsonify({"error": account_data["error"]}), 404
        
        logger.info(f"✅ Account data retrieved for {user_email}")
        return jsonify(account_data), 200
        
    except Exception as e:
        logger.error(f"Error in lookup_account: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/products", methods=["GET", "OPTIONS"])
@limiter.limit("100 per minute")
@conditional_cross_origin()
def get_products():
    """Get current product catalog with categories - PUBLIC ENDPOINT"""
    if request.method == "OPTIONS" and not IS_PRODUCTION:
        return jsonify({}), 200
    
    try:
        products_result = get_all_available_products()
        if "error" in products_result:
            return jsonify({"error": products_result["error"]}), 500
        return jsonify(products_result), 200
    except Exception as e:
        logger.error(f"Error in get_products: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/query", methods=["POST", "OPTIONS"])
@limiter.limit("20 per minute" if IS_PRODUCTION else "100 per minute")
@conditional_cross_origin()
def query():
    """🛡️ SECURED AI query handler with personalized greetings"""
    if request.method == "OPTIONS":
        return jsonify({}), 200  # ✅ Handle CORS preflight
    
    try:
        data = request.get_json()
        
        # ✅ NEW: Enhanced validation
        validation_error = validate_query_input(data)
        if validation_error:
            logger.warning(f"Query validation failed: {validation_error}")
            return jsonify({"error": validation_error}), 400
        
        # ✅ NEW: Sanitize input
        user_query = sanitize_string(data["query"], max_length=2000)
        
        if not user_query:
            return jsonify({"error": "Query cannot be empty"}), 400
        
        k = data.get("k", 3)
        citations = data.get("citations", False)
        include_products = data.get("include_products", False)
        
        logger.info(f"Processing query: '{user_query}'")
        
        # Get customer info for personalization
        account_data = ""
        owned_products = []
        user_email = None
        customer_info = None
        
        auth_header = request.headers.get("Authorization")
        if auth_header:
            user_email = get_user_email_from_token(auth_header)
            if user_email:
                account_info = extract_account_products(user_email)
                if "error" not in account_info:
                    account_data = account_info["account_summary"]
                    owned_products = account_info.get("owned_products", [])
                    customer_info = account_info.get("customer_info", {})
                    logger.info(f"🔒 Using account data for {user_email}")
        
        # Get available products if requested
        available_products = []
        if include_products:
            products_result = get_all_available_products()
            if "error" not in products_result:
                available_products = products_result["products"]
        
        # Initialize vector database
        vectordb = initialize_vector_db()
        if not vectordb:
            return jsonify({"error": "Vector database not initialized"}), 500
        
        # Retrieve relevant documents
        retriever = vectordb.as_retriever(search_kwargs={"k": k})
        docs = retriever.invoke(user_query)
        
        if not docs and not account_data:
            response_data = {
                "response": "I don't have information about that. Let me check with my team and get back to you shortly.",
                "sources": [],
                "query": user_query,
                "citations_enabled": citations,
                "account_data_used": False,
                "customer_info": None,
                "recommended_products": []
            }
            return jsonify(response_data)
        
        # Process sources
        source_to_content = {}
        source_names = []
        for doc in docs:
            source_name = os.path.basename(doc.metadata.get('source', 'Unknown'))
            if source_name not in source_to_content:
                source_to_content[source_name] = []
                source_names.append(source_name)
            source_to_content[source_name].append(doc.page_content)
        
        # Build context
        context_with_sources = ""
        for i, source_name in enumerate(source_names, 1):
            context_with_sources += f"[Source {i}: {source_name}]\n"
            combined_content = "\n".join(source_to_content[source_name])
            context_with_sources += f"{combined_content}\n\n"
        
        # Generate personalized response
        prompt = build_personalized_prompt(context_with_sources, user_query, account_data, owned_products, available_products, customer_info)
        llm = ChatOpenAI(model_name="gpt-4", api_key=OPENAI_API_KEY, temperature=0.1)
        response = llm.invoke(prompt)
        response_text = response.content
        
        # Process citations if enabled
        cited_sources = []
        if citations:
            cited_sources = extract_cited_sources(response_text, source_names)
        
        # Get product recommendations
        recommended_products = []
        # Note: AI assistant handles product recommendations via natural language routing
        
        # Build response with customer info (not email)
        response_data = {
            "response": response_text,
            "sources": cited_sources,
            "query": user_query,
            "citations_enabled": citations,
            "navigation_enabled": citations,
            "account_data_used": bool(account_data),
            "customer_info": customer_info if customer_info else None,
            "recommended_products": recommended_products
        }
        
        return jsonify(response_data)
    
    except Exception as e:
        logger.error(f"Unexpected error in query processing: {e}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@app.route("/status")
def status():
    """Enhanced production-ready status check with security information"""
    vector_db_status = "not initialized"
    if vector_db_cache is not None:
        vector_db_status = "cached and ready"
    elif os.path.exists(docs_path):
        content_files = list(Path(docs_path).glob("*.md"))
        vector_db_status = f"content available ({len(content_files)} files), not yet initialized"
    else:
        vector_db_status = f"content folder missing: {docs_path}"
    
    # Test FastSpring API
    fastspring_status = "unknown"
    try:
        test_result = retrieve_fastspring_data({"email": "test@test.com"})
        if "error" in test_result and "HTTP 404" in test_result["error"]:
            fastspring_status = "connected (no test account found - normal)"
        elif "error" not in test_result:
            fastspring_status = "connected"
        else:
            fastspring_status = f"error: {test_result['error']}"
    except Exception as e:
        fastspring_status = f"error: {str(e)}"
    
    # Test OpenAI
    openai_status = "unknown"
    try:
        test_embedding = OpenAIEmbeddings(api_key=OPENAI_API_KEY)
        test_embedding.embed_query("test")
        openai_status = "connected"
    except Exception as e:
        openai_status = f"connection error: {str(e)}"
    
    # Test products API and get dynamic categories
    products_status = "unknown"
    categories_status = "unknown"
    try:
        products_result = get_all_available_products()
        if "error" not in products_result:
            products_count = len(products_result.get("products", []))
            products_status = f"connected ({products_count} products available with FastSpring categories)"
            
            # Get dynamic categories
            categories = list(set([
                product.get('attributes', {}).get('category', 'Other') 
                for product in products_result.get("products", [])
            ]))
            categories_status = f"available ({len(categories)} categories: {', '.join(sorted(categories))})"
        else:
            products_status = f"error: {products_result['error']}"
    except Exception as e:
        products_status = f"error: {str(e)}"
        categories_status = f"error: {str(e)}"
    
    return jsonify({
        "status": "🛡️ SECURED PRODUCTION-READY SONGWISH API" if IS_PRODUCTION else "🔧 DEVELOPMENT MODE WITH SECURITY",
        "environment": "production" if IS_PRODUCTION else "development",
        "cors_enabled": not IS_PRODUCTION or bool(os.getenv('ALLOWED_ORIGINS')),
        "debug_mode": app.config.get('DEBUG', False),
        "content_folder": docs_path,
        "vector_db": vector_db_status,
        "fastspring_api": fastspring_status,
        "fastspring_products": products_status,
        "product_categories": categories_status,
        "openai_api": openai_status,
        "auth0_domain": AUTH0_DOMAIN,
        "features": [
            "🛡️ Security-hardened production deployment" if IS_PRODUCTION else "🔧 Development mode with security",
            "🔒 HTTPS enforcement (production)",
            "🛡️ Security headers protection",
            "🚧 Rate limiting protection",
            "🔍 Enhanced input validation",
            "📋 Request logging and monitoring",
            "🔒 Conditional CORS handling",
            "📦 FastSpring account data extraction", 
            "🛍️ Live product catalog with FastSpring categories",
            "🏷️ Dynamic category filtering",
            "🤖 AI shopping assistant with personalization",
            "🧭 Simple navigation",
            "💡 Product recommendations",
            "📚 RAG content search",
            "☁️ Automatic S3 content fetching"
        ],
        "endpoints": [
            "/products - Get all products [100/min]",
            "/products/categories - Get all categories [100/min]",
            "/products/category/<name> - Filter by category [100/min]",
            "/query - AI assistant [20/min prod, 100/min dev]",
            "/lookup_account - Customer account [10/min prod, 50/min dev] (auth required)"
        ],
        "security": {
            "https_enforcement": "enabled" if IS_PRODUCTION else "disabled (dev only)",
            "security_headers": "enabled" if IS_PRODUCTION else "disabled (dev only)",
            "rate_limiting": "enabled",
            "input_validation": "enabled (enhanced)",
            "request_logging": "enabled" if IS_PRODUCTION else "disabled (dev only)",
            "cors": "disabled" if IS_PRODUCTION and not os.getenv('ALLOWED_ORIGINS') else "configured",
            "debug": "disabled" if IS_PRODUCTION else "enabled",
            "logging": "warning+" if IS_PRODUCTION else "info+",
            "jwt_auth": "enabled"
        },
        "rate_limits": {
            "default": ["200 per day", "50 per hour"] if IS_PRODUCTION else ["1000 per hour"],
            "query_endpoint": "20/min" if IS_PRODUCTION else "100/min",
            "account_lookup": "10/min" if IS_PRODUCTION else "50/min",
            "public_endpoints": "100/min"
        },
        "s3_integration": "✅ AUTOMATIC - self-healing content fetch",
        "message": f"🛡️ SongWish API running in {'SECURED PRODUCTION' if IS_PRODUCTION else 'DEVELOPMENT WITH SECURITY'} mode with FastSpring categories!"
    })

@app.route("/docs", methods=["GET"])
@limiter.limit("50 per minute")
@conditional_cross_origin()
def list_documents():
    """List all available documents and their route mappings"""
    try:
        if not os.path.exists(docs_path):
            return jsonify({"error": f"Documents folder not found: {docs_path}"}), 404
        
        md_files = [f for f in os.listdir(docs_path) if f.endswith('.md')]
        file_info = []
        
        for filename in md_files:
            file_path = os.path.join(docs_path, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                file_info.append({
                    "filename": filename,
                    "route": ROUTE_MAPPING.get(filename, "No route mapped"),
                    "size": len(content),
                    "has_mapping": filename in ROUTE_MAPPING
                })
            except Exception as e:
                file_info.append({
                    "filename": filename, 
                    "error": f"Could not read file: {str(e)}"
                })
        
        return jsonify({
            "documents_folder": docs_path,
            "total_files": len(md_files),
            "mapped_files": len([f for f in md_files if f in ROUTE_MAPPING]),
            "files": file_info,
            "route_mappings": ROUTE_MAPPING
        })
        
    except Exception as e:
        return jsonify({"error": f"Error listing documents: {str(e)}"}), 500

@app.route("/")
@limiter.limit("20 per minute")
def index():
    """Basic web interface"""
    return render_template('index.html')

# Force vector database initialization at startup
logger.warning("🔄 Initializing vector database at startup...")
vector_db_cache = initialize_vector_db()
if vector_db_cache:
    logger.warning("✅ Vector database ready!")
else:
    logger.error("❌ Vector database failed to initialize!")

if __name__ == "__main__":
    env_status = "SECURED PRODUCTION" if IS_PRODUCTION else "DEVELOPMENT WITH SECURITY"
    logger.warning(f"🛡️ Starting SongWish AI Shopping Assistant in {env_status} mode...")
    logger.warning(f"🔒 Auth0 Domain: {AUTH0_DOMAIN}")
    logger.warning(f"📁 Content folder: {docs_path}")
    logger.warning(f"🛡️ Security: {'Full production security enabled' if IS_PRODUCTION else 'Development with security features'}")
    if IS_PRODUCTION:
        logger.warning("🔒 HTTPS enforcement: ENABLED")
        logger.warning("🛡️ Security headers: ENABLED")
        logger.warning("📋 Request logging: ENABLED")
    
    # Rate limiting info
    rate_limits = ["200 per day", "50 per hour"] if IS_PRODUCTION else ["1000 per hour"]
    logger.warning(f"🚧 Rate limiting: ENABLED ({rate_limits})")
    logger.warning("🔍 Input validation: ENHANCED")
    logger.warning(f"🎵 Features: AI Shopping Assistant + FastSpring Integration + S3 Content")
    logger.warning(f"🏷️ Categories: Dynamic FastSpring categories")
    app.run(debug=not IS_PRODUCTION, port=5000)