import json
import datetime
import os
import random
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # needed for session

# Logging function to capture all user actions
def log_action(action_type, details):
    if not isinstance(details, dict):
        details = {}
    log_entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'action_type': action_type,
        'details': details
    }
    with open('login_attempts.log', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

# Example fake toy product data
PRODUCTS = [
    {
        'id': 1,
        'name': 'LEGO Star Wars Millennium Falcon',
        'price': 159.99,
        'image': 'https://images.unsplash.com/photo-1519125323398-675f0ddb6308?auto=format&fit=crop&w=400&q=80',
        'desc': 'Iconic Star Wars spaceship with 1,329 pieces. Perfect for ages 9+ and Star Wars fans.',
        'shipping_weight': 2.8,
        'category': 'Building Sets',
        'age_range': '9+',
        'rating': 4.9,
        'reviews': 1247
    },
    {
        'id': 2,
        'name': 'Hot Wheels Ultimate Garage',
        'price': 49.99,
        'image': 'https://images.unsplash.com/photo-1519125323398-675f0ddb6308?auto=format&fit=crop&w=400&q=80',
        'desc': 'Multi-level garage with ramps, elevator, and 5 Hot Wheels cars included.',
        'shipping_weight': 3.2,
        'category': 'Vehicles & Cars',
        'age_range': '3+',
        'rating': 4.7,
        'reviews': 892
    },
    {
        'id': 3,
        'name': 'Barbie Dreamhouse',
        'price': 199.99,
        'image': 'https://images.unsplash.com/photo-1519125323398-675f0ddb6308?auto=format&fit=crop&w=400&q=80',
        'desc': '3-story dollhouse with elevator, pool, and 70+ accessories.',
        'shipping_weight': 8.5,
        'category': 'Dolls & Accessories',
        'age_range': '3+',
        'rating': 4.6,
        'reviews': 445
    },
    {
        'id': 4,
        'name': 'Nerf N-Strike Elite Disruptor',
        'price': 19.99,
        'image': 'https://images.unsplash.com/photo-1519125323398-675f0ddb6308?auto=format&fit=crop&w=400&q=80',
        'desc': '6-dart rotating drum blaster with tactical rail for accessories.',
        'shipping_weight': 1.1,
        'category': 'Outdoor & Sports',
        'age_range': '8+',
        'rating': 4.8,
        'reviews': 1567
    },
    {
        'id': 5,
        'name': 'Play-Doh Kitchen Creations',
        'price': 24.99,
        'image': 'https://images.unsplash.com/photo-1519125323398-675f0ddb6308?auto=format&fit=crop&w=400&q=80',
        'desc': 'Kitchen set with 20 Play-Doh colors and food-making tools.',
        'shipping_weight': 2.3,
        'category': 'Arts & Crafts',
        'age_range': '3+',
        'rating': 4.5,
        'reviews': 723
    },
    {
        'id': 6,
        'name': 'Monopoly Junior',
        'price': 15.99,
        'image': 'https://images.unsplash.com/photo-1519125323398-675f0ddb6308?auto=format&fit=crop&w=400&q=80',
        'desc': 'Simplified version of the classic board game for younger players.',
        'shipping_weight': 1.8,
        'category': 'Board Games',
        'age_range': '5+',
        'rating': 4.4,
        'reviews': 2156
    },
    {
        'id': 7,
        'name': 'Remote Control Robot',
        'price': 39.99,
        'image': 'https://images.unsplash.com/photo-1519125323398-675f0ddb6308?auto=format&fit=crop&w=400&q=80',
        'desc': 'Programmable robot with LED eyes, voice commands, and dance moves.',
        'shipping_weight': 1.5,
        'category': 'Electronic Toys',
        'age_range': '6+',
        'rating': 4.3,
        'reviews': 567
    },
    {
        'id': 8,
        'name': 'Wooden Building Blocks Set',
        'price': 29.99,
        'image': 'https://images.unsplash.com/photo-1519125323398-675f0ddb6308?auto=format&fit=crop&w=400&q=80',
        'desc': '100-piece natural wood building blocks for creative construction play.',
        'shipping_weight': 2.1,
        'category': 'Building Sets',
        'age_range': '1+',
        'rating': 4.7,
        'reviews': 1892
    }
]

# In-memory reviews storage (for demo, not persistent)
REVIEWS = {}

# Shipping rates
SHIPPING_RATES = {
    'standard': {'cost': 5.99, 'days': '3-5 business days'},
    'expedited': {'cost': 12.99, 'days': '2-3 business days'},
    'overnight': {'cost': 24.99, 'days': '1 business day'}
}

def calculate_shipping(cart_items):
    total_weight = sum(item['product']['shipping_weight'] * item['quantity'] for item in cart_items)
    if total_weight <= 5:
        return SHIPPING_RATES['standard']
    elif total_weight <= 15:
        return SHIPPING_RATES['expedited']
    else:
        return SHIPPING_RATES['overnight']

def admin_required(f):
    def wrapper(*args, **kwargs):
        if 'username' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/')
def home():
    # Get featured products (first 4 products for demo)
    featured_products = PRODUCTS[:4]
    log_action('visit_home', {})
    return render_template('home.html', featured_products=featured_products)

@app.route('/products')
def products():
    # VULNERABLE: SQL injection in search parameter
    search_query = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    age_filter = request.args.get('age', '')
    
    # VULNERABLE: Direct string concatenation for SQL injection simulation
    if search_query:
        fake_sql_query = f"SELECT * FROM products WHERE name LIKE '%{search_query}%' OR description LIKE '%{search_query}%'"
        log_action('product_search', {'search_query': search_query, 'sql_query': fake_sql_query})
    
    # Filter products based on search (simulating database query)
    filtered_products = PRODUCTS
    if search_query:
        filtered_products = [p for p in PRODUCTS if search_query.lower() in p['name'].lower() or search_query.lower() in p['desc'].lower()]
    if category_filter:
        filtered_products = [p for p in filtered_products if p['category'] == category_filter]
    if age_filter:
        filtered_products = [p for p in filtered_products if age_filter in p['age_range']]
    
    log_action('view_products', {'search_query': search_query, 'category': category_filter, 'age': age_filter})
    return render_template('products.html', products=filtered_products, search_query=search_query, category_filter=category_filter, age_filter=age_filter)

@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product_detail(product_id):
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if not product:
        return "Product not found", 404
    if request.method == 'POST':
        # Accept review (simulate XSS/HTML injection)
        review = request.form.get('review', '')
        REVIEWS.setdefault(product_id, []).append(review)
        log_action('review_submitted', {'product_id': product_id, 'review': review})
    log_action('view_product', {'product_id': product_id})
    product_reviews = REVIEWS.get(product_id, [])
    return render_template('product_detail.html', product=product, reviews=product_reviews)

@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if request.method == 'POST':
        # Accept both JSON and form submissions
        if request.is_json:
            data = request.get_json() or {}
            product_id = data.get('product_id')
        else:
            product_id = request.form.get('product_id')
        log_action('add_to_cart', {'product_id': product_id})
        # Fake cart logic: just log, don't actually store
        if request.is_json:
            return jsonify({'success': True, 'message': 'Added to cart!'})
        else:
            return redirect(url_for('cart'))
    
    # For GET request, create sample cart items for demonstration
    cart_items = []
    # Add a sample item to the cart for demonstration
    if PRODUCTS:
        sample_product = PRODUCTS[0]  # Use first product as sample
        cart_items.append({
            'product': sample_product,
            'quantity': 1,
            'item_total': sample_product['price']
        })
    
    # Calculate shipping
    shipping = calculate_shipping(cart_items) if cart_items else SHIPPING_RATES['standard']
    
    # Calculate subtotal
    subtotal = sum(item['item_total'] for item in cart_items)
    
    # Calculate tax (8.5% tax rate)
    tax = subtotal * 0.085
    
    # Calculate grand total
    grand_total = subtotal + shipping['cost'] + tax
    
    log_action('view_cart', {'item_count': len(cart_items)})
    return render_template('cart.html', 
                         cart_items=cart_items,
                         subtotal=subtotal,
                         shipping=shipping,
                         tax=tax,
                         grand_total=grand_total)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json() or {}
        else:
            # Handle form data
            data = {
                'name': request.form.get('name'),
                'phone': request.form.get('phone'),
                'address': request.form.get('address'),
                'city': request.form.get('city'),
                'state': request.form.get('state'),
                'zip': request.form.get('zip'),
                'payment': request.form.get('payment'),
                'card_number': request.form.get('cardNumber'),
                'expiry': request.form.get('expiry'),
                'cvv': request.form.get('cvv')
            }
        
        log_action('checkout_attempt', data)
        
        # VULNERABLE: Log sensitive payment information
        log_action('payment_info', {
            'card_number': data.get('card_number', ''),
            'expiry': data.get('expiry', ''),
            'cvv': data.get('cvv', ''),
            'address': data.get('address', '')
        })
        
        if request.is_json:
            return jsonify({'success': False, 'message': 'Checkout failed. Please try again later.'})
        else:
            # Redirect to order confirmation for form submissions
            return redirect(url_for('order_confirmation'))
    
    # For GET request, create sample cart items for demonstration
    cart_items = []
    # Add a sample item to the cart for demonstration
    if PRODUCTS:
        sample_product = PRODUCTS[0]  # Use first product as sample
        cart_items.append({
            'product': sample_product,
            'quantity': 1,
            'item_total': sample_product['price']
        })
    
    # Calculate shipping
    shipping = calculate_shipping(cart_items) if cart_items else SHIPPING_RATES['standard']
    
    # Calculate subtotal
    subtotal = sum(item['item_total'] for item in cart_items)
    
    # Calculate tax (8.5% tax rate)
    tax = subtotal * 0.085
    
    # Calculate grand total
    grand_total = subtotal + shipping['cost'] + tax
    
    log_action('view_checkout', {'item_count': len(cart_items)})
    return render_template('checkout.html', 
                         cart_items=cart_items,
                         subtotal=subtotal,
                         shipping=shipping,
                         tax=tax,
                         grand_total=grand_total)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        log_action('visit_login', {})
        return render_template('login.html')

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABLE: Direct string concatenation for SQL injection
    fake_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    log_action('login_attempt', {'username': username, 'password': password, 'raw_query': fake_query})
    
    # VULNERABLE: Multiple SQL injection patterns
    sql_injection_patterns = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin'#",
        "admin'/*",
        "' UNION SELECT * FROM users--",
        "' UNION SELECT username,password FROM users--"
    ]
    
    # Check for SQL injection attempts
    sqli_detected = any(pattern in username or pattern in password for pattern in sql_injection_patterns)
    
    # VULNERABLE: Allow login with SQL injection or correct credentials
    if (username == 'admin' and password == 'password123') or sqli_detected:
        session['username'] = username
        session['is_admin'] = True
        log_action('login_success', {'username': username, 'sqli': sqli_detected, 'query': fake_query})
        return jsonify({'success': True, 'message': 'Login successful! Redirecting...', 'redirect_url': url_for('admin')})
    else:
        log_action('login_failure', {'username': username})
        return jsonify({'success': False, 'message': 'Wrong username or password.'})

@app.route('/admin', methods=['GET'])
@admin_required
def admin():
    # Read last 100 log lines for admin
    try:
        with open('login_attempts.log', 'r') as f:
            logs = f.readlines()[-100:]
        logs = [json.loads(line) for line in logs]
    except Exception:
        logs = []
    log_action('admin_dashboard', {'username': session['username']})
    return render_template('admin.html', username=session['username'], logs=logs, products=PRODUCTS, reviews=REVIEWS)

@app.route('/admin/add_product', methods=['POST'])
@admin_required
def admin_add_product():
    data = request.form
    new_id = max([p['id'] for p in PRODUCTS] or [0]) + 1
    product = {
        'id': new_id,
        'name': data.get('name'),
        'price': float(data.get('price', 0)),
        'image': data.get('image', ''),
        'desc': data.get('desc', '')
    }
    PRODUCTS.append(product)
    log_action('admin_add_product', {'admin': session['username'], 'product': product})
    return redirect(url_for('admin'))

@app.route('/admin/edit_product/<int:product_id>', methods=['POST'])
@admin_required
def admin_edit_product(product_id):
    data = request.form
    for p in PRODUCTS:
        if p['id'] == product_id:
            p['name'] = data.get('name', p['name'])
            p['price'] = float(data.get('price', p['price']))
            p['image'] = data.get('image', p['image'])
            p['desc'] = data.get('desc', p['desc'])
            log_action('admin_edit_product', {'admin': session['username'], 'product': p})
            break
    return redirect(url_for('admin'))

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    global PRODUCTS
    PRODUCTS = [p for p in PRODUCTS if p['id'] != product_id]
    log_action('admin_delete_product', {'admin': session['username'], 'product_id': product_id})
    return redirect(url_for('admin'))

@app.route('/admin/delete_review/<int:product_id>/<int:review_idx>', methods=['POST'])
@admin_required
def admin_delete_review(product_id, review_idx):
    if product_id in REVIEWS and 0 <= review_idx < len(REVIEWS[product_id]):
        deleted = REVIEWS[product_id].pop(review_idx)
        log_action('admin_delete_review', {'admin': session['username'], 'product_id': product_id, 'review': deleted})
    return redirect(url_for('admin'))

@app.route('/admin/system', methods=['GET', 'POST'])
@admin_required
def admin_system():
    if request.method == 'POST':
        command = request.form.get('command', '')
        
        # VULNERABLE: Command injection - directly executing user input
        import subprocess
        try:
            # VULNERABLE: Shell command injection
            result = subprocess.check_output(command, shell=True, text=True)
            log_action('admin_command', {'admin': session['username'], 'command': command, 'result': result})
            return jsonify({'success': True, 'output': result})
        except Exception as e:
            log_action('admin_command_error', {'admin': session['username'], 'command': command, 'error': str(e)})
            return jsonify({'success': False, 'error': str(e)})
    
    log_action('admin_system_access', {'admin': session['username']})
    return render_template('admin_system.html')

@app.route('/order_confirmation')
def order_confirmation():
    # Create sample order data
    cart_items = []
    if PRODUCTS:
        sample_product = PRODUCTS[0]
        cart_items.append({
            'product': sample_product,
            'quantity': 1,
            'item_total': sample_product['price']
        })
    
    shipping = calculate_shipping(cart_items) if cart_items else SHIPPING_RATES['standard']
    subtotal = sum(item['item_total'] for item in cart_items)
    tax = subtotal * 0.085
    grand_total = subtotal + shipping['cost'] + tax
    
    # Create sample shipping address
    shipping_address = {
        'name': 'John Doe',
        'address': '123 Main Street',
        'city': 'Anytown',
        'state': 'CA',
        'zip': '12345',
        'phone': '(555) 123-4567'
    }
    
    # Get current date
    from datetime import datetime
    current_date = datetime.now().strftime('%B %d, %Y, %I:%M %p')
    
    log_action('order_confirmation_view', {'item_count': len(cart_items)})
    return render_template('order_confirmation.html', 
                         cart_items=cart_items,
                         subtotal=subtotal,
                         shipping=shipping,
                         tax=tax,
                         grand_total=grand_total,
                         shipping_address=shipping_address,
                         current_date=current_date)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        log_action('visit_register', {})
        return render_template('register.html')
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    # VULNERABLE: Direct string concatenation for SQL injection
    fake_insert_query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
    log_action('register_attempt', {'username': username, 'email': email, 'sql_query': fake_insert_query})
    
    # VULNERABLE: No input validation or sanitization
    # VULNERABLE: XSS vulnerability - directly using user input
    if username and password and email:
        # Simulate successful registration
        log_action('register_success', {'username': username, 'email': email})
        return jsonify({'success': True, 'message': 'Registration successful! Please login.'})
    else:
        log_action('register_failure', {'username': username, 'email': email})
        return jsonify({'success': False, 'message': 'All fields are required.'})

@app.route('/logout')
def logout():
    log_action('logout', {'username': session.get('username')})
    session.clear()
    return redirect(url_for('home'))

@app.route('/admin/upload', methods=['GET', 'POST'])
@admin_required
def admin_upload():
    if request.method == 'POST':
        # VULNERABLE: File upload without proper validation
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file selected'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        # VULNERABLE: No file type validation
        # VULNERABLE: No file size limits
        # VULNERABLE: Path traversal possible
        filename = file.filename
        file.save(f'uploads/{filename}')  # VULNERABLE: Direct file save
        
        log_action('admin_file_upload', {'admin': session['username'], 'filename': filename})
        return jsonify({'success': True, 'message': f'File {filename} uploaded successfully'})
    
    log_action('admin_upload_access', {'admin': session['username']})
    return render_template('admin_upload.html')

@app.route('/search', methods=['GET'])
def search():
    # VULNERABLE: SQL injection in search parameter
    query = request.args.get('q', '')
    
    # VULNERABLE: Direct string concatenation for SQL injection simulation
    fake_sql_query = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%' OR category LIKE '%{query}%'"
    log_action('search_query', {'query': query, 'sql_query': fake_sql_query})
    
    # Filter products based on search (simulating database query)
    filtered_products = []
    if query:
        filtered_products = [p for p in PRODUCTS if query.lower() in p['name'].lower() or query.lower() in p['desc'].lower() or query.lower() in p['category'].lower()]
    else:
        filtered_products = PRODUCTS
    
    return render_template('search_results.html', products=filtered_products, query=query)

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.get_json() or {}
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    
    # Find the product
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if not product:
        return jsonify({'success': False, 'message': 'Product not found'})
    
    # Log the action
    log_action('add_to_cart_ajax', {'product_id': product_id, 'quantity': quantity})
    
    # For demo purposes, return success
    # In a real app, you'd add to session cart or database
    return jsonify({
        'success': True, 
        'message': f'{product["name"]} added to cart!',
        'cart_count': random.randint(1, 10)  # Random cart count for demo
    })

@app.route('/get_cart_count')
def get_cart_count():
    # For demo purposes, return a random count
    count = random.randint(0, 5)
    return jsonify({'count': count})

@app.route('/log_action', methods=['POST'])
def log_action_endpoint():
    data = request.get_json() or {}
    action = data.get('action', 'unknown')
    details = data.get('details', {})
    log_action(action, details)
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)
