# 🔍 Ironwall Security Audit Report

**Target:** `./battle_test_candidates/ecommerce-flask/`  
**Date:** 2026-07-12 20:56:06  
**Duration:** 2m2.131s  
**Tool Version:** ironwall v0.7.0  

## 📊 Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 10 |
| 🟢 LOW | 2 |
| ℹ️ INFO | 104 |
| **Total** | **119** |

## 🔴 CRITICAL Findings

### IRON-MISS-006: Missing 5 security controls in add_product

**File:** `F:\ClaudeFiles\_research\ironwall\battle_test_candidates\ecommerce-flask\app\routes\products.py:141`  
**Category:** missing-auth+input_validation+rate_limiting+csrf_protection+content_type_validation  
**CWE:** CWE-16  
**CVSS:** 9.8  
**AI Confidence:** 95%  

**Code:**
```
def add_product():
    """
    Add a new product to the database.

    This function creates a new product with the provided details and adds it to the database.
    It requires admin privileges.

    Returns:
        tuple: A tuple containing:
            - A JSON object with a success message and the new product's ID.
            - HTTP status code 201 if successful, 400 for bad request, or 500 for server error.

    Raises:
        HTTPException: 400 Bad Request if required fields are missing.
        HTTPException: 500 Internal Server Error if there's a database error.
    """
    data = request.get_json()
    if not data or "name" not in data or "price" not in data:
        return jsonify({"msg": "Name and price are required fields"}), 400

    product = Product(
        name=data["name"],
        description=data.get("description", ""),
        price=data["price"],
        stock=data.get("stock", 0),
    )
    try:
        db.session.add(product)
        db.session.commit()
    except (AttributeError, ValueError, TypeError) as error:
        db.session.rollback()
        return (
            jsonify(
                {
                    "msg": "An error occurred while adding the product",
                    "error": str(error),
                }
            ),
            500,
        )
    return jsonify({"msg": "Product added", "product_id": product.id}), 201
```

**Fix:**
Add authentication middleware or decorator to verify admin privileges before processing the request. Example: @login_required or check session token at function start.; Add validation for price (positive float), stock (non-negative integer), and name (non-empty string). Use type checks and range checks before creating the Product object.; Implement rate limiting using Flask-Limiter or similar middleware. Apply a reasonable limit per user/IP for POST requests to this endpoint.; Add CSRF token validation using Flask-WTF or similar. Ensure the token is checked for all state-changing POST requests.; Check that request.content_type == 'application/json' before calling get_json(). Return 415 Unsupported Media Type if the content type is invalid.

---

### IRON-MISS-007: Missing 5 security controls in edit_product

**File:** `F:\ClaudeFiles\_research\ironwall\battle_test_candidates\ecommerce-flask\app\routes\products.py:186`  
**Category:** missing-auth+input_validation+rate_limiting+csrf_protection+content_type_validation  
**CWE:** CWE-16  
**CVSS:** 9.8  
**AI Confidence:** 95%  

**Code:**
```
def edit_product(product_id):
    """
    Edit an existing product.

    This function updates the details of an existing product with the given ID.
    It requires admin privileges.

    Args:
        product_id (int): The ID of the product to edit.

    Returns:
        tuple: A tuple containing:
            - A JSON object with a success message and the updated product's ID.
            - HTTP status code 200 if successful, 400 for bad request, or 500 for server error.

    Raises:
        HTTPException: 404 Not Found if the product does not exist.
        HTTPException: 400 Bad Request if no data is provided.
        HTTPException: 500 Internal Server Error if there's a database error.
    """
    product = Product.query.get_or_404(product_id)
    data = request.get_json()
    if not data:
        return jsonify({"msg": "No data provided"}), 400

    product.name = data.get("name", product.name)
    product.description = data.get("description", product.description)
    product.price = data.get("price", product.price)
    product.stock = data.get("stock", product.stock)

    try:
        db.session.commit()
    except (AttributeError, ValueError, TypeError) as error:
        db.session.rollback()
        return (
            jsonify(
                {
                    "msg": "An error occurred while updating the product",
                    "error": str(error),
                }
            ),
            500,
        )
    return jsonify({"msg": "Product updated", "product_id": product.id}), 200
```

**Fix:**
Add authentication middleware or decorator to verify user identity and admin role before processing the request. Example: @login_required or check session token at function start.; Validate each field before assignment: ensure price is a positive number, stock is a non-negative integer, name is non-empty and within length limits, description is within length limits.; Apply rate limiting middleware to this endpoint, e.g., Flask-Limiter with a reasonable limit per user/IP.; Add CSRF token validation to the endpoint. In Flask, use Flask-WTF or generate and validate CSRF tokens manually.; Check that request.content_type == 'application/json' before calling get_json(), or use a decorator to enforce the content type.

---

## 🟠 HIGH Findings

### IRON-SEMGREP-009: dockerfile.security.missing-user.missing-user: By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'.

**File:** `battle_test_candidates\ecommerce-flask\Dockerfile:14`  
**Category:** security  
**CWE:** CWE-250: Execution with Unnecessary Privileges  
**CVSS:** 9.8  
**AI Confidence:** 80%  

**Code:**
```
14 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can exploit a vulnerability in the application running inside the container (e.g., RCE, command injection) to gain code execution as root.
- **Path:** 1. Attacker exploits a vulnerability in the Flask app (e.g., SSTI, command injection) to execute arbitrary code. 2. Since the container runs as root (no USER directive), the attacker gains root privileges inside the container. 3. Attacker can then escape the container (e.g., via mounted Docker socket, kernel exploits) or compromise the host.
- **Impact:** Full container compromise with root privileges, potentially leading to host compromise if container escape is possible.

**Fix:**
USER non-root
CMD ["flask", "run"]

**References:**
- https://semgrep.dev/r/dockerfile.security.missing-user.missing-user

---

### IRON-111: Potential Encryption/secret key hardcoded

**File:** `config.py:17`  
**Category:** hardcoded-secret  
**CWE:** CWE-798  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
17 | SECRET_KEY = "test-secret-key"
```

**Attack Scenario:**
- **Actor:** An attacker with access to the source code repository (e.g., via a compromised developer machine, insider threat, or public repository leak).
- **Path:** 1. Attacker obtains the source code (e.g., clones the repo, reads config.py). 2. Extracts SECRET_KEY = "test-secret-key" from line 17. 3. Uses this key to forge Flask session cookies, decrypt session data, or perform other cryptographic operations that rely on this secret.
- **Impact:** Attacker can forge arbitrary Flask session cookies, leading to session hijacking, privilege escalation, or impersonation of any user. This can result in unauthorized access to sensitive data or administrative functions.

---

### IRON-112: Potential Encryption/secret key hardcoded

**File:** `config.py:18`  
**Category:** hardcoded-secret  
**CWE:** CWE-798  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
18 | JWT_SECRET_KEY = "test-jwt-secret-key"
```

**Attack Scenario:**
- **Actor:** An attacker with access to the source code repository (e.g., via a compromised developer machine, insider threat, or public repository leak).
- **Path:** 1. Attacker obtains the source code (e.g., clones the repo, reads config.py). 2. Extracts JWT_SECRET_KEY = "test-jwt-secret-key" from line 18. 3. Uses this key to forge or verify JWT tokens, potentially gaining unauthorized access to API endpoints or user accounts.
- **Impact:** Attacker can forge valid JWT tokens, bypassing authentication and authorization checks. This can lead to unauthorized access to protected API endpoints, data exfiltration, or privilege escalation.

---

### IRON-MISS-001: Missing 4 security controls in place_order

**File:** `F:\ClaudeFiles\_research\ironwall\battle_test_candidates\ecommerce-flask\app\routes\orders.py:45`  
**Category:** missing-input_validation+rate_limiting+csrf_protection+content_type_validation  
**CWE:** CWE-16  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
def place_order():
    """
    Place an order based on the current user's cart.

    This endpoint processes the items in the user's cart, creates an order,
    and clears the cart after successfully placing the order.

    Returns:
        JSON response with a success message and the order ID if successful,
        or an error message if the cart is empty.
    """
    user = User.query.get(get_jwt_identity())
    cart = user.cart

    if not cart or not cart.items:
        return jsonify({"msg": "Cart is empty"}), 400

    total = sum(item.product.price * item.quantity for item in cart.items)
    order = Order(user_id=user.id, total=total)
    db.session.add(order)
    db.session.commit()

    for item in cart.items:
        order_item = OrderItem(
            order_id=order.id,
            product_id=item.product_id,
            quantity=item.quantity,
            price=item.product.price,
        )
        db.session.add(order_item)
    db.session.commit()

    # Clear the cart
    CartItem.query.filter_by(cart_id=cart.id).delete()
    db.session.commit()

    return jsonify({"msg": "Order placed successfully",
                   "order_id": order.id}), 201
```

**Fix:**
Validate that each item's quantity is a positive integer and that the price is a valid positive number. Consider adding server-side validation for product existence and stock availability.; Implement rate limiting using Flask-Limiter or similar middleware. For example: @limiter.limit('10 per minute'); If the app serves browser clients with session auth, add CSRF token validation. For JWT-based APIs, ensure proper CORS configuration and use SameSite cookies if applicable.; Add a check at the beginning of the handler: if not request.is_json: return jsonify({'msg': 'Content-Type must be application/json'}), 415

---

### IRON-MISS-002: Missing 2 security controls in get_order_history

**File:** `F:\ClaudeFiles\_research\ironwall\battle_test_candidates\ecommerce-flask\app\routes\orders.py:87`  
**Category:** missing-input_validation+rate_limiting  
**CWE:** CWE-16  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
def get_order_history():
    """
    Retrieve the current user's order history.

    This endpoint returns a list of all orders made by the user,
    sorted from the most recent to the oldest.

    Returns:
        JSON response containing the user's order list.
    """
    user = User.query.get(get_jwt_identity())
    # orders = Order.query.filter_by(
    # user_id=user.id).order_by(
    # Order.id.desc()).all()
    # The desc() method must be explicitly from sqlalchemy module to work
    # correctly.
    orders = Order.query.filter_by(
        user_id=user.id).order_by(
        desc(
            Order.id)).all()

    order_history = [
        {
            "id": order.id,
            "total": order.total,
            "date": order.date.isoformat() if hasattr(order, "date") else None,
            "items_count": len(order.order_items),
        }
        for order in orders
    ]

    return jsonify({"orders": order_history}), 200
```

**Fix:**
Validate the JWT identity before using it in a database query. Ensure it is a valid integer or UUID as expected.; Add rate limiting middleware or decorator to limit requests per user/IP, e.g., @limiter.limit('10 per minute').

---

### IRON-MISS-003: Missing 2 security controls in get_order_details

**File:** `F:\ClaudeFiles\_research\ironwall\battle_test_candidates\ecommerce-flask\app\routes\orders.py:123`  
**Category:** missing-input_validation+rate_limiting  
**CWE:** CWE-16  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
def get_order_details(order_id):
    """
    Retrieves the details of a specific order.

    This endpoint returns detailed information about an order,
    including all order items.

    Args:
        order_id (int): The ID of the order to be viewed.

    Returns:
        JSON response with order details.
    """
    user = User.query.get(get_jwt_identity())
    order = Order.query.filter_by(id=order_id, user_id=user.id).first()

    if not order:
        return jsonify({"msg": "Pedido não encontrado"}), 404

    order_items = [
        {
            "product_id": item.product_id,
            "product_name": item.product.name,
            "quantity": item.quantity,
            "price": item.price,
        }
        for item in order.order_items
    ]

    order_details = {
        "id": order.id,
        "total": order.total,
        "date": order.date.isoformat() if hasattr(order, "date") else None,
        "items": order_items,
    }

    return jsonify({"order": order_details}), 200
```

**Fix:**
Add validation to ensure order_id is a positive integer. Example: if not isinstance(order_id, int) or order_id <= 0: return error response.; Add rate limiting middleware or decorator. Example: @limiter.limit('10 per minute')

---

### IRON-MISS-004: Missing 4 security controls in add_to_cart

**File:** `F:\ClaudeFiles\_research\ironwall\battle_test_candidates\ecommerce-flask\app\routes\cart.py:98`  
**Category:** missing-input_validation+rate_limiting+csrf_protection+content_type_validation  
**CWE:** CWE-16  
**CVSS:** 7.5  
**AI Confidence:** 95%  

**Code:**
```
def add_to_cart():
    """
    Add a product to the user's cart.

    This endpoint adds a product to the user's cart. If the cart does not exist, it will be created.
    If the product is already in the cart, its quantity will be updated.

    Returns:
        JSON response with a success message.
    """
    # -- Legacy --
    # data = request.get_json()
    # user = User.query.get(get_jwt_identity())
    # cart = user.cart
    # if not cart:
    #     cart = Cart(user_id=user.id)
    #     db.session.add(cart)
    #     db.session.commit()
    # product = Product.query.get_or_404(data["product_id"])
    # cart_item = CartItem.query.filter_by(
    #     cart_id=cart.id, product_id=product.id).first()
    # if cart_item:
    #     cart_item.quantity += data.get("quantity", 1)
    # else:
    #     cart_item = CartItem(
    #         cart_id=cart.id,
    #         product_id=product.id,
    #         quantity=data.get(
    #             "quantity",
    #             1))
    #     db.session.add(cart_item)
    # db.session.commit()

    data = request.get_json()
    # Fetching user ID from JWT token
    user_id = get_jwt_identity()
    # Getting product_id and quantity from the request data
    product_id = data["product_id"]
    quantity = data.get("quantity", 1)  # Default to 1 if not provided
    # Delegating cart logic to the cart_service
    cart_service.add_item(
        user_id=user_id,
        product_id=product_id,
        quantity=quantity)
    return jsonify({"msg": "Product added to cart"}), 200
```

**Fix:**
Validate product_id is a positive integer and quantity is a positive integer. Use type checking and range validation before passing to cart_service.; Apply rate limiting middleware, e.g., Flask-Limiter with a limit like '30 per minute' per user.; Implement CSRF protection using Flask-WTF or a custom token check. Ensure the CSRF token is validated for all state-changing requests.; Check that request.content_type == 'application/json' before calling request.get_json(). Return 415 Unsupported Media Type if invalid.

---

### IRON-MISS-005: Missing 2 security controls in get_product

**File:** `F:\ClaudeFiles\_research\ironwall\battle_test_candidates\ecommerce-flask\app\routes\products.py:105`  
**Category:** missing-input_validation+rate_limiting  
**CWE:** CWE-16  
**CVSS:** 7.5  
**AI Confidence:** 95%  

**Code:**
```
def get_product(product_id):
    """
    Retrieve a specific product by its ID.

    This function queries the database for a product with the given ID and returns its details.

    Args:
        product_id (int): The ID of the product to retrieve.

    Returns:
        tuple: A tuple containing:
            - A JSON object with the product's details.
            - HTTP status code 200.

    Raises:
        HTTPException: 404 Not Found if the product does not exist.
    """
    product = Product.query.get(product_id)
    if product is None:
        return jsonify({"msg": "Product not found"}), 404
    return (
        jsonify(
            {
                "id": product.id,
                "name": product.name,
                "description": product.description,
                "price": product.price,
                "stock": product.stock,
            }
        ),
        200,
    )
```

**Fix:**
Add input validation to ensure product_id is a positive integer. Example: if not isinstance(product_id, int) or product_id <= 0: return jsonify({'msg': 'Invalid product ID'}), 400; Implement rate limiting using Flask-Limiter or similar middleware. Example: @limiter.limit('100 per minute')

---

## 🟡 MEDIUM Findings

### IRON-SEMGREP-001: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**File:** `battle_test_candidates\ecommerce-flask\.github\workflows\Build, Test, Lint & Format.yml:12`  
**Category:** security  
**CWE:** CWE-1357: Reliance on Insufficiently Trustworthy Component  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
12 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can compromise the GitHub account of the action owner or gain write access to the action repository.
- **Path:** 1. Attacker compromises the owner of the action referenced at line 12 (e.g., actions/checkout@v3). 2. Attacker pushes a malicious commit to the v3 tag. 3. The next CI run on the target repository uses the compromised action. 4. Malicious code executes in the CI environment, potentially exfiltrating secrets or modifying the build.
- **Impact:** Supply-chain compromise: attacker can execute arbitrary code in the CI pipeline, steal secrets (e.g., AWS keys, GitHub tokens), or inject backdoors into the built artifacts.

**References:**
- https://semgrep.dev/r/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag

---

### IRON-SEMGREP-002: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**File:** `battle_test_candidates\ecommerce-flask\.github\workflows\Build, Test, Lint & Format.yml:14`  
**Category:** security  
**CWE:** CWE-1357: Reliance on Insufficiently Trustworthy Component  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
14 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can compromise the GitHub account of the action owner or gain write access to the action repository.
- **Path:** 1. Attacker compromises the owner of the action referenced at line 14. 2. Attacker pushes a malicious commit to the mutable tag. 3. The next CI run uses the compromised action. 4. Malicious code executes in the CI environment.
- **Impact:** Supply-chain compromise: attacker can execute arbitrary code in the CI pipeline, steal secrets, or inject backdoors into the built artifacts.

**References:**
- https://semgrep.dev/r/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag

---

### IRON-SEMGREP-003: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**File:** `battle_test_candidates\ecommerce-flask\.github\workflows\Build, Test, Lint & Format.yml:19`  
**Category:** security  
**CWE:** CWE-1357: Reliance on Insufficiently Trustworthy Component  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
19 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can compromise the GitHub account of the action owner or gain write access to the action repository.
- **Path:** 1. Attacker compromises the owner of the action referenced at line 19. 2. Attacker pushes a malicious commit to the mutable tag. 3. The next CI run uses the compromised action. 4. Malicious code executes in the CI environment.
- **Impact:** Supply-chain compromise: attacker can execute arbitrary code in the CI pipeline, steal secrets, or inject backdoors into the built artifacts.

**References:**
- https://semgrep.dev/r/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag

---

### IRON-SEMGREP-004: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**File:** `battle_test_candidates\ecommerce-flask\.github\workflows\build_workflow.yml:11`  
**Category:** security  
**CWE:** CWE-1357: Reliance on Insufficiently Trustworthy Component  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
11 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can compromise the GitHub account of the action owner or gain write access to the action repository.
- **Path:** 1. Attacker compromises the owner of the action referenced at line 11 in build_workflow.yml. 2. Attacker pushes a malicious commit to the mutable tag. 3. The next CI run uses the compromised action. 4. Malicious code executes in the CI environment.
- **Impact:** Supply-chain compromise: attacker can execute arbitrary code in the CI pipeline, steal secrets, or inject backdoors into the built artifacts.

**References:**
- https://semgrep.dev/r/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag

---

### IRON-SEMGREP-005: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**File:** `battle_test_candidates\ecommerce-flask\.github\workflows\build_workflow.yml:14`  
**Category:** security  
**CWE:** CWE-1357: Reliance on Insufficiently Trustworthy Component  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
14 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can compromise the GitHub account of the action owner or gain write access to the action repository.
- **Path:** 1. Attacker compromises the owner of the action referenced at line 14 in build_workflow.yml. 2. Attacker pushes a malicious commit to the mutable tag. 3. The next CI run uses the compromised action. 4. Malicious code executes in the CI environment.
- **Impact:** Supply-chain compromise: attacker can execute arbitrary code in the CI pipeline, steal secrets, or inject backdoors into the built artifacts.

**References:**
- https://semgrep.dev/r/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag

---

### IRON-SEMGREP-006: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**File:** `battle_test_candidates\ecommerce-flask\.github\workflows\build_workflow.yml:19`  
**Category:** security  
**CWE:** CWE-1357: Reliance on Insufficiently Trustworthy Component  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
19 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can compromise the GitHub account of the action owner or gain write access to the action repository.
- **Path:** 1. Attacker compromises the owner of the action referenced at line 19 in build_workflow.yml. 2. Attacker pushes a malicious commit to the mutable tag. 3. The next CI run uses the compromised action. 4. Malicious code executes in the CI environment.
- **Impact:** Supply-chain compromise: attacker can execute arbitrary code in the CI pipeline, steal secrets, or inject backdoors into the built artifacts.

**References:**
- https://semgrep.dev/r/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag

---

### IRON-SEMGREP-007: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**File:** `battle_test_candidates\ecommerce-flask\.github\workflows\build_workflow.yml:58`  
**Category:** security  
**CWE:** CWE-1357: Reliance on Insufficiently Trustworthy Component  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
58 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can compromise the GitHub account of the action owner or gain write access to the action repository.
- **Path:** 1. Attacker compromises the owner of the action referenced at line 58 in build_workflow.yml. 2. Attacker pushes a malicious commit to the mutable tag. 3. The next CI run uses the compromised action. 4. Malicious code executes in the CI environment.
- **Impact:** Supply-chain compromise: attacker can execute arbitrary code in the CI pipeline, steal secrets, or inject backdoors into the built artifacts.

**References:**
- https://semgrep.dev/r/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag

---

### IRON-SEMGREP-008: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**File:** `battle_test_candidates\ecommerce-flask\.github\workflows\build_workflow.yml:74`  
**Category:** security  
**CWE:** CWE-1357: Reliance on Insufficiently Trustworthy Component  
**CVSS:** 7.5  
**AI Confidence:** 90%  

**Code:**
```
74 | requires login
```

**Attack Scenario:**
- **Actor:** An attacker who can compromise the GitHub account of the action owner or gain write access to the action repository.
- **Path:** 1. Attacker compromises the owner of the action referenced at line 74 in build_workflow.yml. 2. Attacker pushes a malicious commit to the mutable tag. 3. The next CI run uses the compromised action. 4. Malicious code executes in the CI environment.
- **Impact:** Supply-chain compromise: attacker can execute arbitrary code in the CI pipeline, steal secrets, or inject backdoors into the built artifacts.

**References:**
- https://semgrep.dev/r/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag

---

### IRON-118: Unpinned GitHub Action in Build, Test, Lint & Format.yml

**File:** `.github/workflows/Build, Test, Lint & Format.yml:0`  
**Category:** supply-chain  
**CWE:** CWE-1104  
**CVSS:** 5.0  

**Fix:**
Pin actions to full commit SHA: uses: actions/checkout@a81bb... instead of @v4

**References:**
- https://github.com/stepsecurity/secure-workflows

---

### IRON-119: Unpinned GitHub Action in build_workflow.yml

**File:** `.github/workflows/build_workflow.yml:0`  
**Category:** supply-chain  
**CWE:** CWE-1104  
**CVSS:** 5.0  

**Fix:**
Pin actions to full commit SHA: uses: actions/checkout@a81bb... instead of @v4

**References:**
- https://github.com/stepsecurity/secure-workflows

---

## 🟢 LOW Findings

### IRON-115: Unsafe Docker COPY in Dockerfile

**File:** `Dockerfile:8`  
**Category:** insecure-configuration  
**CWE:** CWE-16  
**CVSS:** 2.5  

**Code:**
```
8 | COPY . .
```

**Fix:**
Use .dockerignore file to exclude sensitive files from Docker build context.

---

### IRON-117: 1/10 recent commits are not GPG signed

**File:** `.git:0`  
**Category:** supply-chain  
**CWE:** CWE-1104  
**CVSS:** 2.0  

**Fix:**
Configure git GPG signing: git config --global commit.gpgsign true

**References:**
- https://docs.github.com/en/authentication/managing-commit-signature-verification

---

## ℹ️ INFO Findings

### IRON-SEMGREP-010: python.django.security.audit.unvalidated-password.unvalidated-password: The password on 'user' is being set without validating the password. Call django.contrib.auth.password_validation.validate_password() with validation functions before setting the password. See https://docs.djangoproject.com/en/3.0/topics/auth/passwords/ for more information.

**File:** `battle_test_candidates\ecommerce-flask\app\routes\auth.py:68`  
**Category:** security  
**CWE:** CWE-521: Weak Password Requirements  
**CVSS:** 7.5  
**AI Confidence:** 95%  

**Code:**
```
68 | requires login
```

**Fix:**
if django.contrib.auth.password_validation.validate_password(data["password"], user=user):
        user.set_password(data["password"])

**References:**
- https://semgrep.dev/r/python.django.security.audit.unvalidated-password.unvalidated-password

---

### IRON-SEMGREP-011: generic.secrets.security.detected-jwt-token.detected-jwt-token: JWT token detected

**File:** `battle_test_candidates\ecommerce-flask\documentation.md:1191`  
**Category:** security  
**CWE:** CWE-321: Use of Hard-coded Cryptographic Key  
**CVSS:** 9.8  
**AI Confidence:** 95%  

**Code:**
```
1191 | requires login
```

**References:**
- https://semgrep.dev/r/generic.secrets.security.detected-jwt-token.detected-jwt-token

---

### IRON-BANDIT-001: [B105] hardcoded_password_string: Possible hardcoded password: 'test-secret-key'

**File:** `./battle_test_candidates/ecommerce-flask/config.py:17`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
16     SQLALCHEMY_TRACK_MODIFICATIONS = False
17     SECRET_KEY = "test-secret-key"
18     JWT_SECRET_KEY = "test-jwt-secret-key"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-002: [B105] hardcoded_password_string: Possible hardcoded password: 'test-jwt-secret-key'

**File:** `./battle_test_candidates/ecommerce-flask/config.py:18`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
17     SECRET_KEY = "test-secret-key"
18     JWT_SECRET_KEY = "test-jwt-secret-key"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-003: [B105] hardcoded_password_string: Possible hardcoded password: 'password'

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:113`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
112         "email": "newuser@example.com",
113         "password": "password",
114     }
115 
116 
117 @pytest.fixture
118 def sample_user(session):
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-004: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:132`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
131     response = client.post("/auth/register", json=new_user_data)
132     assert response.status_code == 201
133     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-005: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:134`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
133     data = json.loads(response.data)
134     assert data["msg"] == "User registered successfully"
135     user = User.query.filter_by(email=new_user_data["email"]).first()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-006: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:136`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
135     user = User.query.filter_by(email=new_user_data["email"]).first()
136     assert user is not None
137     assert user.username == new_user_data["username"]
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-007: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:137`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
136     assert user is not None
137     assert user.username == new_user_data["username"]
138
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-008: [B105] hardcoded_password_string: Possible hardcoded password: 'password'

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:145`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
144         "email": "anotheremail@example.com",
145         "password": "password",
146     }
147     response = client.post("/auth/register", json=existing_user_data)
148     assert response.status_code == 400
149     data = json.loads(response.data)
150     assert data["msg"] == "Username already exists"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-009: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:148`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
147     response = client.post("/auth/register", json=existing_user_data)
148     assert response.status_code == 400
149     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-010: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:150`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
149     data = json.loads(response.data)
150     assert data["msg"] == "Username already exists"
151
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-011: [B105] hardcoded_password_string: Possible hardcoded password: 'password'

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:158`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
157         "email": sample_user.email,
158         "password": "password",
159     }
160     response = client.post("/auth/register", json=existing_email_data)
161     assert response.status_code == 400
162     data = json.loads(response.data)
163     assert data["msg"] == "Email already exists"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-012: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:161`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
160     response = client.post("/auth/register", json=existing_email_data)
161     assert response.status_code == 400
162     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-013: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:163`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
162     data = json.loads(response.data)
163     assert data["msg"] == "Email already exists"
164
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-014: [B105] hardcoded_password_string: Possible hardcoded password: 'password'

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:168`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
167     """Test logging in with valid credentials."""
168     login_data = {"username": sample_user.username, "password": "password"}
169     response = client.post("/auth/login", json=login_data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-015: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:170`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
169     response = client.post("/auth/login", json=login_data)
170     assert response.status_code == 200
171     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-016: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:172`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
171     data = json.loads(response.data)
172     assert "access_token" in data
173
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-017: [B105] hardcoded_password_string: Possible hardcoded password: 'wrongpassword'

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:177`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
176     """Test logging in with invalid credentials."""
177     invalid_login_data = {"username": "wronguser", "password": "wrongpassword"}
178     response = client.post("/auth/login", json=invalid_login_data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-018: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:179`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
178     response = client.post("/auth/login", json=invalid_login_data)
179     assert response.status_code == 401
180     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-019: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_auth.py:181`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
180     data = json.loads(response.data)
181     assert data["msg"] == "Invalid credentials"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-020: [B105] hardcoded_password_string: Possible hardcoded password: 'password'

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:119`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
118     response = client.post(
119         "/auth/login", json={"username": "testuser", "password": "password"}
120     )
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-021: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:166`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
165     response = client.get("/cart", headers=auth_headers)
166     assert response.status_code == 200
167     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-022: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:168`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
167     data = json.loads(response.data)
168     assert data["cart"] == []
169
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-023: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:189`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
188     )
189     assert response.status_code == 200
190     assert json.loads(response.data)["msg"] == "Product added to cart"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-024: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:190`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
189     assert response.status_code == 200
190     assert json.loads(response.data)["msg"] == "Product added to cart"
191
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-025: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:195`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
194     data = json.loads(response.data)
195     assert len(data["cart"]) == 1
196     assert data["cart"][0]["product_id"] == sample_product.id
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-026: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:196`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
195     assert len(data["cart"]) == 1
196     assert data["cart"][0]["product_id"] == sample_product.id
197     assert data["cart"][0]["quantity"] == 2
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-027: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:197`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
196     assert data["cart"][0]["product_id"] == sample_product.id
197     assert data["cart"][0]["quantity"] == 2
198
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-028: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:223`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
222         headers=auth_headers)
223     assert response.status_code == 200
224     assert json.loads(response.data)[
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-029: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:224`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
223     assert response.status_code == 200
224     assert json.loads(response.data)[
225         "msg"] == "Item successfully removed from cart"
226
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-030: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:230`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
229     data = json.loads(response.data)
230     assert data["cart"] == []
231
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-031: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:245`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
244     response = client.delete("/cart/999", headers=auth_headers)
245     assert response.status_code == 404
246     assert json.loads(response.data)["msg"] == "Cart not found"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-032: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:246`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
245     assert response.status_code == 404
246     assert json.loads(response.data)["msg"] == "Cart not found"
247
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-033: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:274`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
273     )
274     assert response.status_code == 200
275     assert json.loads(response.data)["msg"] == "Product added to cart"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-034: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:275`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
274     assert response.status_code == 200
275     assert json.loads(response.data)["msg"] == "Product added to cart"
276
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-035: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:280`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
279     data = json.loads(response.data)
280     assert len(data["cart"]) == 1
281     assert data["cart"][0]["product_id"] == sample_product.id
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-036: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:281`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
280     assert len(data["cart"]) == 1
281     assert data["cart"][0]["product_id"] == sample_product.id
282     assert data["cart"][0]["quantity"] == 3
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-037: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:282`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
281     assert data["cart"][0]["product_id"] == sample_product.id
282     assert data["cart"][0]["quantity"] == 3
283
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-038: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:304`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
303     data = json.loads(response.data)
304     assert len(data["cart"]) == 1
305
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-039: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:308`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
307     response = client.delete("/cart/clear", headers=auth_headers)
308     assert response.status_code == 200
309     assert json.loads(response.data)["msg"] == "Cart cleared"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-040: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:309`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
308     assert response.status_code == 200
309     assert json.loads(response.data)["msg"] == "Cart cleared"
310
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-041: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_carts.py:314`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
313     data = json.loads(response.data)
314     assert data["cart"] == []
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-042: [B105] hardcoded_password_string: Possible hardcoded password: 'password'

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:146`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
145     response = client.post(
146         "/auth/login", json={"username": "testuser", "password": "password"}
147     )
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-043: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:230`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
229     response = client.post("/orders", headers=auth_headers)
230     assert response.status_code == 400
231     assert json.loads(response.data)["msg"] == "Cart is empty"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-044: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:231`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
230     assert response.status_code == 400
231     assert json.loads(response.data)["msg"] == "Cart is empty"
232
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-045: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:249`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
248     response = client.post("/orders", headers=auth_headers)
249     assert response.status_code == 201
250     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-046: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:251`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
250     data = json.loads(response.data)
251     assert data["msg"] == "Order placed successfully"
252     assert "order_id" in data
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-047: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:252`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
251     assert data["msg"] == "Order placed successfully"
252     assert "order_id" in data
253
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-048: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:257`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
256     cart_data = json.loads(cart_response.data)
257     assert cart_data["cart"] == []
258
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-049: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:279`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
278     response = client.get("/orders/history", headers=auth_headers)
279     assert response.status_code == 200
280     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-050: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:281`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
280     data = json.loads(response.data)
281     assert len(data["orders"]) == 1
282     assert "id" in data["orders"][0]
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-051: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:282`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
281     assert len(data["orders"]) == 1
282     assert "id" in data["orders"][0]
283     assert data["orders"][0]["items_count"] > 0
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-052: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:283`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
282     assert "id" in data["orders"][0]
283     assert data["orders"][0]["items_count"] > 0
284
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-053: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:306`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
305     response = client.get(f"/orders/{order_id}", headers=auth_headers)
306     assert response.status_code == 200
307     data = json.loads(response.data)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-054: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:308`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
307     data = json.loads(response.data)
308     assert "order" in data
309     assert data["order"]["id"] == order_id
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-055: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:309`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
308     assert "order" in data
309     assert data["order"]["id"] == order_id
310     assert len(data["order"]["items"]) > 0
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-056: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:310`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
309     assert data["order"]["id"] == order_id
310     assert len(data["order"]["items"]) > 0
311
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-057: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:325`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
324     response = client.get("/orders/999", headers=auth_headers)
325     assert response.status_code == 404
326     assert json.loads(response.data)["msg"] == "Pedido não encontrado"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-058: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_orders.py:326`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
325     assert response.status_code == 404
326     assert json.loads(response.data)["msg"] == "Pedido não encontrado"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-059: [B105] hardcoded_password_string: Possible hardcoded password: 'test-secret-key'

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:35`  
**Category:** bandit-b105  
**CWE:** CWE-22  
**CVSS:** 2.5  

**Code:**
```
34     app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
35     app.config["JWT_SECRET_KEY"] = "test-secret-key"
36
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b105.html

---

### IRON-BANDIT-060: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:151`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
150 
151         assert Product.query.count() == 1
152
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-061: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:170`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
169     with fixture_app.app_context():
170         assert Product.query.count() == 1
171         db_product = Product.query.get(fixture_sample_product)
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-062: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:172`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
171         db_product = Product.query.get(fixture_sample_product)
172         assert db_product is not None
173         assert db_product.id == fixture_sample_product
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-063: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:173`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
172         assert db_product is not None
173         assert db_product.id == fixture_sample_product
174         assert db_product.name == "Sample Product"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-064: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:174`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
173         assert db_product.id == fixture_sample_product
174         assert db_product.name == "Sample Product"
175
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-065: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:177`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
176     response = fixture_client.get("/products")
177     assert response.status_code == 200
178     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-066: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:179`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
178     data = response.get_json()
179     assert isinstance(data, list)
180     assert len(data) == 1
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-067: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:180`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
179     assert isinstance(data, list)
180     assert len(data) == 1
181     assert data[0]["name"] == "Sample Product"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-068: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:181`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
180     assert len(data) == 1
181     assert data[0]["name"] == "Sample Product"
182     assert data[0]["id"] == fixture_sample_product
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-069: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:182`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
181     assert data[0]["name"] == "Sample Product"
182     assert data[0]["id"] == fixture_sample_product
183
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-070: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:197`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
196     response = fixture_client.get(f"/products/{fixture_sample_product}")
197     assert response.status_code == 200
198     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-071: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:199`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
198     data = response.get_json()
199     assert data["name"] == "Sample Product"
200     assert data["description"] == "This is a sample product."
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-072: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:200`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
199     assert data["name"] == "Sample Product"
200     assert data["description"] == "This is a sample product."
201     assert data["price"] == 19.99
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-073: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:201`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
200     assert data["description"] == "This is a sample product."
201     assert data["price"] == 19.99
202     assert data["stock"] == 100
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-074: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:202`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
201     assert data["price"] == 19.99
202     assert data["stock"] == 100
203
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-075: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:216`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
215     response = fixture_client.get("/products/999")
216     assert response.status_code == 404
217     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-076: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:218`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
217     data = response.get_json()
218     assert data["msg"] == "Product not found"
219
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-077: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:244`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
243     )
244     assert response.status_code == 201
245     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-078: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:246`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
245     data = response.get_json()
246     assert data["msg"] == "Product added"
247     assert "product_id" in data
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-079: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:247`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
246     assert data["msg"] == "Product added"
247     assert "product_id" in data
248
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-080: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:252`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
251         product = Product.query.get(data["product_id"])
252         assert product is not None
253         assert product.name == "New Product"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-081: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:253`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
252         assert product is not None
253         assert product.name == "New Product"
254
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-082: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:279`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
278     )
279     assert response.status_code == 403
280     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-083: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:281`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
280     data = response.get_json()
281     assert data["msg"] == "Admin privilege required"
282
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-084: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:301`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
300     )
301     assert response.status_code == 400
302     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-085: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:303`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
302     data = response.get_json()
303     assert data["msg"] == "Name and price are required fields"
304
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-086: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:332`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
331     )
332     assert response.status_code == 200
333     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-087: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:334`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
333     data = response.get_json()
334     assert data["msg"] == "Product updated"
335
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-088: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:339`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
338         product = Product.query.get(fixture_sample_product)
339         assert product is not None
340         assert product.name == "Updated Product"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-089: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:340`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
339         assert product is not None
340         assert product.name == "Updated Product"
341         assert product.description == "Updated description."
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-090: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:341`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
340         assert product.name == "Updated Product"
341         assert product.description == "Updated description."
342         assert product.price == 39.99
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-091: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:342`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
341         assert product.description == "Updated description."
342         assert product.price == 39.99
343         assert product.stock == 75
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-092: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:343`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
342         assert product.price == 39.99
343         assert product.stock == 75
344
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-093: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:372`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
371     )
372     assert response.status_code == 403
373     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-094: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:374`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
373     data = response.get_json()
374     assert data["msg"] == "Admin privilege required"
375
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-095: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:396`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
395     )
396     assert response.status_code == 200
397     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-096: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:398`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
397     data = response.get_json()
398     assert data["msg"] == "Product deleted"
399
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-097: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:403`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
402         product = Product.query.get(fixture_sample_product)
403         assert product is None
404
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-098: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:425`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
424     )
425     assert response.status_code == 403
426     data = response.get_json()
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-BANDIT-099: [B101] assert_used: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**File:** `./battle_test_candidates/ecommerce-flask/tests\test_products.py:427`  
**Category:** bandit-b101  
**CWE:** CWE-79  
**CVSS:** 2.5  

**Code:**
```
426     data = response.get_json()
427     assert data["msg"] == "Admin privilege required"
```

**References:**
- https://bandit.readthedocs.io/en/latest/plugins/b101.html

---

### IRON-114: SBOM generated: 18 components detected

**File:** `sbom.cdx.json:0`  
**Category:** sbom  

**References:**
- https://github.com/anchore/syft

---

### IRON-116: SBOM generation available via syft

**File:** `./battle_test_candidates/ecommerce-flask/:0`  
**Category:** sbom  

**Fix:**
syft scan ./battle_test_candidates/ecommerce-flask/ -o cyclonedx-json > sbom.cdx.json

**References:**
- https://github.com/anchore/syft

---

### IRON-120: OpenSSF Scorecard not installed

**File:** `./battle_test_candidates/ecommerce-flask/:0`  
**Category:** supply-chain  

**Fix:**
go install github.com/ossf/scorecard/v5@latest

**References:**
- https://securityscorecards.dev/

---


---

*Report generated by [Ironwall v0.7.0](https://github.com/FYFran/ironwall) — 8-Step Security Audit CLI*
