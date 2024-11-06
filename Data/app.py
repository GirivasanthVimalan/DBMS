from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from config import Config
from datetime import datetime

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY  # Required for session management

# Database connection function
def get_db_connection():
    return mysql.connector.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB
    )
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    return redirect(url_for('login'))

# Login page with separate admin and staff login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form['role']  # 'admin' or 'staff'
        username_or_id = request.form['username_or_id']
        password = request.form['password'].strip()

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        
        try:
            if role == 'admin':
                # Fetch admin by username with parameterized query
                cur.execute("SELECT admin_id, password FROM Admin_Login WHERE admin_id = %s", (username_or_id,))
                admin = cur.fetchone()
                print("Admin query result:", admin)  # Debugging print

                # Check if admin exists and password matches
                if admin:
                    print("Stored hash for admin:", admin['password'])  # Debugging print
                    if admin['password'] == password:
                        session['user_id'] = admin['admin_id']
                        session['user_role'] = 'admin'
                        flash("Admin logged in successfully.")
                        return redirect(url_for('admin_dashboard'))
                    else:
                        flash("Incorrect password for admin.")
                else:
                    flash("Admin username not found.")

            elif role == 'staff':
                # Fetch staff by staff_id with parameterized query
                cur.execute("SELECT staff_id, password FROM Staff_Login WHERE staff_id = %s", (username_or_id,))
                staff = cur.fetchone()
                print("Staff query result:", staff)  # Debugging print

                # Check if staff exists and password matches
                if staff:
                    print("Stored hash for staff:", staff['password'])  # Debugging print
                    if staff['password'] == password:
                        session['user_id'] = staff['staff_id']
                        session['user_role'] = 'staff'
                        flash("Staff logged in successfully.")
                        return redirect(url_for('staff_dashboard'))
                    else:
                        flash("Incorrect password for staff.")
                else:
                    flash("Staff ID not found.")

            else:
                flash("Invalid role selected.")
        
        finally:
            cur.close()
            conn.close()

    return render_template('login.html')

# Admin dashboard
@app.route('/add_staff', methods=['POST'])
def add_staff():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied.")
        return redirect(url_for('login'))
    
    # Get form data
    staff_id = request.form['staff_id']
    name = request.form['name']
    department = request.form['department']
    email = request.form['email']
    phone_number = request.form['phone_number']
    password = request.form['password']
    
    # Hash the password
    
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Insert into Staff table
        cur.execute(
            "INSERT INTO Staff (staff_id, name, department, email, phone_number) VALUES (%s, %s, %s, %s, %s)",
            (staff_id, name, department, email, phone_number)
        )
        
        # Insert into Staff_Login table
        cur.execute(
            "INSERT INTO Staff_Login (staff_id, password) VALUES (%s, %s)",
            (staff_id, password)
        )
        
        conn.commit()
        flash("Staff member added successfully!")
    except Exception as e:
        conn.rollback()
        flash("Error adding staff member. Please check data and try again.")
        print(f"Error adding staff: {e}")
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

# Display requests and allocation details for admin
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied.")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        # Fetch all pending requests with staff details
        cur.execute("""
            SELECT Request.request_id, Request.staff_id, Request.request_date, Request.request_status,
                   Request.priority, Request.required_date, Request.return_date, Staff.name AS staff_name
            FROM Request
            JOIN Staff ON Request.staff_id = Staff.staff_id
            WHERE Request.request_status = 'pending'
        """)
        requests = cur.fetchall()

        # Fetch allocation details
        cur.execute("""
            SELECT Allocation.allocation_id, Allocation.request_id, Allocation.resource_id,
                   Allocation.allocation_date, Allocation.return_date, Allocation.status,
                   Resource.resource_name
            FROM Allocation
            JOIN Resource ON Allocation.resource_id = Resource.resource_id
        """)
        allocations = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template('admin_dashboard.html', requests=requests, allocations=allocations)

# Handle resource allocation
@app.route('/allocate_resource', methods=['POST'])
def allocate_resource():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied.")
        return redirect(url_for('login'))

    allocation_data = request.form
    request_id = allocation_data['request_id']
    resource_id = allocation_data['resource_id']
    allocation_date = allocation_data['allocation_date']
    return_date = allocation_data['return_date']

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Insert allocation details
        cur.execute(
            "INSERT INTO Allocation (request_id, resource_id, allocation_date, return_date, status) VALUES (%s, %s, %s, %s, %s)",
            (request_id, resource_id, allocation_date, return_date, 'allocated')
        )
        # Update resource status to 'allocated'
        cur.execute("UPDATE Resource SET status = %s WHERE resource_id = %s", ('allocated', resource_id))
        conn.commit()
        flash("Resource allocated successfully!")
    except Exception as e:
        flash("Error allocating resource.")
        print(f"Allocation error: {e}")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/staff_dashboard', methods=['GET', 'POST'])
def staff_dashboard():
    if 'user_role' in session and session['user_role'] == 'staff':
        staff_id = session['user_id']
        
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        
        # Fetch available resources for dropdown selection in the request form
        cur.execute("SELECT resource_id, resource_name FROM Resource WHERE status = 'available'")
        resources = cur.fetchall()

        # Fetch staff's existing requests
        cur.execute("SELECT * FROM Request WHERE staff_id = %s", (staff_id,))
        requests = cur.fetchall()

        # Fetch allocation details linked to the staff's requests
        cur.execute("""
            SELECT a.allocation_id, a.request_id, a.resource_id, r.resource_name, a.allocation_date, 
                   a.return_date, a.status
            FROM Allocation a
            JOIN Resource r ON a.resource_id = r.resource_id
            JOIN Request req ON a.request_id = req.request_id
            WHERE req.staff_id = %s
        """, (staff_id,))
        allocations = cur.fetchall()

        cur.close()
        conn.close()
        
        return render_template('staff_dashboard.html', requests=requests, resources=resources, allocations=allocations)
    
    flash("Access denied.")
    return redirect(url_for('login'))
# Route to handle request submission
@app.route('/submit_request', methods=['POST'])
def submit_request():
    if 'user_role' in session and session['user_role'] == 'staff':
        staff_id = session['user_id']
        priority = request.form['priority']
        required_date = request.form['required_date']
        return_date = request.form['return_date']
        resource_id = request.form['resource_id']
        quantity = request.form['quantity']

        conn = get_db_connection()
        cur = conn.cursor()
        
        # Insert new request into the Request table
        cur.execute("""
            INSERT INTO Request (staff_id, request_date, request_status, priority, required_date, return_date)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (staff_id, datetime.now().date(), 'pending', priority, required_date, return_date))
        
        # Get the new request_id for linking requested resources
        request_id = cur.lastrowid

        # Insert resource request into Requested_Resources table
        cur.execute("""
            INSERT INTO Requested_Resources (request_id, resource_id, quantity)
            VALUES (%s, %s, %s)
        """, (request_id, resource_id, quantity))
        
        conn.commit()
        cur.close()
        conn.close()
        
        flash("Request submitted successfully!")
        return redirect(url_for('staff_dashboard'))

    flash("Access denied.")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True,port=3000)
