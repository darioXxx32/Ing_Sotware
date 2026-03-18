from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
import random
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import socket
from collections import deque, Counter
from threading import Thread, Lock
from time import time
from scapy.all import sniff, IP, TCP, UDP, ICMP

app = Flask(__name__)
app.secret_key = "clave_super_secreta_para_pruebas"

# =========================
# DB
# =========================
def get_connection():
    return pymysql.connect(
        host="127.0.0.1",
        port=3306,
        user="idsuser",
        password="idspass",
        database="idsdb",
        cursorclass=pymysql.cursors.DictCursor
    )

# =========================
# DECORATORS
# =========================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You must log in first.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("You must log in first.", "error")
                return redirect(url_for('login'))

            user_role = session.get('role')
            if user_role not in allowed_roles:
                flash("You do not have permission to access this section.", "error")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def is_general_admin():
    return session.get('username') == 'dario' and session.get('role') == 'admin'



def check_tcp_service(host, port, timeout=1):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False
def log_action(action, entity_type=None, entity_id=None, details=None, user_id=None):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                user_id if user_id is not None else session.get('user_id'),
                action,
                entity_type,
                entity_id,
                details,
                request.remote_addr
            ))
            conn.commit()
    finally:
        conn.close()



# =========================
# LIVE NETWORK MONITOR
# =========================
class LiveNetworkMonitor:
    def __init__(self):
        self.lock = Lock()
        self.running = False
        self.interface = None

        self.packet_timestamps = deque(maxlen=5000)
        self.byte_timestamps = deque(maxlen=5000)

        self.protocol_counter = Counter()
        self.src_ip_counter = Counter()

        self.recent_packets = deque(maxlen=100)

    def process_packet(self, pkt):
        now = time()
        pkt_len = len(pkt)

        protocol = "OTHER"
        src_ip = "unknown"
        dst_ip = "unknown"

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                protocol = "TCP"
            elif UDP in pkt:
                protocol = "UDP"
            elif ICMP in pkt:
                protocol = "ICMP"
            else:
                protocol = "IP"

        with self.lock:
            self.packet_timestamps.append(now)
            self.byte_timestamps.append((now, pkt_len))
            self.protocol_counter[protocol] += 1
            self.src_ip_counter[src_ip] += 1

            self.recent_packets.append({
                "time": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "size": pkt_len
            })

    def start(self, iface=None):
        if self.running:
            return

        self.running = True
        self.interface = iface

        def _sniff():
            try:
                sniff(
                    iface=iface,
                    prn=self.process_packet,
                    store=False
                )
            except Exception as e:
                print(f"[LIVE MONITOR] Sniff error: {e}")

        thread = Thread(target=_sniff, daemon=True)
        thread.start()

    def get_snapshot(self):
        now = time()
        window_seconds = 20

        with self.lock:
            # packets/sec and bytes/sec over last 20 seconds
            pps_points = []
            bps_points = []

            for i in range(window_seconds, 0, -1):
                start = now - i
                end = start + 1

                p_count = sum(1 for ts in self.packet_timestamps if start <= ts < end)
                b_count = sum(size for ts, size in self.byte_timestamps if start <= ts < end)

                pps_points.append(p_count)
                bps_points.append(b_count)

            protocol_labels = list(self.protocol_counter.keys())
            protocol_values = list(self.protocol_counter.values())

            top_src = self.src_ip_counter.most_common(5)
            top_src_labels = [ip for ip, _ in top_src]
            top_src_values = [count for _, count in top_src]

            labels_time = [f"-{i}s" for i in range(window_seconds-1, -1, -1)]

            return {
                "time_labels": labels_time,
                "packets_per_sec": pps_points,
                "bytes_per_sec": bps_points,
                "protocol_labels": protocol_labels,
                "protocol_values": protocol_values,
                "top_src_labels": top_src_labels,
                "top_src_values": top_src_values,
                "total_packets": sum(pps_points),
                "total_bytes": sum(bps_points)
            }

live_monitor = LiveNetworkMonitor()
# intenta arrancar captura live al iniciar la app
try:
    live_monitor.start()
except Exception as e:
    print(f"[LIVE MONITOR] Could not start automatically: {e}")

# =========================
# PUBLIC ROUTES
# =========================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username_or_email or not password:
            flash("All fields are required.", "error")
            return render_template('login.html')

        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                sql = """
                    SELECT u.id, u.username, u.email, u.password_hash, u.role_id, u.is_active,
                           r.name AS role_name
                    FROM users u
                    JOIN roles r ON u.role_id = r.id
                    WHERE u.username = %s OR u.email = %s
                    LIMIT 1
                """
                cursor.execute(sql, (username_or_email, username_or_email))
                user = cursor.fetchone()

            if not user:
                flash("Invalid username or password.", "error")
                return render_template('login.html')

            if not user['is_active']:
                flash("This account is inactive.", "error")
                return render_template('login.html')

            if not check_password_hash(user['password_hash'], password):
                flash("Invalid username or password.", "error")
                return render_template('login.html')

            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role_name']

            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
                    (user['id'],)
                )
                conn.commit()

            # AQUÍ VA log_action
            log_action(
                action="login",
                entity_type="user",
                entity_id=user['id'],
                details=f"User {user['username']} logged in successfully.",
                user_id=user['id']
            )

            if user['role_name'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role_name'] == 'soc_analyst':
                return redirect(url_for('soc_dashboard'))
            elif user['role_name'] == 'netadmin':
                return redirect(url_for('netadmin_dashboard'))
            elif user['role_name'] == 'auditor':
                return redirect(url_for('auditor_dashboard'))
            elif user['role_name'] == 'ml_engineer':
                return redirect(url_for('ml_dashboard'))
            elif user['role_name'] == 'operator':
                return redirect(url_for('operator_dashboard'))
            else:
                flash("Unknown role.", "error")
                return redirect(url_for('home'))

        finally:
            conn.close()

    return render_template('login.html')

@app.route('/back-dashboard')
@login_required
def back_dashboard():
    role = session.get('role')

    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'soc_analyst':
        return redirect(url_for('soc_dashboard'))
    elif role == 'netadmin':
        return redirect(url_for('netadmin_dashboard'))
    elif role == 'auditor':
        return redirect(url_for('auditor_dashboard'))
    elif role == 'ml_engineer':
        return redirect(url_for('ml_dashboard'))
    elif role == 'operator':
        return redirect(url_for('operator_dashboard'))
    else:
        return redirect(url_for('home'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip()

        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id, username, email
                    FROM users
                    WHERE username = %s OR email = %s
                    LIMIT 1
                """, (username_or_email, username_or_email))
                user = cursor.fetchone()

                if not user:
                    flash("User not found.", "error")
                    return render_template('forgot_password.html')

                cursor.execute("""
                    SELECT usa.question_id, sq.question_text
                    FROM user_security_answers usa
                    JOIN security_questions sq ON usa.question_id = sq.id
                    WHERE usa.user_id = %s
                """, (user['id'],))
                questions = cursor.fetchall()

                if len(questions) < 2:
                    flash("This account does not have enough security questions configured.", "error")
                    return render_template('forgot_password.html')

                selected = random.sample(questions, 2)

                session['reset_user_id'] = user['id']
                session['reset_questions'] = [q['question_id'] for q in selected]

                return render_template('reset_password.html', questions=selected)

        finally:
            conn.close()

    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['POST'])
def reset_password():
    if 'reset_user_id' not in session or 'reset_questions' not in session:
        flash("Reset session expired. Try again.", "error")
        return redirect(url_for('forgot_password'))

    answer1 = request.form.get('answer_1', '').strip()
    answer2 = request.form.get('answer_2', '').strip()
    new_password = request.form.get('new_password', '').strip()

    if not answer1 or not answer2 or not new_password:
        flash("All fields are required.", "error")
        return redirect(url_for('forgot_password'))

    user_id = session['reset_user_id']
    question_ids = session['reset_questions']

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT question_id, answer_hash
                FROM user_security_answers
                WHERE user_id = %s AND question_id IN (%s, %s)
                ORDER BY question_id ASC
            """ % ("%s", "%s", "%s"), (user_id, question_ids[0], question_ids[1]))
            stored_answers = cursor.fetchall()

            if len(stored_answers) != 2:
                flash("Security answers could not be validated.", "error")
                return redirect(url_for('forgot_password'))

            answers_map = {stored_answers[0]['question_id']: stored_answers[0]['answer_hash'],
                           stored_answers[1]['question_id']: stored_answers[1]['answer_hash']}

            valid_1 = check_password_hash(answers_map[question_ids[0]], answer1)
            valid_2 = check_password_hash(answers_map[question_ids[1]], answer2)

            if not (valid_1 and valid_2):
                flash("Incorrect security answers.", "error")
                return redirect(url_for('forgot_password'))

            new_hash = generate_password_hash(new_password)

            cursor.execute("""
                UPDATE users
                SET password_hash = %s
                WHERE id = %s
            """, (new_hash, user_id))
            conn.commit()

        session.pop('reset_user_id', None)
        session.pop('reset_questions', None)
        log_action(
             action="reset_password",
             entity_type="user",
             entity_id=user_id,
            details="Password reset through security questions.",
            user_id=user_id
        )

        flash("Password updated successfully. You can log in now.", "success")
        return redirect(url_for('login'))
    

    finally:
        conn.close()

def save_traffic_snapshot():
    snapshot = live_monitor.get_snapshot()

    protocol_map = dict(zip(snapshot["protocol_labels"], snapshot["protocol_values"]))
    top_src_ip = snapshot["top_src_labels"][0] if snapshot["top_src_labels"] else None

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO traffic_metrics (
                    window_seconds, packets_total, bytes_total,
                    tcp_count, udp_count, icmp_count, other_count,
                    top_src_ip
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                20,
                snapshot["total_packets"],
                snapshot["total_bytes"],
                protocol_map.get("TCP", 0),
                protocol_map.get("UDP", 0),
                protocol_map.get("ICMP", 0),
                protocol_map.get("OTHER", 0) + protocol_map.get("IP", 0),
                top_src_ip
            ))
            conn.commit()
    finally:
        conn.close()

@app.route('/logout')
def logout():
    current_user_id = session.get('user_id')
    current_username = session.get('username')

    if current_user_id:
        log_action(
            action="logout",
            entity_type="user",
            entity_id=current_user_id,
            details=f"User {current_username} logged out.",
            user_id=current_user_id
        )

    session.clear()
    flash("Session closed successfully.", "success")
    return redirect(url_for('login'))

# =========================
# DASHBOARDS
# =========================
@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template('admin_dashboard.html', username=session.get('username'))

@app.route('/soc')
@login_required
@role_required('soc_analyst')
def soc_dashboard():
    return render_template('soc_dashboard.html', username=session.get('username'))

@app.route('/netadmin')
@login_required
@role_required('netadmin')
def netadmin_dashboard():
    return render_template('netadmin_dashboard.html', username=session.get('username'))

@app.route('/auditor')
@login_required
@role_required('auditor')
def auditor_dashboard():
    return render_template('auditor_dashboard.html', username=session.get('username'))

@app.route('/ml')
@login_required
@role_required('ml_engineer')
def ml_dashboard():
    return render_template('ml_dashboard.html', username=session.get('username'))

@app.route('/operator')
@login_required
@role_required('operator')
def operator_dashboard():
    return render_template('operator_dashboard.html', username=session.get('username'))


@app.route('/services-status')
@login_required
@role_required('operator', 'admin')
def services_status():
    mysql_ok = check_tcp_service("127.0.0.1", 3306)

    services = [
        {
            "name": "Flask Web Application",
            "status": "online",
            "description": "Main web application currently running."
        },
        {
            "name": "MySQL Database",
            "status": "online" if mysql_ok else "offline",
            "description": "Relational database used by the platform."
        },
        {
            "name": "Events Module",
            "status": "online",
            "description": "Module used to list, filter and inspect captured events."
        },
        {
            "name": "Detection Service",
            "status": "pending",
            "description": "Machine learning detection service not fully integrated yet."
        }
    ]



    return render_template(
        'services_status.html',
        services=services,
        username=session.get('username')
    )

@app.route('/collectors-status')
@login_required
@role_required('netadmin', 'admin')
def collectors_status():
    collectors = [
        {
            "id": 1,
            "name": "collector-edge-01",
            "type": "Edge Sensor",
            "location": "DMZ Segment",
            "status": "online",
            "last_seen": "2026-03-13 18:40:21",
            "description": "Main collector receiving perimeter traffic logs."
        },
        {
            "id": 2,
            "name": "collector-core-02",
            "type": "Core Network Collector",
            "location": "Internal Core",
            "status": "warning",
            "last_seen": "2026-03-13 18:31:02",
            "description": "Collector active with delayed ingestion."
        },
        {
            "id": 3,
            "name": "collector-branch-03",
            "type": "Branch Office Collector",
            "location": "Remote Site A",
            "status": "offline",
            "last_seen": "2026-03-13 16:02:11",
            "description": "Collector not responding from remote segment."
        },
        {
            "id": 4,
            "name": "collector-cloud-04",
            "type": "Cloud Log Collector",
            "location": "AWS VPC",
            "status": "online",
            "last_seen": "2026-03-13 18:41:08",
            "description": "Receiving VPC flow logs and cloud audit events."
        }
    ]

    return render_template(
        'collectors_status.html',
        collectors=collectors,
        username=session.get('username')
    )



# =========================
# ADMIN USER MANAGEMENT
# =========================
@app.route('/admin/users')
@login_required
@role_required('admin')
def manage_users():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT u.id, u.username, u.email, u.role_id, u.is_active,
                       u.created_at, u.last_login, r.name AS role_name
                FROM users u
                JOIN roles r ON u.role_id = r.id
                ORDER BY u.id ASC
            """
            cursor.execute(sql)
            users = cursor.fetchall()
    finally:
        conn.close()

    return render_template('manage_users.html', users=users, username=session.get('username'))

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_user():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM roles ORDER BY id ASC")
            roles = cursor.fetchall()
            cursor.execute("SELECT id, question_text FROM security_questions ORDER BY id ASC")
            security_questions = cursor.fetchall()

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            role_id = request.form.get('role_id')

            answers = {}
            for q in security_questions:
                answers[q['id']] = request.form.get(f"question_{q['id']}", '').strip()

            if not username or not email or not password or not role_id:
                flash("All fields are required.", "error")
                return render_template('create_user.html', roles=roles, security_questions=security_questions)

            if sum(1 for v in answers.values() if v) < 3:
                flash("At least 3 security answers must be provided.", "error")
                return render_template('create_user.html', roles=roles, security_questions=security_questions)

            password_hash = generate_password_hash(password)

            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role_id)
                    VALUES (%s, %s, %s, %s)
                """, (username, email, password_hash, role_id))
                user_id = cursor.lastrowid

                for qid, answer in answers.items():
                    if answer:
                        cursor.execute("""
                            INSERT INTO user_security_answers (user_id, question_id, answer_hash)
                            VALUES (%s, %s, %s)
                        """, (user_id, qid, generate_password_hash(answer)))

                conn.commit()
                log_action(
                    action="create_user",
                    entity_type="user",
                    entity_id=user_id,
                    details=f"User {username} created with role_id {role_id}."
                )

            flash("User created successfully.", "success")
            return redirect(url_for('manage_users'))

    finally:
        conn.close()

    return render_template('create_user.html', roles=roles, security_questions=security_questions)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM roles ORDER BY id ASC")
            roles = cursor.fetchall()

            cursor.execute("""
                SELECT id, username, email, role_id, is_active
                FROM users
                WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()

            if not user:
                flash("User not found.", "error")
                return redirect(url_for('manage_users'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            role_id = request.form.get('role_id')
            is_active = 1 if request.form.get('is_active') == 'on' else 0

            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET username = %s, email = %s, role_id = %s, is_active = %s
                    WHERE id = %s
                """, (username, email, role_id, is_active, user_id))
                conn.commit()
                log_action(
                    action="edit_user",
                    entity_type="user",
                    entity_id=user_id,
                    details=f"User updated: username={username}, email={email}, role_id={role_id}, is_active={is_active}."
                )
                

                
            flash("User updated successfully.", "success")
            return redirect(url_for('manage_users'))

    finally:
        conn.close()

    return render_template('edit_user.html', user=user, roles=roles)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    if not is_general_admin():
        flash("Only the general administrator can delete users.", "error")
        return redirect(url_for('manage_users'))

    if session.get('user_id') == user_id:
        flash("You cannot delete your own account while logged in.", "error")
        return redirect(url_for('manage_users'))

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
    finally:
        conn.close()
    
    log_action(
        action="delete_user",
        entity_type="user",
        entity_id=user_id,
        details=f"User with id {user_id} deleted by general administrator."
    )    

    flash("User deleted successfully.", "success")
    return redirect(url_for('manage_users'))

@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def toggle_user_status(user_id):
    if session.get('user_id') == user_id:
        flash("You cannot deactivate your own account while logged in.", "error")
        return redirect(url_for('manage_users'))

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE users
                SET is_active = NOT is_active
                WHERE id = %s
            """, (user_id,))
            conn.commit()
            log_action(
                action="toggle_user_status",
                entity_type="user",
                entity_id=user_id,
                details=f"User status toggled for user id {user_id}."
            )
    finally:
        conn.close()

    flash("User status updated successfully.", "success")
    return redirect(url_for('manage_users'))
# =========================
# EVENTS MODULE
# =========================
@app.route('/events')
@login_required
@role_required('admin', 'soc_analyst', 'operator')
def list_events():
    source_ip = request.args.get('source_ip', '').strip()
    dest_ip = request.args.get('dest_ip', '').strip()
    protocol = request.args.get('protocol', '').strip()
    label = request.args.get('label', '').strip()
    status = request.args.get('status', '').strip()

    query = """
        SELECT id, timestamp, source_ip, dest_ip, source_port, dest_port,
               protocol, size, label, score, status
        FROM events
        WHERE 1=1
    """
    params = []

    if source_ip:
        query += " AND source_ip LIKE %s"
        params.append(f"%{source_ip}%")

    if dest_ip:
        query += " AND dest_ip LIKE %s"
        params.append(f"%{dest_ip}%")

    if protocol:
        query += " AND protocol = %s"
        params.append(protocol)

    if label:
        query += " AND label = %s"
        params.append(label)

    if status:
        query += " AND status = %s"
        params.append(status)

    query += " ORDER BY timestamp DESC"

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            events = cursor.fetchall()
    finally:
        conn.close()

    return render_template(
        'events_list.html',
        events=events,
        source_ip=source_ip,
        dest_ip=dest_ip,
        protocol=protocol,
        label=label,
        status=status
    )

@app.route('/events/<int:event_id>')
@login_required
@role_required('admin', 'soc_analyst', 'operator')
def event_detail(event_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT *
                FROM events
                WHERE id = %s
            """, (event_id,))
            event = cursor.fetchone()

            if not event:
                flash("Event not found.", "error")
                return redirect(url_for('list_events'))
    finally:
        conn.close()

    return render_template('event_detail.html', event=event)


# =========================
# AUDIT LOG MODULE
# =========================
@app.route('/audit-log')
@login_required
@role_required('auditor', 'admin')
def audit_log_list():
    action = request.args.get('action', '').strip()
    entity_type = request.args.get('entity_type', '').strip()
    entity_id = request.args.get('entity_id', '').strip()

    query = """
        SELECT al.id, al.action, al.entity_type, al.entity_id, al.details,
               al.ip_address, al.created_at, u.username
        FROM audit_log al
        LEFT JOIN users u ON al.user_id = u.id
        WHERE 1=1
    """
    params = []

    if action:
        query += " AND al.action = %s"
        params.append(action)

    if entity_type:
        query += " AND al.entity_type = %s"
        params.append(entity_type)

    if entity_id:
        query += " AND al.entity_id = %s"
        params.append(entity_id)

    query += " ORDER BY al.created_at DESC"

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            logs = cursor.fetchall()
    finally:
        conn.close()

    return render_template(
        'audit_log_list.html',
        logs=logs,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id
    )

@app.route('/audit-log/<int:log_id>')
@login_required
@role_required('auditor', 'admin')
def audit_log_detail(log_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT al.*, u.username
                FROM audit_log al
                LEFT JOIN users u ON al.user_id = u.id
                WHERE al.id = %s
            """, (log_id,))
            log = cursor.fetchone()

            if not log:
                flash("Audit log entry not found.", "error")
                return redirect(url_for('audit_log_list'))
    finally:
        conn.close()

    return render_template('audit_log_detail.html', log=log)


# =========================
# ALERTS MODULE
# =========================
@app.route('/alerts')
@login_required
@role_required('soc_analyst', 'admin')
def list_alerts():
    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()

    query = """
        SELECT a.id, a.title, a.severity, a.status, a.created_at,
               a.event_id, e.source_ip, e.dest_ip, e.protocol
        FROM alerts a
        JOIN events e ON a.event_id = e.id
        WHERE 1=1
    """
    params = []

    if severity:
        query += " AND a.severity = %s"
        params.append(severity)

    if status:
        query += " AND a.status = %s"
        params.append(status)

    query += " ORDER BY a.created_at DESC"

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            alerts = cursor.fetchall()
    finally:
        conn.close()

    return render_template(
        'alerts_list.html',
        alerts=alerts,
        severity=severity,
        status=status
    )

@app.route('/alerts/<int:alert_id>')
@login_required
@role_required('soc_analyst', 'admin')
def alert_detail(alert_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT a.*, e.source_ip, e.dest_ip, e.source_port, e.dest_port,
                       e.protocol, e.label, e.score, e.raw_log
                FROM alerts a
                JOIN events e ON a.event_id = e.id
                WHERE a.id = %s
            """, (alert_id,))
            alert = cursor.fetchone()

            if not alert:
                flash("Alert not found.", "error")
                return redirect(url_for('list_alerts'))
    finally:
        conn.close()

    return render_template('alert_detail.html', alert=alert)

@app.route('/alerts/<int:alert_id>/close', methods=['POST'])
@login_required
@role_required('soc_analyst', 'admin')
def close_alert(alert_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE alerts
                SET status = 'closed'
                WHERE id = %s
            """, (alert_id,))
            conn.commit()
            log_action(
             action="close_alert",
             entity_type="alert",
             entity_id=alert_id,
             details=f"Alert {alert_id} closed."
            )
    finally:
        conn.close()

    flash("Alert closed successfully.", "success")
    return redirect(url_for('list_alerts'))

# =========================
# FIREWALL REQUESTS MODULE
# =========================
@app.route('/firewall-requests')
@login_required
@role_required('netadmin', 'admin')
def list_firewall_requests():
    status = request.args.get('status', '').strip()

    query = """
        SELECT fr.*,
               u1.username AS requested_by_name,
               u2.username AS validated_by_name,
               u3.username AS applied_by_name
        FROM firewall_requests fr
        JOIN users u1 ON fr.requested_by = u1.id
        LEFT JOIN users u2 ON fr.validated_by = u2.id
        LEFT JOIN users u3 ON fr.applied_by = u3.id
        WHERE 1=1
    """
    params = []

    if status:
        query += " AND fr.status = %s"
        params.append(status)

    query += " ORDER BY fr.created_at DESC"

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            requests_data = cursor.fetchall()
    finally:
        conn.close()

    return render_template(
        'firewall_requests_list.html',
        requests_data=requests_data,
        status=status
    )

@app.route('/firewall-requests/create', methods=['GET', 'POST'])
@login_required
@role_required('soc_analyst', 'admin')
def create_firewall_request():
    if request.method == 'POST':
        source_ip = request.form.get('source_ip', '').strip()
        dest_ip = request.form.get('dest_ip', '').strip()
        port = request.form.get('port', '').strip()
        protocol = request.form.get('protocol', '').strip()
        reason = request.form.get('reason', '').strip()

        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO firewall_requests
                    (requested_by, source_ip, dest_ip, port, protocol, reason, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'requested')
                """, (
                    session.get('user_id'),
                    source_ip or None,
                    dest_ip or None,
                    int(port) if port else None,
                    protocol or None,
                    reason
                ))
                conn.commit()
                request_id = cursor.lastrowid
                log_action(
                  action="create_firewall_request",
                  entity_type="firewall_request",
                  entity_id=request_id,
                  details=f"Firewall request created for source_ip={source_ip}, dest_ip={dest_ip}, port={port}, protocol={protocol}."
                )
        finally:
            conn.close()

        flash("Firewall request created successfully.", "success")
        return redirect(url_for('soc_dashboard'))

    return render_template('create_firewall_request.html')

@app.route('/firewall-requests/<int:request_id>/validate', methods=['POST'])
@login_required
@role_required('netadmin', 'admin')
def validate_firewall_request(request_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE firewall_requests
                SET status = 'validated',
                    validated_by = %s,
                    validated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND status = 'requested'
            """, (session.get('user_id'), request_id))
            conn.commit()
            log_action(
              action="validate_firewall_request",
              entity_type="firewall_request",
              entity_id=request_id,
              details=f"Firewall request {request_id} validated."
            )
    finally:
        conn.close()

    flash("Firewall request validated successfully.", "success")
    return redirect(url_for('list_firewall_requests'))

@app.route('/firewall-requests/<int:request_id>/apply', methods=['POST'])
@login_required
@role_required('netadmin', 'admin')
def apply_firewall_request(request_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE firewall_requests
                SET status = 'applied',
                    applied_by = %s,
                    applied_at = CURRENT_TIMESTAMP
                WHERE id = %s AND status = 'validated'
            """, (session.get('user_id'), request_id))
            conn.commit()
            log_action(
             action="apply_firewall_request",
             entity_type="firewall_request",
             entity_id=request_id,
             details=f"Firewall request {request_id} applied."
            )
    finally:
        conn.close()

    flash("Firewall request applied successfully.", "success")
    return redirect(url_for('list_firewall_requests'))


# =========================
# ML MODELS MODULE
# =========================
@app.route('/models')
@login_required
@role_required('ml_engineer', 'admin')
def list_models():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT m.*, u.username AS created_by_name
                FROM models m
                LEFT JOIN users u ON m.created_by = u.id
                ORDER BY m.created_at DESC
            """)
            models = cursor.fetchall()
    finally:
        conn.close()

    return render_template('models_list.html', models=models)

@app.route('/models/<int:model_id>')
@login_required
@role_required('ml_engineer', 'admin')
def model_detail(model_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT m.*, u.username AS created_by_name
                FROM models m
                LEFT JOIN users u ON m.created_by = u.id
                WHERE m.id = %s
            """, (model_id,))
            model = cursor.fetchone()

            if not model:
                flash("Model not found.", "error")
                return redirect(url_for('list_models'))
    finally:
        conn.close()

    return render_template('model_detail.html', model=model)

@app.route('/models/create', methods=['GET', 'POST'])
@login_required
@role_required('ml_engineer', 'admin')
def create_model():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        version = request.form.get('version', '').strip()
        model_type = request.form.get('model_type', '').strip()
        dataset_name = request.form.get('dataset_name', '').strip()
        accuracy = request.form.get('accuracy', '').strip()
        precision_score = request.form.get('precision_score', '').strip()
        recall_score = request.form.get('recall_score', '').strip()
        f1_score = request.form.get('f1_score', '').strip()

        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO models
                    (name, version, model_type, dataset_name, accuracy, precision_score, recall_score, f1_score, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    name, version, model_type, dataset_name,
                    accuracy or None,
                    precision_score or None,
                    recall_score or None,
                    f1_score or None,
                    session.get('user_id')
                ))
                model_id = cursor.lastrowid
                conn.commit()

            log_action(
                action="create_model",
                entity_type="model",
                entity_id=model_id,
                details=f"Model {name} version {version} created."
            )
        finally:
            conn.close()

        flash("Model registered successfully.", "success")
        return redirect(url_for('list_models'))

    return render_template('create_model.html')

@app.route('/model-requests')
@login_required
@role_required('ml_engineer', 'admin')
def list_model_requests():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT mr.*, 
                       m.name AS model_name,
                       m.version AS model_version,
                       u1.username AS requested_by_name,
                       u2.username AS reviewed_by_name
                FROM model_requests mr
                JOIN models m ON mr.model_id = m.id
                JOIN users u1 ON mr.requested_by = u1.id
                LEFT JOIN users u2 ON mr.reviewed_by = u2.id
                ORDER BY mr.created_at DESC
            """)
            requests_data = cursor.fetchall()
    finally:
        conn.close()

    return render_template('model_requests_list.html', requests_data=requests_data)

@app.route('/model-requests/create/<int:model_id>', methods=['POST'])
@login_required
@role_required('ml_engineer', 'admin')
def create_model_request(model_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO model_requests
                (model_id, requested_by, request_type, status)
                VALUES (%s, %s, 'promote', 'pending')
            """, (model_id, session.get('user_id')))
            request_id = cursor.lastrowid
            conn.commit()

        log_action(
            action="create_model_request",
            entity_type="model_request",
            entity_id=request_id,
            details=f"Promote request created for model id {model_id}."
        )
    finally:
        conn.close()

    flash("Promote request created successfully.", "success")
    return redirect(url_for('list_model_requests'))

# =========================
# ADMIN REVIEW OF MODEL REQUESTS
# =========================
@app.route('/admin/model-requests')
@login_required
@role_required('admin')
def admin_model_requests():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT mr.*, 
                       m.name AS model_name,
                       m.version AS model_version,
                       u1.username AS requested_by_name,
                       u2.username AS reviewed_by_name
                FROM model_requests mr
                JOIN models m ON mr.model_id = m.id
                JOIN users u1 ON mr.requested_by = u1.id
                LEFT JOIN users u2 ON mr.reviewed_by = u2.id
                ORDER BY mr.created_at DESC
            """)
            requests_data = cursor.fetchall()
    finally:
        conn.close()

    return render_template('admin_model_requests.html', requests_data=requests_data)

@app.route('/admin/model-requests/<int:request_id>/approve', methods=['POST'])
@login_required
@role_required('admin')
def approve_model_request(request_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT model_id
                FROM model_requests
                WHERE id = %s AND status = 'pending'
            """, (request_id,))
            req = cursor.fetchone()

            if not req:
                flash("Request not found or already reviewed.", "error")
                return redirect(url_for('admin_model_requests'))

            model_id = req['model_id']

            # Desactivar todos los modelos
            cursor.execute("UPDATE models SET is_active = FALSE")

            # Activar el modelo aprobado
            cursor.execute("""
                UPDATE models
                SET is_active = TRUE
                WHERE id = %s
            """, (model_id,))

            # Marcar solicitud como aprobada
            cursor.execute("""
                UPDATE model_requests
                SET status = 'approved',
                    reviewed_by = %s,
                    reviewed_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (session.get('user_id'), request_id))

            conn.commit()

        log_action(
            action="approve_model_request",
            entity_type="model_request",
            entity_id=request_id,
            details=f"Model request {request_id} approved. Model {model_id} promoted to active."
        )
    finally:
        conn.close()

    flash("Model request approved successfully.", "success")
    return redirect(url_for('admin_model_requests'))

@app.route('/admin/model-requests/<int:request_id>/reject', methods=['POST'])
@login_required
@role_required('admin')
def reject_model_request(request_id):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE model_requests
                SET status = 'rejected',
                    reviewed_by = %s,
                    reviewed_at = CURRENT_TIMESTAMP
                WHERE id = %s AND status = 'pending'
            """, (session.get('user_id'), request_id))
            conn.commit()

        log_action(
            action="reject_model_request",
            entity_type="model_request",
            entity_id=request_id,
            details=f"Model request {request_id} rejected."
        )
    finally:
        conn.close()

    flash("Model request rejected successfully.", "success")
    return redirect(url_for('admin_model_requests'))


# =========================
# OPERATOR METRICS DASHBOARD
# =========================
@app.route('/operator-metrics')
@login_required
@role_required('operator', 'admin')
def operator_metrics():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # resumen general
            cursor.execute("SELECT COUNT(*) AS total FROM events")
            total_events = cursor.fetchone()['total']

            cursor.execute("SELECT COUNT(*) AS total FROM events WHERE label = 'attack'")
            total_attacks = cursor.fetchone()['total']

            cursor.execute("SELECT COUNT(*) AS total FROM events WHERE label = 'suspicious'")
            total_suspicious = cursor.fetchone()['total']

            cursor.execute("SELECT COUNT(*) AS total FROM events WHERE label = 'normal'")
            total_normal = cursor.fetchone()['total']

            # por protocolo
            cursor.execute("""
                SELECT protocol, COUNT(*) AS total
                FROM events
                GROUP BY protocol
                ORDER BY total DESC
            """)
            protocol_data = cursor.fetchall()

            # por etiqueta
            cursor.execute("""
                SELECT label, COUNT(*) AS total
                FROM events
                GROUP BY label
                ORDER BY total DESC
            """)
            label_data = cursor.fetchall()

            # por estado
            cursor.execute("""
                SELECT status, COUNT(*) AS total
                FROM events
                GROUP BY status
                ORDER BY total DESC
            """)
            status_data = cursor.fetchall()

            # últimos 10 eventos para ver fluctuación temporal
            cursor.execute("""
                SELECT DATE_FORMAT(timestamp, '%%H:%%i') AS event_time, COUNT(*) AS total
                FROM (
                    SELECT timestamp
                    FROM events
                    ORDER BY timestamp DESC
                    LIMIT 10
                ) recent_events
                GROUP BY event_time
                ORDER BY event_time ASC
            """)
            time_data = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        'operator_metrics_dashboard.html',
        total_events=total_events,
        total_attacks=total_attacks,
        total_suspicious=total_suspicious,
        total_normal=total_normal,
        protocol_data=protocol_data,
        label_data=label_data,
        status_data=status_data,
        time_data=time_data,
        username=session.get('username')
    )



# =========================
# LIVE TRAFFIC DASHBOARD
# =========================
@app.route('/operator-live')
@login_required
@role_required('operator', 'admin')
def operator_live_dashboard():
    return render_template(
        'operator_live_dashboard.html',
        username=session.get('username')
    )

@app.route('/api/live-traffic')
@login_required
@role_required('operator', 'admin')
def api_live_traffic():
    return live_monitor.get_snapshot()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)