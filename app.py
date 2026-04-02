from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import pymysql
import random
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import socket
from collections import deque, Counter
from threading import Thread, Lock
from time import time
from scapy.all import sniff, IP, TCP, UDP, ICMP , conf
from collections import Counter, deque
from threading import Thread, Lock
from time import time , sleep
conf.use_pcap=True

from time import sleep
app = Flask(__name__)
app.secret_key = "clave_super_secreta_para_pruebas"
_table_columns_cache = {}
PROJECT_IMAGES_DIR = os.path.join(app.root_path, "Imagenes")

# =========================
# DBdskjsfrkjpofkrdario
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

def get_table_columns(table_name):
    if table_name not in _table_columns_cache:
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(f"SHOW COLUMNS FROM {table_name}")
                _table_columns_cache[table_name] = {row["Field"] for row in cursor.fetchall()}
        finally:
            conn.close()
    return _table_columns_cache[table_name]

def get_existing_columns(table_name, preferred_columns):
    table_columns = get_table_columns(table_name)
    return [column for column in preferred_columns if column in table_columns]

def format_datetime(value):
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value

def serialize_event_record(event):
    serialized = dict(event)
    serialized["timestamp"] = format_datetime(serialized.get("timestamp"))
    return serialized

def ensure_user_role_requests_table():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_role_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    assigned_role_id INT NULL,
                    reviewed_by INT NULL,
                    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_at TIMESTAMP NULL DEFAULT NULL,
                    UNIQUE KEY uq_user_role_requests_user (user_id)
                )
            """)
            conn.commit()
    finally:
        conn.close()

def get_user_role_request(cursor, user_id):
    cursor.execute("""
        SELECT urr.id, urr.status, urr.assigned_role_id, urr.requested_at, urr.reviewed_at,
               urr.reviewed_by, r.name AS assigned_role_name, reviewer.username AS reviewed_by_name
        FROM user_role_requests urr
        LEFT JOIN roles r ON urr.assigned_role_id = r.id
        LEFT JOIN users reviewer ON urr.reviewed_by = reviewer.id
        WHERE urr.user_id = %s
        LIMIT 1
    """, (user_id,))
    return cursor.fetchone()

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
            if not user_role:
                return redirect(url_for('pending_role_assignment'))

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
# =========================
# LIVE NETWORK MONITOR
# =========================
class LiveNetworkMonitor:
    def __init__(self):
        self.lock = Lock()
        self.running = False
        self.interface = None

        self.packet_timestamps = deque(maxlen=10000)
        self.byte_timestamps = deque(maxlen=10000)

        self.protocol_counter = Counter()
        self.src_ip_counter = Counter()
        self.dst_ip_counter = Counter()

        self.recent_packets = deque(maxlen=300)

    def process_packet(self, pkt):
        now = time()
        pkt_len = len(pkt)

        protocol = "OTHER"
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        flags = None

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                protocol = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                try:
                    flags = str(pkt[TCP].flags)
                except Exception:
                    flags = None
            elif UDP in pkt:
                protocol = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
            elif ICMP in pkt:
                protocol = "ICMP"
            else:
                protocol = "IP"

        with self.lock:
            self.packet_timestamps.append(now)
            self.byte_timestamps.append((now, pkt_len))

            self.protocol_counter[protocol] += 1
            if src_ip:
                self.src_ip_counter[src_ip] += 1
            if dst_ip:
                self.dst_ip_counter[dst_ip] += 1

            self.recent_packets.append({
                "time": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "size": pkt_len,
                "flags": flags
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
            top_dst = self.dst_ip_counter.most_common(5)

            top_src_labels = [ip for ip, _ in top_src]
            top_src_values = [count for _, count in top_src]

            top_dst_labels = [ip for ip, _ in top_dst]
            top_dst_values = [count for _, count in top_dst]

            labels_time = [f"-{i}s" for i in range(window_seconds - 1, -1, -1)]

            return {
                "time_labels": labels_time,
                "packets_per_sec": pps_points,
                "bytes_per_sec": bps_points,
                "protocol_labels": protocol_labels,
                "protocol_values": protocol_values,
                "top_src_labels": top_src_labels,
                "top_src_values": top_src_values,
                "top_dst_labels": top_dst_labels,
                "top_dst_values": top_dst_values,
                "total_packets": sum(pps_points),
                "total_bytes": sum(bps_points)
            }

    def get_recent_packets_copy(self, limit=50):
        with self.lock:
            return list(self.recent_packets)[-limit:]


# =========================
# TRAFFIC PERSISTENCE
# =========================
def save_traffic_snapshot():
    snapshot = live_monitor.get_snapshot()
    traffic_metric_columns = get_table_columns("traffic_metrics")

    protocol_map = dict(zip(snapshot["protocol_labels"], snapshot["protocol_values"]))
    payload = {
        "window_seconds": 20,
        "packets_total": snapshot["total_packets"],
        "bytes_total": snapshot["total_bytes"],
        "tcp_count": protocol_map.get("TCP", 0),
        "udp_count": protocol_map.get("UDP", 0),
        "icmp_count": protocol_map.get("ICMP", 0),
        "other_count": protocol_map.get("OTHER", 0) + protocol_map.get("IP", 0),
        "top_src_ip": snapshot["top_src_labels"][0] if snapshot["top_src_labels"] else None,
        "top_dst_ip": snapshot["top_dst_labels"][0] if snapshot["top_dst_labels"] else None,
    }
    insertable_columns = [column for column in payload if column in traffic_metric_columns]

    if not insertable_columns:
        raise RuntimeError("traffic_metrics does not have compatible columns for snapshot persistence")

    placeholders = ", ".join(["%s"] * len(insertable_columns))
    columns_sql = ", ".join(insertable_columns)
    values = [payload[column] for column in insertable_columns]

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO traffic_metrics ({columns_sql}) VALUES ({placeholders})",
                values
            )
            conn.commit()
    finally:
        conn.close()



def classify_packet_for_now(packet_dict):
    """
    Clasificación simple temporal.
    Luego esto será reemplazado por dataset + /predict.
    """
    protocol = packet_dict.get("protocol")
    size = packet_dict.get("size", 0)
    dst_port = packet_dict.get("dst_port")

    label = "normal"
    score = 0.05

    # reglas muy básicas de transición
    if protocol == "TCP" and dst_port in (22, 23, 3389):
        label = "suspicious"
        score = 0.60
    elif size > 1400:
        label = "suspicious"
        score = 0.40

    return label, score


def save_recent_packets_as_events(max_packets=10):
    packets = live_monitor.get_recent_packets_copy(limit=max_packets)

    if not packets:
        return

    event_columns = get_table_columns("events")

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            for pkt in packets:
                src_ip = pkt.get("src_ip")
                dst_ip = pkt.get("dst_ip")

                if not src_ip:
                    continue

                label, score = classify_packet_for_now(pkt)

                raw_log = (
                    f"src={src_ip}, dst={dst_ip}, "
                    f"sport={pkt.get('src_port')}, dport={pkt.get('dst_port')}, "
                    f"protocol={pkt.get('protocol')}, size={pkt.get('size')}, flags={pkt.get('flags')}"
                )
                payload = {
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "source_port": pkt.get("src_port"),
                    "dest_port": pkt.get("dst_port"),
                    "protocol": pkt.get("protocol"),
                    "size": pkt.get("size"),
                    "flags": pkt.get("flags"),
                    "label": label,
                    "score": score,
                    "model_version": "rules_v0",
                    "status": "new",
                    "raw_log": raw_log,
                }
                insertable_columns = [column for column in payload if column in event_columns]

                if not insertable_columns:
                    raise RuntimeError("events does not have compatible columns for packet persistence")

                placeholders = ", ".join(["%s"] * len(insertable_columns))
                columns_sql = ", ".join(insertable_columns)
                values = [payload[column] for column in insertable_columns]

                cursor.execute(
                    f"INSERT INTO events ({columns_sql}) VALUES ({placeholders})",
                    values
                )

            conn.commit()
    finally:
        conn.close()


def start_metrics_persistor():
    def _persist_loop():
        while True:
            try:
                save_traffic_snapshot()
            except Exception as e:
                print(f"[METRICS] Error saving traffic snapshot: {e}")
            sleep(10)

    thread = Thread(target=_persist_loop, daemon=True)
    thread.start()


def start_events_persistor():
    def _persist_loop():
        while True:
            try:
                save_recent_packets_as_events(max_packets=8)
            except Exception as e:
                print(f"[EVENTS] Error saving recent packets as events: {e}")
            sleep(15)

    thread = Thread(target=_persist_loop, daemon=True)
    thread.start()


live_monitor = LiveNetworkMonitor()

def start_background_services():
    try:
        live_monitor.start()
    except Exception as e:
        print(f"[LIVE MONITOR] Could not start automatically: {e}")

    try:
        start_metrics_persistor()
    except Exception as e:
        print(f"[METRICS] Could not start persistor: {e}")

    try:
        start_events_persistor()
    except Exception as e:
        print(f"[EVENTS] Could not start events persistor: {e}")



# =========================
# PUBLIC ROUTES
# =========================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/imagenes/<path:filename>')
def project_image(filename):
    return send_from_directory(PROJECT_IMAGES_DIR, filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        ensure_user_role_requests_table()

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
            session['role_assignment_pending'] = False

            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
                    (user['id'],)
                )
                role_request = get_user_role_request(cursor, user['id'])
                conn.commit()

            # AQUÍ VA log_action
            role_pending = role_request and role_request['status'] == 'pending'
            session['role_assignment_pending'] = bool(role_pending)

            log_action(
                action="login",
                entity_type="user",
                entity_id=user['id'],
                details=(
                    f"User {user['username']} logged in and is waiting for role assignment."
                    if role_pending else
                    f"User {user['username']} logged in successfully."
                ),
                user_id=user['id']
            )

            if role_pending:
                session['role'] = None
                return redirect(url_for('pending_role_assignment'))

            session['role'] = user['role_name']

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    ensure_user_role_requests_table()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, question_text FROM security_questions ORDER BY id ASC")
            security_questions = cursor.fetchall()

            cursor.execute("""
                SELECT id, name
                FROM roles
                WHERE name = %s
                LIMIT 1
            """, ('operator',))
            default_role = cursor.fetchone()

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()

            answers = {}
            for question in security_questions:
                answers[question['id']] = request.form.get(f"question_{question['id']}", '').strip()

            if not default_role:
                flash("Registration is unavailable because the operator role is not configured.", "error")
                return render_template('register.html', security_questions=security_questions)

            if not username or not email or not password or not confirm_password:
                flash("All required fields must be completed.", "error")
                return render_template('register.html', security_questions=security_questions)

            if password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template('register.html', security_questions=security_questions)

            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "error")
                return render_template('register.html', security_questions=security_questions)

            if sum(1 for value in answers.values() if value) < 3:
                flash("At least 3 security answers must be provided.", "error")
                return render_template('register.html', security_questions=security_questions)

            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id
                    FROM users
                    WHERE username = %s OR email = %s
                    LIMIT 1
                """, (username, email))
                existing_user = cursor.fetchone()

                if existing_user:
                    flash("Username or email is already registered.", "error")
                    return render_template('register.html', security_questions=security_questions)

                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role_id)
                    VALUES (%s, %s, %s, %s)
                """, (username, email, generate_password_hash(password), default_role['id']))
                user_id = cursor.lastrowid

                cursor.execute("""
                    INSERT INTO user_role_requests (user_id, status, assigned_role_id, reviewed_by, reviewed_at)
                    VALUES (%s, 'pending', NULL, NULL, NULL)
                """, (user_id,))

                for question_id, answer in answers.items():
                    if answer:
                        cursor.execute("""
                            INSERT INTO user_security_answers (user_id, question_id, answer_hash)
                            VALUES (%s, %s, %s)
                        """, (user_id, question_id, generate_password_hash(answer)))

                conn.commit()

            log_action(
                action="self_register",
                entity_type="user",
                entity_id=user_id,
                details=f"Public registration completed for {username}. Pending admin role assignment created.",
                user_id=user_id
            )
            flash("Account created successfully. Sign in to wait for role assignment from the administrator.", "success")
            return redirect(url_for('login'))

    finally:
        conn.close()

    return render_template('register.html', security_questions=security_questions)

@app.route('/back-dashboard')
@login_required
def back_dashboard():
    role = session.get('role')

    if session.get('role_assignment_pending') or not role:
        return redirect(url_for('pending_role_assignment'))

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

@app.route('/pending-role')
@login_required
def pending_role_assignment():
    ensure_user_role_requests_table()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.username, u.is_active, r.name AS role_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                WHERE u.id = %s
                LIMIT 1
            """, (session.get('user_id'),))
            user = cursor.fetchone()

            if not user:
                session.clear()
                flash("User account was not found.", "error")
                return redirect(url_for('login'))

            role_request = get_user_role_request(cursor, user['id'])

            if not user['is_active']:
                session.clear()
                flash("This account is inactive.", "error")
                return redirect(url_for('login'))

            if not role_request or role_request['status'] != 'pending':
                session['role_assignment_pending'] = False
                session['role'] = user['role_name']

                if user['role_name']:
                    flash("Role assigned successfully. Access has been enabled.", "success")
                    return redirect(url_for('back_dashboard'))

                flash("Your account still does not have a valid role assigned.", "error")
                return redirect(url_for('logout'))

            session['role_assignment_pending'] = True
            session['role'] = None
            return render_template(
                'pending_role_assignment.html',
                username=user['username'],
                requested_at=role_request['requested_at']
            )
    finally:
        conn.close()

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
    return render_template(
        'role_dashboard.html',
        dashboard=build_admin_dashboard_context(session.get('username'))
    )

@app.route('/soc')
@login_required
@role_required('soc_analyst')
def soc_dashboard():
    return render_template(
        'role_dashboard.html',
        dashboard=build_soc_dashboard_context(session.get('username'))
    )

@app.route('/netadmin')
@login_required
@role_required('netadmin')
def netadmin_dashboard():
    return render_template(
        'role_dashboard.html',
        dashboard=build_netadmin_dashboard_context(session.get('username'))
    )

@app.route('/auditor')
@login_required
@role_required('auditor')
def auditor_dashboard():
    return render_template(
        'role_dashboard.html',
        dashboard=build_auditor_dashboard_context(session.get('username'))
    )

@app.route('/ml')
@login_required
@role_required('ml_engineer')
def ml_dashboard():
    return render_template(
        'role_dashboard.html',
        dashboard=build_ml_dashboard_context(session.get('username'))
    )

@app.route('/operator')
@login_required
@role_required('operator', 'admin')
def operator_dashboard():
    dashboard_data = get_operator_dashboard_data()
    return render_template(
        'operator_dashboard.html',
        username=session.get('username'),
        dashboard_data=dashboard_data
    )

@app.route('/api/operator-overview')
@login_required
@role_required('operator', 'admin')
def api_operator_overview():
    return jsonify(get_operator_dashboard_data())


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
    collectors = get_collectors_catalog()

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
    ensure_user_role_requests_table()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT u.id, u.username, u.email, u.role_id, u.is_active,
                       u.created_at, u.last_login, r.name AS role_name,
                       urr.status AS request_status, urr.requested_at,
                       reviewer.username AS reviewed_by_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                LEFT JOIN user_role_requests urr ON urr.user_id = u.id
                LEFT JOIN users reviewer ON urr.reviewed_by = reviewer.id
                ORDER BY
                    CASE WHEN urr.status = 'pending' THEN 0 ELSE 1 END,
                    u.id ASC
            """
            cursor.execute(sql)
            users = cursor.fetchall()
    finally:
        conn.close()

    pending_requests_count = sum(1 for user in users if user.get('request_status') == 'pending')
    return render_template(
        'manage_users.html',
        users=users,
        username=session.get('username'),
        pending_requests_count=pending_requests_count
    )

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
    ensure_user_role_requests_table()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name FROM roles ORDER BY id ASC")
            roles = cursor.fetchall()

            cursor.execute("""
                SELECT u.id, u.username, u.email, u.role_id, u.is_active,
                       urr.status AS request_status, urr.requested_at
                FROM users u
                LEFT JOIN user_role_requests urr ON urr.user_id = u.id
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

            if not username or not email or not role_id:
                flash("All fields are required.", "error")
                return render_template('edit_user.html', user=user, roles=roles)

            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET username = %s, email = %s, role_id = %s, is_active = %s
                    WHERE id = %s
                """, (username, email, role_id, is_active, user_id))

                cursor.execute("""
                    SELECT id
                    FROM user_role_requests
                    WHERE user_id = %s
                    LIMIT 1
                """, (user_id,))
                existing_request = cursor.fetchone()

                if existing_request:
                    cursor.execute("""
                        UPDATE user_role_requests
                        SET status = 'approved',
                            assigned_role_id = %s,
                            reviewed_by = %s,
                            reviewed_at = CURRENT_TIMESTAMP
                        WHERE user_id = %s
                    """, (role_id, session.get('user_id'), user_id))

                conn.commit()
                log_action(
                    action="edit_user",
                    entity_type="user",
                    entity_id=user_id,
                    details=(
                        f"User updated and role request approved: username={username}, email={email}, role_id={role_id}, is_active={is_active}."
                        if user.get('request_status') == 'pending' else
                        f"User updated: username={username}, email={email}, role_id={role_id}, is_active={is_active}."
                    )
                )
                

                
            flash(
                "User updated and role assigned successfully." if user.get('request_status') == 'pending'
                else "User updated successfully.",
                "success"
            )
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

def normalize_event_filters(source):
    return {
        "source_ip": source.get('source_ip', '').strip(),
        "dest_ip": source.get('dest_ip', '').strip(),
        "protocol": source.get('protocol', '').strip(),
        "label": source.get('label', '').strip(),
        "status": source.get('status', '').strip()
    }

def parse_int_arg(value, default=50, minimum=1, maximum=200):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))

def build_events_where_clause(filters, event_columns):
    clauses = ["1=1"]
    params = []

    if filters.get("source_ip") and "source_ip" in event_columns:
        clauses.append("source_ip LIKE %s")
        params.append(f"%{filters['source_ip']}%")

    if filters.get("dest_ip") and "dest_ip" in event_columns:
        clauses.append("dest_ip LIKE %s")
        params.append(f"%{filters['dest_ip']}%")

    if filters.get("protocol") and "protocol" in event_columns:
        clauses.append("protocol = %s")
        params.append(filters["protocol"])

    if filters.get("label") and "label" in event_columns:
        clauses.append("label = %s")
        params.append(filters["label"])

    if filters.get("status") and "status" in event_columns:
        clauses.append("status = %s")
        params.append(filters["status"])

    return " AND ".join(clauses), params

def fetch_events_data(filters=None, limit=50):
    filters = filters or {}
    event_columns = get_table_columns("events")
    where_sql, params = build_events_where_clause(filters, event_columns)
    preferred_columns = [
        "id", "timestamp", "source_ip", "dest_ip", "source_port", "dest_port",
        "protocol", "size", "label", "score", "status", "raw_log", "model_version"
    ]
    select_parts = [
        column if column in event_columns else f"NULL AS {column}"
        for column in preferred_columns
    ]
    order_column = "timestamp" if "timestamp" in event_columns else "id"

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT {", ".join(select_parts)}
                FROM events
                WHERE {where_sql}
                ORDER BY {order_column} DESC
                LIMIT %s
                """,
                params + [limit]
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    return [serialize_event_record(row) for row in rows]

def fetch_event_summary(filters=None):
    filters = filters or {}
    event_columns = get_table_columns("events")
    where_sql, params = build_events_where_clause(filters, event_columns)
    select_parts = ["COUNT(*) AS total_events"]

    if "label" in event_columns:
        select_parts.extend([
            "SUM(CASE WHEN label = 'attack' THEN 1 ELSE 0 END) AS total_attacks",
            "SUM(CASE WHEN label = 'suspicious' THEN 1 ELSE 0 END) AS total_suspicious",
            "SUM(CASE WHEN label = 'normal' THEN 1 ELSE 0 END) AS total_normal"
        ])
    else:
        select_parts.extend([
            "0 AS total_attacks",
            "0 AS total_suspicious",
            "0 AS total_normal"
        ])

    if "status" in event_columns:
        select_parts.append("SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) AS total_new")
    else:
        select_parts.append("0 AS total_new")

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT {", ".join(select_parts)}
                FROM events
                WHERE {where_sql}
                """,
                params
            )
            summary = cursor.fetchone() or {}
    finally:
        conn.close()

    return {
        "total_events": int(summary.get("total_events") or 0),
        "total_attacks": int(summary.get("total_attacks") or 0),
        "total_suspicious": int(summary.get("total_suspicious") or 0),
        "total_normal": int(summary.get("total_normal") or 0),
        "total_new": int(summary.get("total_new") or 0)
    }

def get_operator_dashboard_data():
    event_summary = fetch_event_summary()
    recent_events = fetch_events_data(limit=6)
    live_snapshot = live_monitor.get_snapshot()

    return {
        "event_summary": event_summary,
        "recent_events": recent_events,
        "live_metrics": {
            "total_packets": live_snapshot.get("total_packets", 0),
            "total_bytes": live_snapshot.get("total_bytes", 0),
            "top_protocol": (
                live_snapshot["protocol_labels"][0]
                if live_snapshot.get("protocol_labels")
                else "No data"
            ),
            "top_source_ip": (
                live_snapshot["top_src_labels"][0]
                if live_snapshot.get("top_src_labels")
                else "No data"
            )
        }
    }

def fetch_scalar(cursor, query, params=None, key="total", default=0):
    cursor.execute(query, params or ())
    row = cursor.fetchone() or {}
    value = row.get(key, default)
    return value if value is not None else default

def format_percentage_value(value, fallback="0%"):
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return fallback

    if numeric <= 1:
        numeric *= 100

    return f"{numeric:.1f}".rstrip("0").rstrip(".") + "%"

def build_action_item(href, icon, title, description):
    return {
        "href": href,
        "icon": icon,
        "title": title,
        "description": description
    }

def build_focus_item(title, description):
    return {
        "title": title,
        "description": description
    }

def build_activity_item(eyebrow, title, description, meta=None):
    return {
        "eyebrow": eyebrow,
        "title": title,
        "description": description,
        "meta": meta
    }

def get_collectors_catalog():
    return [
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

def build_system_objective(role_note):
    return {
        "title": "Objetivo general del sistema",
        "description": (
            "La plataforma funciona como un IDS colaborativo: captura trafico, detecta eventos "
            "sospechosos y coordina la respuesta entre operaciones, red, auditoria y machine learning."
        ),
        "stages": [
            {
                "eyebrow": "Captura",
                "title": "Recolectar y centralizar evidencia",
                "description": "Eventos, alertas, collectors y actividad de usuarios quedan visibles en un solo lugar."
            },
            {
                "eyebrow": "Deteccion",
                "title": "Priorizar riesgo y contexto",
                "description": "El sistema clasifica trafico, destaca anomalias y facilita el analisis por rol."
            },
            {
                "eyebrow": "Respuesta",
                "title": "Actuar y mejorar continuamente",
                "description": "Cada perfil interviene para contener incidentes, auditar decisiones y elevar el motor de deteccion."
            }
        ],
        "note": role_note
    }

def build_admin_dashboard_context(username):
    total_users = 0
    active_users = 0
    pending_role_requests = 0
    pending_model_requests = 0
    total_events = 0
    recent_users = []

    try:
        ensure_user_role_requests_table()
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                total_users = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM users"))
                active_users = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM users WHERE is_active = 1"))
                pending_role_requests = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(*) AS total FROM user_role_requests WHERE status = 'pending'"
                ))
                pending_model_requests = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(*) AS total FROM model_requests WHERE status = 'pending'"
                ))
                total_events = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM events"))

                cursor.execute("""
                    SELECT u.username, u.created_at, u.is_active,
                           COALESCE(r.name, 'sin rol') AS role_name,
                           urr.status AS request_status
                    FROM users u
                    LEFT JOIN roles r ON u.role_id = r.id
                    LEFT JOIN user_role_requests urr ON urr.user_id = u.id
                    ORDER BY u.created_at DESC
                    LIMIT 4
                """)
                recent_users = cursor.fetchall()
        finally:
            conn.close()
    except Exception:
        recent_users = []

    activity_items = [
        build_activity_item(
            "Pendiente" if user.get("request_status") == "pending" else "Cuenta",
            user.get("username") or "Usuario sin nombre",
            (
                f"Rol: {user.get('role_name') or 'sin rol'} | "
                f"Estado: {'activo' if user.get('is_active') else 'inactivo'}"
            ),
            f"Creado: {format_datetime(user.get('created_at')) or 'sin fecha'}"
        )
        for user in recent_users
    ]

    if not activity_items:
        activity_items = [
            build_activity_item(
                "Sin movimiento",
                "Todavia no hay cuentas recientes",
                "Cuando se creen o aprueben usuarios, apareceran aqui para seguimiento rapido."
            )
        ]

    return {
        "page_title": "Panel de Administrador",
        "panel_class": "admin-panel",
        "role_label": "Administrador",
        "title": "Centro de gobierno del sistema",
        "subtitle": (
            f"Bienvenido, {username}. Desde aqui coordinas accesos, monitoreo y decisiones clave "
            "para que la plataforma IDS opere de forma consistente."
        ),
        "hero_kicker": "Vision ejecutiva",
        "hero_title": "Control transversal de usuarios, eventos y aprobaciones",
        "hero_description": (
            "El rol administrador mantiene alineados los equipos operativos y garantiza que cada perfil "
            "tenga acceso, contexto y flujo de trabajo apropiado."
        ),
        "status_label": f"{pending_role_requests} pendientes" if pending_role_requests else "Activo",
        "hero_link": {"href": url_for('manage_users'), "label": "Gestionar usuarios"},
        "stats": [
            {"label": "Usuarios registrados", "value": total_users, "hint": "Base actual de cuentas"},
            {"label": "Usuarios activos", "value": active_users, "hint": "Accesos habilitados"},
            {"label": "Roles por revisar", "value": pending_role_requests, "hint": "Solicitudes pendientes"},
            {"label": "Eventos monitoreados", "value": total_events, "hint": "Cobertura del sistema"}
        ],
        "focus": {
            "title": "Prioridades del rol",
            "description": "Lo importante para sostener la operacion general del sistema.",
            "items": [
                build_focus_item("Asignacion de accesos", f"{pending_role_requests} cuentas esperan aprobacion o ajuste de rol."),
                build_focus_item("Gobierno operativo", f"{active_users} de {total_users} usuarios estan habilitados para trabajar."),
                build_focus_item("Alineacion con ML", f"{pending_model_requests} solicitudes de promocion necesitan decision administrativa."),
                build_focus_item("Supervision integral", f"El sistema ya concentra {total_events} eventos para trazabilidad y analisis.")
            ]
        },
        "actions": {
            "title": "Accesos rapidos",
            "description": "Entradas directas a las vistas que mas usa este perfil.",
            "items": [
                build_action_item(url_for('manage_users'), "US", "Usuarios y roles", "Crear cuentas, aprobar roles y activar accesos."),
                build_action_item(url_for('list_events'), "EV", "Eventos", "Consultar trafico, etiquetas y estado de los registros."),
                build_action_item(url_for('admin_model_requests'), "MR", "Solicitudes ML", "Revisar promociones de modelos pendientes."),
                build_action_item(url_for('operator_dashboard'), "OP", "Vista operativa", "Abrir el tablero principal de monitoreo.")
            ]
        },
        "activity": {
            "title": "Actividad reciente",
            "description": "Ultimas cuentas visibles para seguimiento administrativo.",
            "link": {"href": url_for('manage_users'), "label": "Abrir gestion completa"},
            "items": activity_items
        },
        "objective": build_system_objective(
            "Tu aporte como admin es mantener el sistema gobernable: acceso correcto, decisiones trazables y coordinacion entre todos los roles."
        )
    }

def build_soc_dashboard_context(username):
    total_alerts = 0
    open_alerts = 0
    critical_alerts = 0
    attack_events = 0
    suspicious_events = 0
    recent_alerts = []

    try:
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                total_alerts = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM alerts"))
                open_alerts = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM alerts WHERE status = 'open'"))
                critical_alerts = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(*) AS total FROM alerts WHERE severity = 'critical' AND status = 'open'"
                ))
                attack_events = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM events WHERE label = 'attack'"))
                suspicious_events = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM events WHERE label = 'suspicious'"))

                cursor.execute("""
                    SELECT a.id, a.title, a.severity, a.status, a.created_at,
                           e.source_ip, e.dest_ip
                    FROM alerts a
                    JOIN events e ON a.event_id = e.id
                    ORDER BY a.created_at DESC
                    LIMIT 4
                """)
                recent_alerts = cursor.fetchall()
        finally:
            conn.close()
    except Exception:
        recent_alerts = []

    activity_items = [
        build_activity_item(
            f"{alert.get('severity') or 'sin gravedad'}",
            alert.get("title") or f"Alerta #{alert.get('id')}",
            (
                f"Origen {alert.get('source_ip') or '-'} hacia {alert.get('dest_ip') or '-'} | "
                f"Estado: {alert.get('status') or 'sin estado'}"
            ),
            f"Creada: {format_datetime(alert.get('created_at')) or 'sin fecha'}"
        )
        for alert in recent_alerts
    ]

    if not activity_items:
        activity_items = [
            build_activity_item(
                "Sin alertas",
                "No hay alertas recientes",
                "Cuando el motor detecte anomalias o ataques, el feed operativo aparecera aqui."
            )
        ]

    return {
        "page_title": "Panel SOC Analyst",
        "panel_class": "soc-panel",
        "role_label": "SOC Analyst",
        "title": "Centro de monitoreo y respuesta",
        "subtitle": (
            f"Bienvenido, {username}. Este panel te ayuda a priorizar alertas, correlacionar eventos "
            "y coordinar medidas de contencion con rapidez."
        ),
        "hero_kicker": "Triage activo",
        "hero_title": "Eventos sospechosos convertidos en decisiones operativas",
        "hero_description": (
            "Aqui se concentra el trabajo del analista: validar riesgo, abrir contexto y escalar acciones "
            "cuando la red muestra senales de ataque o comportamiento anomalo."
        ),
        "status_label": f"{open_alerts} abiertas" if open_alerts else "Estable",
        "hero_link": {"href": url_for('list_alerts'), "label": "Ver alertas"},
        "stats": [
            {"label": "Alertas totales", "value": total_alerts, "hint": "Volumen acumulado"},
            {"label": "Alertas abiertas", "value": open_alerts, "hint": "Pendientes de analisis"},
            {"label": "Criticas activas", "value": critical_alerts, "hint": "Requieren prioridad alta"},
            {"label": "Eventos sospechosos", "value": suspicious_events, "hint": f"Ataques: {attack_events}"}
        ],
        "focus": {
            "title": "Linea de trabajo SOC",
            "description": "Lo que deberia quedar visible apenas entras al panel.",
            "items": [
                build_focus_item("Triage inicial", f"{open_alerts} alertas siguen abiertas y necesitan clasificacion o cierre."),
                build_focus_item("Escalamiento critico", f"{critical_alerts} alertas criticas ameritan seguimiento inmediato."),
                build_focus_item("Correlacion de eventos", f"El sistema registra {attack_events} eventos etiquetados como ataque y {suspicious_events} sospechosos."),
                build_focus_item("Respuesta coordinada", "Si una amenaza requiere contencion, puedes generar una solicitud directa al equipo de red.")
            ]
        },
        "actions": {
            "title": "Accesos rapidos",
            "description": "Vistas mas usadas durante el analisis diario.",
            "items": [
                build_action_item(url_for('list_alerts'), "AL", "Cola de alertas", "Abrir la lista completa con filtros de severidad y estado."),
                build_action_item(url_for('list_alerts', status='open'), "OP", "Solo abiertas", "Ir directo a los casos que siguen pendientes."),
                build_action_item(url_for('list_events'), "EV", "Eventos", "Correlacionar trafico, etiquetas y detalles tecnicos."),
                build_action_item(url_for('create_firewall_request'), "FW", "Contencion", "Solicitar bloqueo o cuarentena al equipo NetAdmin.")
            ]
        },
        "activity": {
            "title": "Alertas recientes",
            "description": "Feed corto para no perder el contexto operativo del turno.",
            "link": {"href": url_for('list_alerts'), "label": "Abrir vista completa"},
            "items": activity_items
        },
        "objective": build_system_objective(
            "Tu rol convierte la deteccion en accion: validar, priorizar y empujar la respuesta antes de que el incidente escale."
        )
    }

def build_netadmin_dashboard_context(username):
    requested_requests = 0
    validated_requests = 0
    applied_requests = 0
    recent_requests = []
    collectors = get_collectors_catalog()
    collectors_issue_count = sum(1 for collector in collectors if collector.get("status") in ("warning", "offline"))

    try:
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                requested_requests = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(*) AS total FROM firewall_requests WHERE status = 'requested'"
                ))
                validated_requests = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(*) AS total FROM firewall_requests WHERE status = 'validated'"
                ))
                applied_requests = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(*) AS total FROM firewall_requests WHERE status = 'applied'"
                ))

                cursor.execute("""
                    SELECT fr.id, fr.source_ip, fr.dest_ip, fr.port, fr.protocol,
                           fr.status, fr.created_at, u1.username AS requested_by_name
                    FROM firewall_requests fr
                    JOIN users u1 ON fr.requested_by = u1.id
                    ORDER BY fr.created_at DESC
                    LIMIT 4
                """)
                recent_requests = cursor.fetchall()
        finally:
            conn.close()
    except Exception:
        recent_requests = []

    activity_items = [
        build_activity_item(
            request_item.get("status") or "sin estado",
            f"Solicitud #{request_item.get('id')}",
            (
                f"{request_item.get('source_ip') or '-'} -> {request_item.get('dest_ip') or '-'} | "
                f"{request_item.get('protocol') or '-'}:{request_item.get('port') or '-'}"
            ),
            (
                f"Solicitada por {request_item.get('requested_by_name') or 'desconocido'} | "
                f"{format_datetime(request_item.get('created_at')) or 'sin fecha'}"
            )
        )
        for request_item in recent_requests
    ]

    if not activity_items:
        activity_items = [
            build_activity_item(
                "Collectors",
                "Sin solicitudes recientes",
                "Mientras tanto, usa este espacio para revisar el estado de collectors y la continuidad de la captura."
            )
        ]

    return {
        "page_title": "Panel NetAdmin",
        "panel_class": "netadmin-panel",
        "role_label": "NetAdmin",
        "title": "Centro de contencion y salud de red",
        "subtitle": (
            f"Bienvenido, {username}. Aqui validas solicitudes de firewall, aplicas contencion "
            "y verificas la estabilidad de los collectors distribuidos."
        ),
        "hero_kicker": "Operacion de red",
        "hero_title": "La respuesta tecnica que ejecuta la contencion del IDS",
        "hero_description": (
            "El panel prioriza solicitudes accionables y te deja ver rapidamente si los collectors "
            "siguen alimentando al sistema con visibilidad confiable."
        ),
        "status_label": f"{requested_requests} por validar" if requested_requests else "En linea",
        "hero_link": {"href": url_for('collectors_status'), "label": "Ver collectors"},
        "stats": [
            {"label": "Solicitudes nuevas", "value": requested_requests, "hint": "Esperan validacion"},
            {"label": "Listas para aplicar", "value": validated_requests, "hint": "Cambios preparados"},
            {"label": "Acciones aplicadas", "value": applied_requests, "hint": "Contencion ejecutada"},
            {"label": "Collectors con alerta", "value": collectors_issue_count, "hint": f"De {len(collectors)} sensores"}
        ],
        "focus": {
            "title": "Lectura operativa del rol",
            "description": "Un resumen rapido para saber donde concentrar la atencion.",
            "items": [
                build_focus_item("Validacion pendiente", f"{requested_requests} solicitudes siguen esperando revision antes de tocar la red."),
                build_focus_item("Aplicacion de cambios", f"{validated_requests} reglas ya estan listas para ejecutarse en firewall."),
                build_focus_item("Continuidad de captura", f"{collectors_issue_count} collectors presentan warning u offline y pueden reducir visibilidad."),
                build_focus_item("Coordinacion con SOC", f"Se han aplicado {applied_requests} acciones de contencion registradas en el flujo.")
            ]
        },
        "actions": {
            "title": "Accesos rapidos",
            "description": "Entradas practicas para revisar cola, aplicar cambios y comprobar telemetria.",
            "items": [
                build_action_item(url_for('list_firewall_requests'), "FR", "Solicitudes", "Abrir la lista completa de requerimientos de firewall."),
                build_action_item(url_for('list_firewall_requests', status='requested'), "RV", "Por validar", "Ir directo a los pedidos nuevos del SOC."),
                build_action_item(url_for('list_firewall_requests', status='validated'), "AP", "Listas para aplicar", "Ver cambios aprobados pendientes de ejecucion."),
                build_action_item(url_for('collectors_status'), "CL", "Collectors", "Revisar disponibilidad, retrasos y nodos sin conexion.")
            ]
        },
        "activity": {
            "title": "Flujo reciente de solicitudes",
            "description": "Resumen corto para no perder el hilo de las medidas de contencion.",
            "link": {"href": url_for('list_firewall_requests'), "label": "Abrir cola completa"},
            "items": activity_items
        },
        "objective": build_system_objective(
            "Tu papel es ejecutar la respuesta tecnica sin perder observabilidad: contienes amenazas y cuidas la salud de la red que alimenta al IDS."
        )
    }

def build_auditor_dashboard_context(username):
    total_logs = 0
    logs_today = 0
    distinct_users = 0
    tracked_entities = 0
    top_actions = []
    recent_logs = []

    try:
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                total_logs = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM audit_log"))
                logs_today = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(*) AS total FROM audit_log WHERE DATE(created_at) = CURDATE()"
                ))
                distinct_users = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(DISTINCT user_id) AS total FROM audit_log WHERE user_id IS NOT NULL"
                ))
                tracked_entities = int(fetch_scalar(
                    cursor,
                    """
                    SELECT COUNT(DISTINCT entity_type) AS total
                    FROM audit_log
                    WHERE entity_type IS NOT NULL AND entity_type <> ''
                    """
                ))

                cursor.execute("""
                    SELECT action, COUNT(*) AS total
                    FROM audit_log
                    GROUP BY action
                    ORDER BY total DESC
                    LIMIT 4
                """)
                top_actions = cursor.fetchall()

                cursor.execute("""
                    SELECT al.id, al.action, al.entity_type, al.details, al.created_at, u.username
                    FROM audit_log al
                    LEFT JOIN users u ON al.user_id = u.id
                    ORDER BY al.created_at DESC
                    LIMIT 4
                """)
                recent_logs = cursor.fetchall()
        finally:
            conn.close()
    except Exception:
        top_actions = []
        recent_logs = []

    focus_items = [
        build_focus_item(
            action_item.get("action") or "accion desconocida",
            f"Registrada {action_item.get('total') or 0} veces en el historial del sistema."
        )
        for action_item in top_actions
    ]

    while len(focus_items) < 4:
        defaults = [
            build_focus_item("Trazabilidad", "Todas las acciones relevantes deben poder reconstruirse con fecha, usuario e IP."),
            build_focus_item("Cumplimiento", "La evidencia operativa ayuda a sostener revisiones internas y externas."),
            build_focus_item("Cambios sensibles", "Usuarios, modelos y acciones de contencion son focos naturales de revision."),
            build_focus_item("Retencion", "Una bitacora consistente mejora el analisis posterior a incidentes.")
        ]
        focus_items = (focus_items + defaults)[:4]

    activity_items = [
        build_activity_item(
            log.get("action") or "evento",
            f"Registro #{log.get('id')}",
            (
                f"Usuario: {log.get('username') or 'System'} | "
                f"Entidad: {log.get('entity_type') or 'sin entidad'}"
            ),
            format_datetime(log.get("created_at")) or "sin fecha"
        )
        for log in recent_logs
    ]

    if not activity_items:
        activity_items = [
            build_activity_item(
                "Bitacora",
                "No hay registros recientes visibles",
                "Cuando el sistema o los usuarios ejecuten acciones relevantes, apareceran aqui."
            )
        ]

    return {
        "page_title": "Panel Auditor",
        "panel_class": "auditor-panel",
        "role_label": "Auditor",
        "title": "Centro de trazabilidad y cumplimiento",
        "subtitle": (
            f"Bienvenido, {username}. Este panel resume la bitacora del sistema para revisar accesos, "
            "acciones administrativas y evidencia operativa."
        ),
        "hero_kicker": "Evidencia operativa",
        "hero_title": "Todo cambio importante debe poder explicarse y reconstruirse",
        "hero_description": (
            "La auditoria no solo mira el pasado: ayuda a verificar que la respuesta a incidentes, "
            "la administracion de usuarios y el ciclo de modelos queden correctamente documentados."
        ),
        "status_label": f"{logs_today} hoy" if logs_today else "Activo",
        "hero_link": {"href": url_for('audit_log_list'), "label": "Abrir audit log"},
        "stats": [
            {"label": "Registros totales", "value": total_logs, "hint": "Historico disponible"},
            {"label": "Registros hoy", "value": logs_today, "hint": "Actividad reciente"},
            {"label": "Usuarios trazados", "value": distinct_users, "hint": "Con eventos auditados"},
            {"label": "Tipos de entidad", "value": tracked_entities, "hint": "Cobertura de evidencia"}
        ],
        "focus": {
            "title": "Senales a revisar",
            "description": "Patrones y frentes que ayudan a orientar una revision rapida.",
            "items": focus_items
        },
        "actions": {
            "title": "Accesos rapidos",
            "description": "Filtros utiles para moverte por la evidencia sin perder tiempo.",
            "items": [
                build_action_item(url_for('audit_log_list'), "LG", "Bitacora completa", "Abrir el registro general del sistema."),
                build_action_item(url_for('audit_log_list', action='login'), "IN", "Inicios de sesion", "Revisar rastros de acceso y autenticacion."),
                build_action_item(url_for('audit_log_list', entity_type='user'), "US", "Cambios de usuarios", "Filtrar evidencia vinculada a cuentas y roles."),
                build_action_item(url_for('audit_log_list', action='approve_model_request'), "ML", "Aprobaciones ML", "Ver acciones ligadas al flujo de modelos.")
            ]
        },
        "activity": {
            "title": "Ultimos registros",
            "description": "Instantanea corta del rastro de auditoria reciente.",
            "link": {"href": url_for('audit_log_list'), "label": "Abrir historial completo"},
            "items": activity_items
        },
        "objective": build_system_objective(
            "Tu valor en la plataforma es preservar confianza: confirmar que cada acceso, cambio y respuesta tenga evidencia clara y verificable."
        )
    }

def build_ml_dashboard_context(username):
    total_models = 0
    active_models = 0
    pending_model_requests = 0
    dataset_count = 0
    best_accuracy = "0%"
    best_model_label = "Sin modelo activo"
    recent_models = []

    try:
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                total_models = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM models"))
                active_models = int(fetch_scalar(cursor, "SELECT COUNT(*) AS total FROM models WHERE is_active = 1"))
                pending_model_requests = int(fetch_scalar(
                    cursor,
                    "SELECT COUNT(*) AS total FROM model_requests WHERE status = 'pending'"
                ))
                dataset_count = int(fetch_scalar(
                    cursor,
                    """
                    SELECT COUNT(DISTINCT dataset_name) AS total
                    FROM models
                    WHERE dataset_name IS NOT NULL AND dataset_name <> ''
                    """
                ))
                best_accuracy = format_percentage_value(fetch_scalar(
                    cursor,
                    "SELECT MAX(accuracy) AS total FROM models",
                    key="total",
                    default=0
                ))

                cursor.execute("""
                    SELECT name, version, accuracy
                    FROM models
                    ORDER BY COALESCE(accuracy, 0) DESC, created_at DESC
                    LIMIT 1
                """)
                best_model = cursor.fetchone()
                if best_model:
                    best_model_label = f"{best_model.get('name')} v{best_model.get('version')}"

                cursor.execute("""
                    SELECT id, name, version, model_type, dataset_name, accuracy, created_at
                    FROM models
                    ORDER BY created_at DESC
                    LIMIT 4
                """)
                recent_models = cursor.fetchall()
        finally:
            conn.close()
    except Exception:
        recent_models = []

    activity_items = [
        build_activity_item(
            model.get("model_type") or "modelo",
            f"{model.get('name') or 'Modelo'} v{model.get('version') or '-'}",
            f"Dataset: {model.get('dataset_name') or 'no especificado'}",
            (
                f"Accuracy: {format_percentage_value(model.get('accuracy'))} | "
                f"{format_datetime(model.get('created_at')) or 'sin fecha'}"
            )
        )
        for model in recent_models
    ]

    if not activity_items:
        activity_items = [
            build_activity_item(
                "Sin versiones",
                "Aun no hay modelos registrados",
                "Cuando empieces a cargar versiones y metricas, este feed mostrara su evolucion."
            )
        ]

    return {
        "page_title": "Panel ML Engineer",
        "panel_class": "ml-panel",
        "role_label": "ML Engineer",
        "title": "Centro de modelos y mejora continua",
        "subtitle": (
            f"Bienvenido, {username}. Aqui organizas versiones, metricas y solicitudes de promocion "
            "para que el motor de deteccion mejore sin perder control."
        ),
        "hero_kicker": "Ciclo del modelo",
        "hero_title": "El motor de deteccion tambien necesita un tablero claro",
        "hero_description": (
            "Este espacio conecta catalogo, metricas y promociones para que el trabajo de ML tenga "
            "impacto visible sobre la calidad del IDS."
        ),
        "status_label": f"{pending_model_requests} pendientes" if pending_model_requests else "Listo",
        "hero_link": {"href": url_for('list_models'), "label": "Ver modelos"},
        "stats": [
            {"label": "Modelos registrados", "value": total_models, "hint": "Versiones disponibles"},
            {"label": "Modelos activos", "value": active_models, "hint": "En produccion"},
            {"label": "Solicitudes pendientes", "value": pending_model_requests, "hint": "Promociones por revisar"},
            {"label": "Mejor accuracy", "value": best_accuracy, "hint": best_model_label}
        ],
        "focus": {
            "title": "Lectura rapida del pipeline",
            "description": "Puntos que ayudan a orientar el trabajo del rol apenas entra al panel.",
            "items": [
                build_focus_item("Catalogo de versiones", f"Hay {total_models} modelos registrados para comparar, revisar y reutilizar."),
                build_focus_item("Promocion a produccion", f"{pending_model_requests} solicitudes de promote siguen esperando revision."),
                build_focus_item("Cobertura de datasets", f"Se han usado {dataset_count} datasets distintos dentro del catalogo actual."),
                build_focus_item("Modelo lider", f"{best_model_label} encabeza las metricas visibles con {best_accuracy}.")
            ]
        },
        "actions": {
            "title": "Accesos rapidos",
            "description": "Vistas practicas para moverte entre registro, metricas y aprobaciones.",
            "items": [
                build_action_item(url_for('create_model'), "NM", "Nuevo modelo", "Registrar una version con metadatos y metricas."),
                build_action_item(url_for('list_models'), "MD", "Catalogo", "Explorar el inventario completo de modelos."),
                build_action_item(url_for('list_model_requests'), "PR", "Promociones", "Consultar solicitudes de despliegue o promote.")
            ]
        },
        "activity": {
            "title": "Versiones recientes",
            "description": "Feed compacto para visualizar la evolucion del trabajo de ML.",
            "link": {"href": url_for('list_models'), "label": "Abrir catalogo completo"},
            "items": activity_items
        },
        "objective": build_system_objective(
            "Tu rol refuerza el nucleo del IDS: mejorar las metricas del detector y convertir aprendizaje en versiones confiables para produccion."
        )
    }
# =========================
# EVENTS MODULE
# =========================
@app.route('/events')
@login_required
@role_required('admin', 'soc_analyst', 'operator')
def list_events():
    filters = normalize_event_filters(request.args)
    events = fetch_events_data(filters=filters, limit=100)
    event_summary = fetch_event_summary(filters=filters)

    return render_template(
        'events_list.html',
        events=events,
        event_summary=event_summary,
        source_ip=filters["source_ip"],
        dest_ip=filters["dest_ip"],
        protocol=filters["protocol"],
        label=filters["label"],
        status=filters["status"]
    )

@app.route('/api/events-feed')
@login_required
@role_required('admin', 'soc_analyst', 'operator')
def api_events_feed():
    filters = normalize_event_filters(request.args)
    limit = parse_int_arg(request.args.get("limit"), default=25, minimum=1, maximum=100)

    return jsonify({
        "filters": filters,
        "summary": fetch_event_summary(filters=filters),
        "events": fetch_events_data(filters=filters, limit=limit)
    })

@app.route('/events/<int:event_id>')
@login_required
@role_required('admin', 'soc_analyst', 'operator')
def event_detail(event_id):
    event_columns = get_table_columns("events")
    select_columns = [
        column if column in event_columns else f"NULL AS {column}"
        for column in [
            "id", "timestamp", "source_ip", "dest_ip", "source_port", "dest_port",
            "protocol", "size", "label", "score", "status", "raw_log",
            "model_version", "flags"
        ]
    ]

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"""
                SELECT {", ".join(select_columns)}
                FROM events
                WHERE id = %s
            """, (event_id,))
            event = cursor.fetchone()

            if not event:
                flash("Event not found.", "error")
                return redirect(url_for('list_events'))
    finally:
        conn.close()

    return render_template('event_detail.html', event=serialize_event_record(event))


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


@app.route('/operator-history')
@login_required
@role_required('operator', 'admin')
def operator_history():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT captured_at, packets_total, bytes_total,
                       tcp_count, udp_count, icmp_count, other_count,
                       top_src_ip, top_dst_ip
                FROM traffic_metrics
                ORDER BY captured_at DESC
                LIMIT 30
            """)
            rows = cursor.fetchall()
    finally:
        conn.close()

    rows.reverse()

    return render_template(
        'operator_history.html',
        rows=rows,
        username=session.get('username')
    )




if __name__ == '__main__':
    debug_mode = True
    if not debug_mode or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_background_services()
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
