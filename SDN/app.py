from flask import Flask, render_template, request, session, redirect, url_for, flash
import json
import os

app = Flask(__name__, template_folder='.')
app.secret_key = 'sdn2026secret'

LOG_FILE = '/home/pi/Desktop/SDN/incidents.log'
BLOCKED_IPS_FILE = '/home/pi/Desktop/SDN/blocked_ips.txt'

def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_blocked_ips(ips):
    with open(BLOCKED_IPS_FILE, 'w') as f:
        for ip in ips:
            f.write(ip + '\n')

@app.route('/')
def index():
    logs = []
    total_events = 0
    blocked_count = 0
    switch_count = 0

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    log = json.loads(line.strip())
                    logs.append(log)
                    total_events += 1
                    if 'BLOCK' in str(log.get('event_type', '')).upper():
                        blocked_count += 1
                    if 'SWITCH' in str(log.get('event_type', '')).upper():
                        switch_count += 1
                except:
                    continue

    logs = logs[-50:][::-1]
    latest_alert = logs[0] if logs else None

    return render_template('index.html',
                         logs=logs,
                         total_events=total_events,
                         blocked_count=blocked_count,
                         switch_count=switch_count,
                         latest_alert=latest_alert,
                         admin_logged_in=session.get('admin_logged_in', False),
                         blocked_ips=load_blocked_ips())

# ====================== ADMIN ROUTES ======================
@app.route('/admin/login', methods=['POST'])
def admin_login():
    if request.form.get('username') == 'admin' and request.form.get('password') == 'sdn2026':
        session['admin_logged_in'] = True
    else:
        flash('Invalid credentials!', 'danger')
    return redirect(url_for('index'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin/clear_logs', methods=['POST'])
def clear_logs():
    if session.get('admin_logged_in'):
        open(LOG_FILE, 'w').close()
        flash('All logs cleared successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/admin/unblock', methods=['POST'])
def unblock_ip():
    if session.get('admin_logged_in'):
        ip = request.form.get('ip')
        if ip:
            blocked = load_blocked_ips()
            if ip in blocked:
                blocked.remove(ip)
                save_blocked_ips(blocked)
                flash(f'IP {ip} has been unblocked!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    print("🚀 SDN Guard Running...")
    print("Access: http://10.58.3.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
