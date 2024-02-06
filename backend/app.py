import logging
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.before_request
def require_login():
    # List of routes that don't require authentication
    open_routes = ['login', 'register', 'static']
    
    if not current_user.is_authenticated and request.endpoint not in open_routes:
        return redirect(url_for('login'))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    members = db.relationship('User', secondary='group_member', backref=db.backref('groups', lazy='dynamic'))

class GroupMember(db.Model):
    __tablename__ = 'group_member'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), primary_key=True)

def clear_messages():
    try:
        num_rows_deleted = db.session.query(Message).delete()
        db.session.commit()
        print(f"Cleared {num_rows_deleted} messages.")
    except Exception as e:
        print("Error clearing messages:", e)
        db.session.rollback()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', messages=messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

from flask import jsonify

@app.route('/messages')
def show_messages():
    messages = Message.query.all()
    messages_list = [{'sender_id': message.sender_id, 'content': message.content, 'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')} for message in messages]
    return jsonify(messages_list)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        content = request.form['content']
        sender = User.query.filter_by(username=current_user.username).first()
        new_message = Message(content=content, sender_id=sender.id)
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!')
    
    messages = Message.query.order_by(Message.timestamp.desc()).all()
    return render_template('message.html', messages=messages)

@socketio.on('send message')
def handle_send_message(json, methods=['GET', 'POST']):
    logging.info(f"Received message: {json}")
    sender = User.query.filter_by(username=current_user.username).first()
    new_message = Message(content=json['content'], sender_id=sender.id)
    db.session.add(new_message)
    db.session.commit()
    emit('receive message', {'content': json['content'], 'sender': sender.username}, broadcast=True)

scheduler.add_job(id='Clear Messages', func=clear_messages, trigger='interval', minutes=5)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)