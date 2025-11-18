import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-123')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bugtracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relationships
    reported_bugs = db.relationship('Bug', backref='reporter', lazy=True, foreign_keys='Bug.reporter_id')
    assigned_bugs = db.relationship('Bug', backref='assigned_to', lazy=True, foreign_keys='Bug.assignee_id')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Bug(db.Model):
    __tablename__ = 'bug'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')
    priority = db.Column(db.String(20), default='Medium')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<Bug {self.title}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    status_filter = request.args.get('status', 'all')
    priority_filter = request.args.get('priority', 'all')
    
    query = Bug.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    if priority_filter != 'all':
        query = query.filter_by(priority=priority_filter)
    
    bugs = query.order_by(Bug.updated_at.desc()).all()
    return render_template('index.html', 
                         bugs=bugs, 
                         current_status=status_filter,
                         current_priority=priority_filter)

@app.route('/bug/new', methods=['GET', 'POST'])
@login_required
def new_bug():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        priority = request.form.get('priority', 'Medium')
        
        if title and description:
            bug = Bug(
                title=title,
                description=description,
                priority=priority,
                reporter_id=current_user.id
            )
            db.session.add(bug)
            db.session.commit()
            flash('Bug reported successfully!', 'success')
            return redirect(url_for('index'))
        
        flash('Please fill in all required fields', 'error')
    
    return render_template('new_bug.html')

@app.route('/bug/<int:bug_id>')
@login_required
def view_bug(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    users = User.query.all()
    return render_template('view_bug.html', bug=bug, users=users)

@app.route('/bug/<int:bug_id>/update', methods=['POST'])
@login_required
def update_bug(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    
    if 'status' in request.form:
        bug.status = request.form['status']
    if 'priority' in request.form:
        bug.priority = request.form['priority']
    if 'assignee_id' in request.form:
        bug.assignee_id = request.form['assignee_id'] if request.form['assignee_id'] else None
    
    db.session.commit()
    flash('Bug updated successfully!', 'success')
    return redirect(url_for('view_bug', bug_id=bug.id))

@app.route('/bug/<int:bug_id>/delete', methods=['POST'])
@login_required
def delete_bug(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    
    # Only allow admins or the bug reporter to delete
    if not current_user.is_admin and current_user.id != bug.reporter_id:
        flash('You do not have permission to delete this bug.', 'error')
        return redirect(url_for('view_bug', bug_id=bug.id))
    
    db.session.delete(bug)
    db.session.commit()
    flash('Bug has been deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Initialize database
with app.app_context():
    db.create_all()
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
