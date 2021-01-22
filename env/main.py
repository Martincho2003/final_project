from enum import unique
import json
import hashlib
from functools import wraps
from flask import request, Flask, flash, redirect, jsonify
from flask import render_template
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (
        TimedJSONWebSignatureSerializer as Serializer,
        BadSignature,
        SignatureExpired
    )
from sqlalchemy.orm import backref


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/dev.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.secret_key = "wakbcawiluchawoedhaewu2342bwa"

db = SQLAlchemy(app)

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    subjects = db.relationship('Subject',
            foreign_keys='Subject.user_id',
            backref='User')
    posts = db.relationship('Post',
            foreign_keys='Post.user_id',
            backref='User')
    messages = db.relationship('Message',
            foreign_keys='Message.user_id',
            backref='User'
            )

    def __init__(self, **kwargs):
        if 'password' in kwargs:
            kwargs['password'] = hash_password(kwargs['password'])
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User %r>' % self.username

    def verify_password(self, password):
        return self.password == hash_password(password)

    def generate_token(self):
        s = Serializer(app.secret_key, expires_in=600)
        return s.dumps({'username': self.username})

    @staticmethod
    def find_by_token(token):
        if not token:
            return None
        try:
            s = Serializer(app.secret_key)
            payload = s.loads(token)
            return User.query.filter_by(username=payload.get('username')).first()
        except SignatureExpired:
            return None

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(500), unique=True)
    posts = db.relationship('Post',
            foreign_keys='Post.subject_id',
            backref='Subject')
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    messages = db.relationship('Message',
            foreign_keys='Message.post_id',
            backref='Post'
            )
    subject_id = db.Column(db.Integer, db.ForeignKey(Subject.id))
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey(Post.id))
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


db.create_all()
def verify_token(token):
    s = Serializer(app.secret_key)
    try:
        s.loads(token)
    except SignatureExpired:
        return False
    except BadSignature:
        return False
    return True

def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        if not token or not verify_token(token):
            flash('You have to be logged in to access this page')
            return redirect('/login')
        return func(*args, **kwargs)
    return wrapper

def stop_logged_users(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        if token and verify_token(token):
            flash('You\'re already logged in.')
            return redirect('/')
        return func(*args, **kwargs)
    return wrapper

@app.route("/")
def hello():
    token = request.cookies.get('token')
    current_user = User.find_by_token(token)
    return render_template("base.html", current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
@stop_logged_users
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        data = json.loads(request.data.decode('ascii'))
        username = data['username']
        password = data['password']

        user = User.query.filter_by(username=username).first()
        if not user or not user.verify_password(password):
            return jsonify({'token': None})
        token = user.generate_token()
        return jsonify({'token': token.decode('ascii')})

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        username = request.form['username']
        password = request.form['password']

    try:
        user = User(
                username=username,
                password=password,
                )
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    except Exception as e:
        flash('Error: Username is already used!')
        return redirect(request.url)

"""
TODO:
@app.route('/my_subjects'), methods=['GET', 'POST']

@app.route('/my_posts'), methods=['GET', 'POST']
"""

@app.route('/add_subject', methods=['GET', 'POST'])
@require_login
def add_subject():
    if request.method == 'GET':
        return render_template('add_subject.html')
    else:
        name = request.form.get("name")
        token = request.cookies.get('token')
        current_user = User.find_by_token(token)
        description = request.form.get('description')
        user_id = current_user.id

    try:
        subject = Subject(
                name=name,
                description=description,
                user_id = user_id
                )
        db.session.add(subject)
        db.session.commit()
        return redirect('/')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/edit_subject/<subject_id>', methods=['GET', 'POST'])
@require_login
def edit_subject(subject_id):
    if request.method == 'GET':
        return render_template('edit_subject.html')
    else:
        name = request.form.get("name")
        description = request.form.get('description')

    try:
        subject = Subject.query.get(subject_id)
        subject.name = name
        subject.description = description
        db.session.commit()
        return redirect('/')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/delete_subject/<subject_id>', methods=['POST'])
@require_login
def delete_subject(subject_id):
    try:
        subject = Subject.query.get(subject_id)
        db.session.delete(subject)
        db.session.commit()
        return redirect('/')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

"""@app.route('/my_posts/add_post/<subject_id>', methods=['GET', 'POST'])
@require_login
def add_post(subject_id):
    if request.method == 'GET':
        return render_template('add_post.html')
    else:
        name = request.form.get("name")
        subject_id = Subject.query.filter_by(id=subject_id)
        token = request.cookies.get('token')
        current_user = User.find_by_token(token)
        user_id = current_user.id

    try:
        subject = Subject(
                name = name,
                subject_id = subject_id,
                user_id = user_id
                )
        db.session.add(subject)
        db.session.commit()
        return redirect('/')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)"""

if __name__ == "__main__":
	app.run()