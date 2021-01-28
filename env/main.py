from sqlalchemy import asc
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
    """messages = db.relationship('Message',
            foreign_keys='Message.user_id',
            backref='User'
            )"""

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
    """messages = db.relationship('Message',
            foreign_keys='Message.subject_id',
            backref='Subject'
            )"""
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    """messages = db.relationship('Message',
            foreign_keys='Message.post_id',
            backref='Post'
            )"""
    subject_id = db.Column(db.Integer, db.ForeignKey(Subject.id))
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

"""class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey(Post.id))
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    subject_id = db.Column(db.Integer, db.ForeignKey(Subject.id))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
"""

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
    all = Subject.query.all()
    subjects = list(all)
    return render_template("base.html", current_user=current_user, subjects=subjects)

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

@app.route('/my_subjects', methods=['GET'])
@require_login
def subjects():
    token = request.cookies.get('token')
    current_user = User.find_by_token(token)
    all = Subject.query.filter_by(user_id = current_user.id)
    subjects = list(all)
    return render_template('my_subjects.html', subjects=subjects)

@app.route('/my_subjects/<subject_id>', methods=['GET'])
@require_login
def subject(subject_id):
    subject = Subject.query.get(subject_id)
    token = request.cookies.get('token')
    current_user = User.find_by_token(token)
    all = Post.query.filter_by(subject_id = subject_id, user_id=current_user.id)
    posts = list(all)
    return render_template('subject.html', subject_id=subject_id, subject=subject, posts=posts)

@app.route('/<subject_id>', methods=['GET'])
def subject2(subject_id):
    subject = Subject.query.get(subject_id)
    token = request.cookies.get('token')
    current_user = User.find_by_token(token)
    all = Post.query.filter_by(subject_id = subject_id).order_by(asc(Post.timestamp)).all()
    posts = list(all)
    return render_template('subject.html', subject_id=subject_id, subject=subject, current_user=current_user, posts=posts)

@app.route('/my_subjects/add_subject', methods=['GET', 'POST'])
@require_login
def add_subject():
    if request.method == 'GET':
        return render_template('add_subject.html')
    else:
        name = request.form.get('name')
        token = request.cookies.get('token')
        current_user = User.find_by_token(token)
        description = request.form.get('message')
        user_id = current_user.id

    try:
        subject = Subject(
                name=name,
                description=description,
                user_id = user_id
                )
        db.session.add(subject)

        db.session.commit()
        return redirect('/my_subjects')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/my_subjects/<subject_id>/edit_subject', methods=['GET', 'POST'])
@require_login
def edit_subject(subject_id):
    if request.method == 'GET':
        subject= Subject.query.get(subject_id)
        return render_template('edit_subject.html', subject_id=subject_id, subject=subject)
    else:
        name = request.form.get('name')
        description = request.form.get('message')

    try:
        subject = Subject.query.get(subject_id)
        subject.name = name
        subject.description = description
        db.session.commit()
        return redirect('/my_subjects/<subject_id>')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/my_subjects/<subject_id>/delete_subject', methods=['GET'])
@require_login
def delete_subject(subject_id):
    try:
        subject = Subject.query.get(subject_id)
        posts = Post.query.filter_by(subject_id=subject_id)
        for post in posts:
            db.session.delete(post)
        """messages = Message.query.get(subject_id=subject_id)
        for message in messages:
            db.session.delete(message)"""
        db.session.delete(subject)
        db.session.commit()
        return redirect('/my_subjects')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/my_subjects/<subject_id>/my_posts', methods=['GET'])
@require_login
def posts(subject_id):
    subject = Subject.query.get(subject_id)
    token = request.cookies.get('token')
    current_user = User.find_by_token(token)
    all = Post.query.filter_by(subject_id=subject_id, user_id = current_user.id)
    posts = list(all)
    return render_template('my_posts.html', subject_id=subject_id, subject=subject, posts=posts)

@app.route('/my_subjects/<subject_id>/my_posts/add_post', methods=['GET', 'POST'])
@require_login
def add_post(subject_id):
    if request.method == 'GET':
        return render_template('add_post.html', subject_id=subject_id)
    else:
        name = request.form.get("name")
        subject_id = subject_id
        token = request.cookies.get('token')
        current_user = User.find_by_token(token)
        user_id = current_user.id

    try:
        post = Post(
                name = name,
                subject_id = subject_id,
                user_id = user_id
                )
        db.session.add(post)
        db.session.commit()
        return redirect('/my_subjects/<subject_id>/my_posts')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/<subject_id>/add_post', methods=['GET', 'POST'])
def add_post_2(subject_id):
    if request.method == 'GET':
        return render_template('add_post.html', subject_id=subject_id)
    else:
        name = request.form.get("name")
        subject_id = subject_id

    try:
        post = Post(
                name = name,
                subject_id = subject_id,
                )
        db.session.add(post)
        db.session.commit()
        return redirect('/')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/my_subjects/<subject_id>/my_posts/<post_id>', methods=['GET'])
@require_login
def post(subject_id, post_id):
    subject = Subject.query.get(subject_id)
    post = Post.query.get(post_id)
    return render_template("post.html", subject_id=subject_id, post_id=post_id,
    subject=subject, post=post)

@app.route('/my_subjects/<subject_id>/my_posts/<post_id>/edit_post', methods=['GET', 'POST'])
@require_login
def edit_post(subject_id, post_id):
    if request.method == 'GET':
        subject = Subject.query.get(subject_id)
        post = Post.query.get(post_id)
        return render_template('edit_post.html', subject_id=subject_id, post_id=post_id,
        subject=subject, post=post)
    else:
        name = request.form.get('name')

    try:
        post = Post.query.get(post_id)
        post.name = name
        db.session.commit()
        return redirect('/my_subjects/<subject_id>/my_posts/<post_id>')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/my_subjects/<subject_id>/my_posts/<post_id>/delete_post', methods=['GET'])
@require_login
def delete_post(subject_id, post_id):
    try:
        post = Post.query.get(post_id)
        """messages = Message.query.get(post_id=post_id)
        for message in messages:
            db.session.delete(message)"""   
        db.session.delete(post)
        db.session.commit()
        return redirect('/my_subjects/<subject_id>/my_posts')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

#TODO:
@app.route('/<subject_id>/<post_id>', methods=['GET', 'POST'])
def messaging(subject_id, post_id):
    if request.method == 'GET':
        return render_template('messages.html', subject_id=subject_id, post_id=post_id)
    else:
        pass

if __name__ == "__main__":
	app.run()