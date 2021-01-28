#..................................................................................#
# subjectss
@app.route('/subject/<subject_id>', methods = ['GET'])
@require_login
def subject(subject_id):
    p = Post.query.filter_by( sub = request.args.get('sub')).all()
    return render_template("subject.html", posts = p, sub = request.args.get('sub'))

@app.route('/add_subject', methods = ['GET', 'POST'])
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
                name = name,
                description = description,
                user_id = user_id
                )
        db.session.add(subject)

        db.session.commit()
        return redirect('/subject')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)
        
#..................................................................................#
# posts 

@app.route('/subject/<subject_id>/add_post', methods = ['GET', 'POST'])
@require_login
def add_post(subject_id):
    if request.method == 'GET':
        return render_template('add_post.html', subject_id = subject_id)
    else:
        content = request.form.get("content")
        subject_id = subject_id
        token = request.cookies.get('token')
        user_id = User.find_by_token(token).id

    try:
        post = Post(
                content = content,
                user_id = user_id,
                sub = request.args.get('sub')
                )
        db.session.add(post)
        db.session.commit()
        return redirect('/subject/<subject_id>/post')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/subject/<subject_id>/post/<post_id>/edit_post', methods=['GET', 'POST'])
@require_login
def edit_post(subject_id, post_id):
    if request.method == 'GET':
        subject = Subject.query.get(subject_id)
        post = Post.query.get(post_id)
        return render_template('edit_post.html', subject_id = subject_id, post_id = post_id,
        subject = subject, post = post)
    else:
        name = request.form.get('name')
    try:
        post = Post.query.get(post_id)
        post.name = name
        db.session.commit()
        return redirect('/subject/<subject_id>/post/<post_id>')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

@app.route('/subject/<subject_id>/post/<post_id>/delete_post', methods=['GET'])
@require_login
def delete_post(subject_id, post_id):
    try:
        post = Post.query.get(post_id)  
        db.session.delete(post)
        db.session.commit()
        return redirect('/subject/<subject_id>/post')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)

#---------------------------------------------------------------------------------#
if __name__ == "__main__":
	app.run( debug=True)



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
