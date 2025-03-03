@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='sha256')
        membership_type = request.form['membership_type']

        # Membership type validation (example)
        if membership_type not in ['basic', 'premium']:
            flash('Invalid membership type', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password, membership_type=membership_type)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')
