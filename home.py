@app.route('/')
def home():
    return render_template('home.html')
