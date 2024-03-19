from flask import Flask, request, render_template, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_login import current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here-123'
login_manager = LoginManager()
login_manager.init_app(app)

# In a real application, the user data would be stored in a database
users = {
    'user1': {'password': 'password1'}, 
    'user2': {'password': 'password2'}
    }

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username not in users:
        return
    user = User()
    user.id = username
    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form['username']
    if (username in users and request.form['password'] == users[username]['password']):
        user = User()
        user.id = username
        login_user(user)
        return redirect(url_for('protected'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out'

@app.route('/protected')
@login_required
def protected():
    return 'Logged in as: ' + current_user.id

if __name__ == "__main__":
    app.run(debug=True)
