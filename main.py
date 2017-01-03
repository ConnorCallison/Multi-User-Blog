import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape =True)

secret = "29ae45de319049aebb7f2c40dc27d83fc37d0a1d"

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

class BaseHandler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template,**kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

"""
-----------------------------------------------
			USER AUTHENTICATION
-----------------------------------------------
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return email and EMAIL_RE.match(email)

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

class RegisterPage(BaseHandler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		self.render("register.html")

	def post(self):
		input_error = False
		self.username = self.request.get('username')
		self.password =  self.request.get('password')
		self.pass_conf = self.request.get('pass-conf')
		self.email = self.request.get('email')

		params = dict( username = self.username,
						email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "Username not valid."
			input_error = True

		if not valid_email(self.email):
			params['error_email'] = "Email not valid."
			input_error = True

		if not valid_password(self.password):
			params['error_password'] = "Password not valid."
			input_error = True

		if not self.password == self.pass_conf:
			params['error_password'] = "Passwords do not match."
			input_error = True

		if input_error:
			self.render("register.html",**params)
		else:
			self.done()

	def done(self):
		#make sure the user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('register.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/welcome')

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


class MainPage(BaseHandler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		self.render("index.html")

class LoginPage(BaseHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'Invalid username / password combination.'
			self.render('login.html', error = msg)

class LogoutHandler(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class WelcomePage(BaseHandler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		if self.user:
			self.render("welcome.html", username = self.user.name)
		else:
			self.redirect('/register')

class MenuMaker(BaseHandler):
	def make_menu():
		self.menu_items ={'Home':'/'}
		if self.user.name:
			menu_items['Post'] = '/post'
			menu_items['Logout'] = '/logout'
		else:
			menu_items['Register'] = '/register'
			menu_items['login'] = '/login'

		return eslf.menu_items


app = webapp2.WSGIApplication([
	('/', MainPage),
	('/register', RegisterPage),
	('/login', LoginPage),
	('/logout', LogoutHandler),
	('/welcome', WelcomePage)
], debug=True)
