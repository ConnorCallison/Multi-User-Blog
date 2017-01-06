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
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "29ae45de319049aebb7f2c40dc27d83fc37d0a1d"

"""
-----------------------------------------------
    Base handler for following pages to use
-----------------------------------------------
"""


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class BaseHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

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
    User Authentication
-----------------------------------------------
"""


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return email and EMAIL_RE.match(email)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

"""
-----------------------------------------------
    Blog Items
-----------------------------------------------
"""


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    username = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    title = db.StringProperty(required=True)
    post_content = db.StringProperty(required=True, multiline=True)
    likes = db.IntegerProperty()

    likers = []

    def handleLikeClick(self, username):
        if username not in self.likers and username != self.username:
            self.likers.append(username)
        elif username in self.likers and username != self.username:
            self.likers.remove(username)
        self.likes = self.sumLikes(self.likers)
        self.put()

    def sumLikes(self, likers):
        num_likes = 0
        for i in likers:
            num_likes += 1
        return num_likes

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid, parent=blog_key())

    def render(self):
        posts = greetings = Post.all().order('-created')
        self.render('index.html', posts=posts)


class Comment(db.Model):
    username = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    comment_text = db.StringProperty(required=True, multiline=True)
    created = db.DateTimeProperty(auto_now_add=True)

"""
-----------------------------------------------
    Pages
-----------------------------------------------
"""


class MainPage(BaseHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.render("index.html", posts=Post.all().order('-created'))


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
            self.render('login.html', error=msg)


class RegisterPage(BaseHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.render("register.html")

    def post(self):
        input_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.pass_conf = self.request.get('pass-conf')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

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
            self.render("register.html", **params)
        else:
            self.done()

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('register.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class SubmitPostPage(BaseHandler):

    def get(self):
        if self.user:
            self.render("new-post.html")
            u = self.user
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')
            return None

        title = self.request.get('title')
        content = self.request.get('content')

        if title and content:
            p = Post(parent=blog_key(), title=title,
                     post_content=content, username=self.user.name)
            p.put()
            self.redirect('/view?post_id=%s' % str(p.key()))
        else:
            error = "Please fill in all fields."
            self.render(
                "new-post.html", title=title, content=content, error=error)


class PostPage(BaseHandler):

    def getComments(self, post_id):
        c = Comment.all()
        c.filter('post_id =', post_id)
        if c:
            return c

    def get(self):
        post_id = self.request.get('post_id')
        if post_id:
            self.render("blogpost.html", post=db.get(
                post_id), comments=self.getComments(post_id))

    def post(self):
        if not self.user:
            self.redirect('/login')
            return None

        post_id = self.request.get('post_id')
        post = db.get(post_id)
        action = self.request.get('action')

        def editPost(self):
            post = db.get(post_id)
            if str(post.username) == (self.user.name):
                post.title = self.request.get('edited-title')
                post.post_content = self.request.get('edited-content')
                post.put()
                self.render(
                    "blogpost.html", post=post,
                    comments=self.getComments(post_id))
            else:
                self.render(
                    "blogpost.html",
                    post=db.get(post_id),
                    comments=self.getComments(post_id),
                    error="You do not have permissino to edit this post.")

        def deletePost(self):
            post = db.get(post_id)
            if post:
                if str(post.username) == str(self.user.name):
                    post.delete()
                    for comment in self.getComments(post_id):
                        comment.delete()
                    self.render(
                        "index.html", message="Post Successfully Deleted")
                else:
                    self.render(
                        "blogpost.html",
                        post=db.get(post_id),
                        comments=self.getComments(post_id),
                        error="You do not have permission to delete this post.")

        def deleteComment(self):
            comment = db.get(self.request.get('comment_id'))
            if comment:
                if str(comment.username) == str(self.user.name):
                    comment.delete()
                    self.render("blogpost.html", post=db.get(
                        post_id), comments=self.getComments(post_id))
                else:
                    self.render(
                        "blogpost.html",
                        post=db.get(post_id),
                        comments=self.getComments(post_id),
                        error="You do not have permission to delete this comment.")

        def commentOnPost(self):
            username = self.user.name
            comment_text = self.request.get('comment_text')

            if username and post_id and comment_text:
                c = Comment(parent=blog_key(), username=username,
                            post_id=post_id, comment_text=comment_text)
                c.put()
                self.render("blogpost.html", post=db.get(
                    post_id), comments=self.getComments(post_id))
            else:
                error = "Please try again"
                self.render("blogpost.html", post=db.get(
                    post_id), comments=self.getComments(post_id), error=error)

        def editComment(self):
            comment = db.get(self.request.get('comment_id'))
            if str(comment.username) == (self.user.name):
                comment.comment_text = self.request.get('edited-comment-text')
                comment.put()
                self.render("blogpost.html", post=db.get(
                    post_id), comments=self.getComments(post_id))
            else:
                self.render(
                    "blogpost.html",
                    post=db.get(post_id),
                    comments=self.getComments(post_id),
                    error="You do not have permission to edit this commment.")

        if action:
            if action == 'edit-post':
                editPost(self)
            elif action == 'delete-post':
                deletePost(self)
            elif action == 'add-comment':
                commentOnPost(self)
            elif action == 'edit-comment':
                editComment(self)
            elif action == 'delete-comment':
                deleteComment(self)
            elif action == 'like-click':
                post.handleLikeClick(self.request.get('username'))
                self.render("blogpost.html", post=db.get(
                    post_id), comments=self.getComments(post_id))


class LogoutHandler(BaseHandler):

    def get(self):
        self.logout()
        self.redirect('/')


class WelcomePage(BaseHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        if self.user:
            self.render("welcome.html", username=self.user.name)
        else:
            self.redirect('/register')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/register', RegisterPage),
    ('/login', LoginPage),
    ('/logout', LogoutHandler),
    ('/post', SubmitPostPage),
    ('/view', PostPage),
    ('/welcome', WelcomePage)
], debug=True)
