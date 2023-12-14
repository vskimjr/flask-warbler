import os
import pdb
from dotenv import load_dotenv

from flask import Flask, render_template, request, flash, redirect, session, g, url_for
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_

from forms import UserAddForm, LoginForm, MessageForm, UpdateProfileForm, CSRFProtectForm
from models import db, connect_db, User, Message, DEFAULT_IMAGE_URL, DEFAULT_HEADER_IMAGE_URL

load_dotenv()

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
toolbar = DebugToolbarExtension(app)

connect_db(app)


##############################################################################
# User signup/login/logout


@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None


@app.before_request
def add_csrf_protect_to_g():
    """Add CSRF protection to global environment"""

    g.csrf_protection = CSRFProtectForm()


def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Log out user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """

    do_logout()

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg,
            )
            db.session.commit()

        except IntegrityError:
            flash("Username already taken", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect(url_for("homepage"))

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login and redirect to homepage on success."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(
            form.username.data,
            form.password.data,
        )

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect(url_for("homepage"))

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.post('/logout')
def logout():
    """Handle logout of user and redirect to homepage."""

    form = g.csrf_protection
    # TODO: check to see if g.user exists
    if form.validate_on_submit():
        do_logout()

        flash("Successfully logged out", "success")
        return redirect(url_for("login"))

    flash("Access unauthorized.", "danger")
    return redirect(url_for("homepage"))

##############################################################################
# General user routes:


@app.get('/users')
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)


@app.get('/users/<int:user_id>')
def show_user(user_id):
    """Show user profile."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    user = User.query.get_or_404(user_id)

    return render_template('users/show.html', user=user)


@app.get('/users/<int:user_id>/following')
def show_following(user_id):
    """Show list of people this user is following."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    user = User.query.get_or_404(user_id)
    return render_template('users/following.html', user=user)


@app.get('/users/<int:user_id>/followers')
def show_followers(user_id):
    """Show list of followers of this user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    user = User.query.get_or_404(user_id)
    return render_template('users/followers.html', user=user)


@app.post('/users/follow/<int:follow_id>')
def start_following(follow_id):
    """Add a follow for the currently-logged-in user.

    Redirect to following page for the current for the current user.
    """
    form = g.csrf_protection

    if not g.user or not form.validate_on_submit():
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.append(followed_user)

    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.post('/users/stop-following/<int:follow_id>')
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user.

    Redirect to following page for the current for the current user.
    """

    form = g.csrf_protection
    # breakpoint()
    if not form.validate_on_submit() or not g.user:
        print("g.user=", g.user)
        # breakpoint()
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.remove(followed_user)
    # breakpoint()
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/profile', methods=["GET", "POST"])
def update_profile():
    """Update profile for current user."""
    # TODO: follow docstring pattern of other routes and include where it redirects

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))
        # TODO: be consistent with the existing codebase

    user = g.user

    form = UpdateProfileForm(obj=user)

    if form.validate_on_submit():
        if User.authenticate(user.username, form.password.data):
            user.username = form.username.data
            user.email = form.email.data
            user.image_url = form.image_url.data or DEFAULT_IMAGE_URL
            user.header_image_url = form.header_image_url.data or DEFAULT_HEADER_IMAGE_URL
            user.bio = form.bio.data
            user.location = form.location.data

            db.session.commit()
            return redirect(f"/users/{user.id}")

        flash("Incorrect Password", "danger")

        # edit the user profile

    return render_template("/users/edit.html", form=form, user_id=user.id)


@app.post('/users/delete')
def delete_user():
    """Delete user.

    Redirect to signup page.
    """

    form = g.csrf_protection

    if not form.validate_on_submit or not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    do_logout()

    Message.query.filter_by(user_id=g.user.id).delete()

    # TODO: Ask why db.session.delete(user.messages) does not work
    # UnmappedInstanceError: Class 'sqlalchemy.orm.collections.InstrumentedList' is not mapped

    db.session.delete(g.user)
    db.session.commit()

    return redirect(url_for("homepage"))


##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["GET", "POST"])
def add_message():
    """Add a message:

    Show form if GET. If valid, update message and redirect to user page.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    form = MessageForm()

    if form.validate_on_submit():
        msg = Message(text=form.text.data)
        g.user.messages.append(msg)
        db.session.commit()

        return redirect(f"/users/{g.user.id}")

    return render_template('messages/create.html', form=form)


@app.get('/messages/<int:message_id>')
def show_message(message_id):
    """Show a message."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    msg = Message.query.get_or_404(message_id)
    return render_template('messages/show.html', message=msg)


@app.post('/messages/<int:message_id>/delete')
def delete_message(message_id):
    """Delete a message.

    Check that this message was written by the current user.
    Redirect to user page on success.
    """

    form = g.csrf_protection
    if not form.validate_on_submit() or not g.user:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    msg = Message.query.get_or_404(message_id)

    if msg.user_id != g.user.id:
        flash("Access unauthorized.", "danger")
        return redirect(url_for("homepage"))

    db.session.delete(msg)
    db.session.commit()

    return redirect(f"/users/{g.user.id}")


##############################################################################
# Homepage and error pages


@app.get('/')
def homepage():
    """Show homepage:

    - anon users: no messages
    - logged in: 100 most recent messages of self & followed_users
    """
    # TODO: make this cleaner. Alt way of doing this is to grab ids from following ...
    if g.user:

        following_ids = [
            follower.id for follower in g.user.following] + [g.user.id]

        messages = (Message
                    .query
                    .filter(Message.user_id.in_(following_ids))
                    .order_by(Message.timestamp.desc())
                    .limit(100)
                    .all()
                    )

        return render_template('home.html', messages=messages)

    else:
        return render_template('home-anon.html')


@app.after_request
def add_header(response):
    """Add non-caching headers on every request."""

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
    response.cache_control.no_store = True
    return response
