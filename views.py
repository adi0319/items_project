import string
import random
import requests
from flask import make_response
import json
import httplib2
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from flask import session as login_session
from models import Base, Category, TechItem, User
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, asc
from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
app = Flask(__name__)

# load the client id to connect to Google API
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
    'web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///tech.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/category/')
def showCategories():
    """ Show all of the categories, public and private views """
    categories = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session:
        return render_template('publicCategories.html', categories=categories)
    else:
        return render_template('categories.html', categories=categories)


@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    """ Create a brand new category """
    # make sure the user is logged in before creating a new category
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    """ Edit an existing category """
    # make sure user is logged in before editing category
    if 'username' not in login_session:
        return redirect('/login')

    editedCategory = session.query(Category).filter_by(id=category_id).one()
    # user cannot edit this category
    if editedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
         to edit this category. Please create your own category in order to \
         edit.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
            return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=editedCategory)


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    """ Delete an existing category """
    # make sure the user is logged in before deleting a category
    if 'username' not in login_session:
        return redirect('/login')

    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    # user cannot delete this category
    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
         to delete this category. Please create your own category in order to \
          delete.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showCategories', category_id=category_id))
    else:
        return render_template(
            'deleteCategory.html', category=categoryToDelete)


@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/tech/')
def showCategory(category_id):
    """ Show category, public and private views """
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(TechItem).filter_by(category_id=category_id).all()

    if ('username' not in login_session
            or creator.id != login_session['user_id']):
        return render_template(
            'publicCategory.html',
            items=items, category=category, creator=creator)
    else:
        return render_template(
            'category.html', items=items, category=category, creator=creator)


@app.route('/category/<int:category_id>/tech/new/', methods=['GET', 'POST'])
def newTechItem(category_id):
    """ Create a new tech item to add to a category """
    # make sure the user is logged in before creating a new tech item
    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
         to add tech items to this category. Please create your own category \
         in order to add items.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        newTechItem = TechItem(
                               name=request.form['name'],
                               description=request.form['description'],
                               price=request.form['price'],
                               category_id=category_id,
                               user_id=login_session['user_id'])
        session.add(newTechItem)
        session.commit()
        flash('New Tech Item %s Successfully Created' % (newTechItem.name))
        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template('newTechItem.html', category_id=category_id)


@app.route('/category/<int:category_id>/tech/<int:tech_id>/edit/',
           methods=['GET', 'POST'])
def editTechItem(category_id, tech_id):
    """ Edit an existing tech item """
    # make sure user is logged in before editing a tech item
    if 'username' not in login_session:
        return redirect('/login')

    editedTechItem = session.query(TechItem).filter_by(id=tech_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
         to edit tech items to this category. Please create your own category \
         in order to edit items.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form['name']:
            editedTechItem.name = request.form['name']
        if request.form['description']:
            editedTechItem.description = request.form['description']
        if request.form['price']:
            editedTechItem.price = request.form['price']
        session.add(editedTechItem)
        session.commit()
        flash('Tech Item Successfully Edited')
        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template('editTechItem.html', category_id=category_id,
                               tech_id=tech_id, item=editedTechItem)


@app.route('/category/<int:category_id>/tech/<int:tech_id>/delete/',
           methods=['GET', 'POST'])
def deleteTechItem(category_id, tech_id):
    """ Delete an existing tech item """
    # make sure user is logged in before deleting a tech item
    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()
    techItemToDelete = session.query(TechItem).filter_by(id=tech_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
         to delete tech items to this category. Please create your own \
         category in order to delete items.');}</script><body \
         onload='myFunction()''>"

    if request.method == 'POST':
        session.delete(techItemToDelete)
        session.commit()
        flash('Tech Item Successfully Deleted')
        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template('deleteTechItem.html', item=techItemToDelete)


@app.route('/category/<int:category_id>/tech/JSON/')
def categoryTechItemsJSON(category_id):
    """ JSON API to view Category Information """
    category = session.query(Category).filter_by(id=category_id).one()
    techItems = session.query(TechItem).filter_by(
        category_id=category_id).all()
    return jsonify(categoryItems=[i.serialize for i in techItems])


@app.route('/category/<int:category_id>/tech/<int:tech_id>/JSON/')
def techItemJSON(category_id, tech_id):
    """ JSON API to view TechItem Information """
    techItem = session.query(TechItem).filter_by(
        id=tech_id, category_id=category_id).one()
    return jsonify(techItem=techItem.serialize)


@app.route('/category/JSON/')
def allCategoriesJSON():
    """ JSON API to view all categories """
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/login')
def showLogin():
    """ Login route, create anti-forgery state token """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # print 'The current session state is %s' % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ Connect to Google Sign-in """
    # ensure the token sent to the server matches the token sent to the client
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # get auth code
    code = request.data

    try:
        # upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        # specify this one time code flow that the server will be sending off
        oauth_flow.redirect_uri = 'postmessage'
        # exchange auth code for a credentials obj
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check that the access token is valid
    access_token = credentials.access_token
    # verify that this is a valid token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    # create a json get request with url and access token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # if there was an error in the access token info, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user ID doesn't match given ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token's client ID does not match app's"), 401)
        print "Token's client ID does not match app's"
        response.headers['Content-Type'] = 'application/json'
        return response

    # check to see if the user is already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # store the access token in the session for later use
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't create a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'

    output += '<img src="'
    output += login_session['picture']
    output += ' " style="width: 300px; height: 300px; border-radius: 150px;\
    -webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """ Signing out the current logged in user from Google """

    # get the curren logged in user
    access_token = login_session.get('access_token')

    # in case there is no user connected
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # attempt to sign out the user
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # Successfully signed out the user
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # did not sign out user
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """ Sign in using Facebook """

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    # exchange client token for long lived server-side token with GET
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=\
    fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # use the token to get the user info from the API
    userinfo_url = 'https://graph.facebook.com/v2.8/me'
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,\
    id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # the token must be stored in the login session in order to logout
    login_session['access_token'] = token

    # get the user's profile pic
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token\
    =%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data['data']['url']

    # see if the user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '</h1>'

    output += '<img src="'
    output += login_session['picture']
    output += ' " style="width: 300px; height: 300px;border-radius: 150px;\
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash('Now logged in as %s' % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """ Log user out of Facebook """
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/disconnect')
def disconnect():
    """ Disconnect based on provider """

    if 'provider' in login_session:
        print login_session['provider']
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


def createUser(login_session):
    """ Create new user in db """
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """ Get user info from db """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """ Get user id from db """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Error:
        return None


if __name__ == '__main__':
    app.secret_key = 'DEV_SECRET_KEY'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
