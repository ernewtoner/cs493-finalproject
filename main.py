from google.cloud import datastore
from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from flask import request
from authlib.flask.client import OAuth
from six.moves.urllib.parse import urlencode

import constants
import uuid

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app_url = 'https://newtoner-cs493-final-project.appspot.com'
app.secret_key = str(uuid.uuid4())
app.debug = True
client = datastore.Client()

@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated

# Controllers API
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/callback')
def callback_handling():
    #auth0.authorize_access_token()
    id_token = auth0.authorize_access_token()['id_token']
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    session['id_token'] = id_token
    return redirect('/dashboard')

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)

@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4),
                           id_token=session['id_token'])
    
@app.route('/users', methods=['POST','GET'])
def users_get_post():
    if request.method == 'POST':
        content = request.get_json()

        # If any required fields are missing respond with error message and 400 Bad Request
        if content.get("name") == None or content.get("email") == None: #or content.get("password") == None:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)

        jwt_header = request.headers.get('Authorization')
        #if jwt_header == None:
        # have to be authorized to create user?

        ###### Get all users in order to check if user has already been created
        user_created = False
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        for e in results:
            # Search for user
            if jwt_header == e["jwt"]:
                user_created = True # Don't create new user
                #user_name = e["owner"]
        
        if not user_created:
            new_user = datastore.entity.Entity(key=client.key(constants.users))
            new_user.update({"name": content["name"], "email": content["email"],
                            "jwt": jwt_header})
            client.put(new_user)
            return (json.dumps({
                "id": new_user.id, 
                "name": new_user["name"], 
                "email": new_user["email"],
                "password": new_user["password"],
                "self": app_url + "/users/" + str(new_user.id)}), 201)
        else:
            return (json.dumps({"Error": "The specified user already exists"}), 400)

    elif request.method == 'GET': # Get all users
        query = client.query(kind=constants.users)
    
        # Pagination
        q_limit = int(request.args.get('limit', '3'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"users": results}
        if next_url:
            output["next"] = next_url
        return (json.dumps(output), 200)
    else:
        return 'Method not recognized'

##### Boats API

# Additionally for this project, you need a relationship between the User entity 
# and a non-user entity. If you were to enhance Assignment 4 so that a boat is 
# owned by a user, then there would be a relationship between the User and Boat entities. 
# This meets the requirement of User entity being related to at least one of the non-user entities.

@app.route('/boats', methods=['POST','GET'])
def boats_get_post():
    if request.method == 'POST':
        content = request.get_json()

        # If any required fields are missing respond with error message and 400 Bad Request
        if content.get("name") == None or content.get("type") == None or content.get("length") == None or content.get("loads") == None:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)
        
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
          "length": content["length"], "loads": content["loads"]})
        client.put(new_boat)
        return (json.dumps({
            "id": new_boat.id, 
            "name": new_boat["name"], 
            "type": new_boat["type"],
            "length": new_boat["length"],
            "loads": new_boat["loads"],
            "self": app_url + "/boats/" + str(new_boat.id)}), 201)        
    elif request.method == 'GET': # Get all boats
        query = client.query(kind=constants.boats)
    
        # Pagination
        q_limit = int(request.args.get('limit', '3'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"boats": results}
        if next_url:
            output["next"] = next_url
        return (json.dumps(output), 200)
    else:
        return 'Method not recognized'

@app.route('/boats/<id>', methods=['DELETE', 'GET'])
def boats_put_delete_get(id):
    if request.method == 'GET': # Get specific boat
        #content = request.get_json()
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)

        # 404 Not Found if invalid boat ID
        if boat == None:
            return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)

        return json.dumps({
            "id": boat_key.id, 
            "name": boat["name"], 
            "type": boat["type"],
            "length": boat["length"],
            "loads": boat["loads"],
            "self": app_url + "/boats/" + str(boat_key.id)})
    elif request.method == 'DELETE': # Delete specific boat
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)

        # 404 Not Found if invalid boat ID
        if boat == None:
            return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)

        client.delete(boat_key)
        return ('',204)
    else:
        return 'Method not recognized'

@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():
    if request.method == 'POST':
        content = request.get_json()
        
        # 400 Bad Request if the required field is missing
        if content.get("weight") == None or content.get("carrier") == None or content.get("content") == None or content.get("delivery_date") == None:
            return (json.dumps({"Error": "The request object is missing a required field"}), 400)
        
        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update({"weight": content["weight"], "carrier": content["carrier"], 
        "content": content["content"], "delivery_date": content["delivery_date"]})
        client.put(new_load)
        return (json.dumps({
            "id": new_load.id, 
            "weight": new_load["weight"],
            "carrier": new_load["carrier"],
            "content": new_load["content"],
            "delivery_date": new_load["delivery_date"],
            "self": app_url + "/loads/" + str(new_load.id)}), 201)
    elif request.method == 'GET': # Get all loads
        query = client.query(kind=constants.loads)

        # Pagination
        q_limit = int(request.args.get('limit', '3'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        return (json.dumps(output), 200)    
    else:
        return 'Method not recognized'

@app.route('/loads/<id>', methods=['DELETE', 'GET'])
def loads_put_delete_get(id):
    # Get load from datastore
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)

    # 404 Not Found for GET or DELETE if load does not exist 
    if load == None:
        return (json.dumps({"Error": "No load with this load_id exists"}), 404)

    if request.method == 'GET':
        return (json.dumps({
            "id": load.id,
            "weight": load["weight"],
            "carrier": load["carrier"],
            "content": load["content"],
            "delivery_date": load["delivery_date"],
            "self": app_url + "/loads/" + str(load_key.id)}), 200)
    elif request.method == 'DELETE':
        # Get all boats
        query = client.query(kind=constants.boats)
        results = list(query.fetch())

        # Check if the load is in any boat, remove from boat if so
        for e in results:
            for i, l in enumerate(e["loads"]):
                if l.get("id") == load.id:
                    e["loads"].pop(i)
                    client.put(e)

        # Remove the load from datastore
        client.delete(load_key)
        return ("", 204)

# Get all loads on a boat
@app.route('/boats/<boat_id>/loads', methods=['GET'])
def get_boat_loads(boat_id):
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)

    if request.method == 'GET':
        print(boat["loads"])
        return (json.dumps({
            "loads": boat["loads"],
            "self": app_url + "/boats/" + str(boat_key.id) + "/loads"}), 200)

# For putting a load into boats you can use a route like /boats/:boat_id/loads/:load_id 
# and the same thing when removing a load but with a different HTTP Verb.
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def loads_put_delete_boat(load_id, boat_id):
    # Get load and boat from datastore
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)

    if request.method == 'PUT':
        # 404 Not Found if invalid load or boat ID
        if load == None or boat == None:
            return (json.dumps({"Error": "The specified boat and/or load don't exist"}), 404)

        # Get all boats
        query = client.query(kind=constants.boats)
        results = list(query.fetch())

        # Check that the load does not already exist in any boat
        for e in results: # Each boat entity
            #print(e)
            for l in e["loads"]: # Each load that boat carries
                #print(l)
                if l.get("id") == load.id:
                    return (json.dumps({"Error": "The specified load already exists in a boat"}), 403)

        boat["loads"].append({
            "id": load.id,
            "self": app_url + "/boats/" + boat_id + "/loads/" + str(load.id)})
        client.put(boat)
        return ("", 204)
    elif request.method == 'DELETE':  # Delete load from boat, not load itself
        # 404 Not Found if invalid load or boat ID or the specified boat isn't at the load
        if load == None or boat == None:
            return (json.dumps({"Error": "The specified boat and/or load don't exist"}), 404)

        # Check for the load in the boat
        for i, l in enumerate(boat["loads"]):
            if load.id == l.get("id"):
                 print("HERE")

                 boat["loads"].pop(i) # Remove if so and update datastore
                 client.put(boat)
                 return ('',204)

        # If the load wasn't found in the boat, return 403
        return (json.dumps({"Error": "That load is not in the specified boat"}), 403)
        
# You must provide a REST API endpoint so that a user can see all the instances 
# of the non-user entity that were created by them.

# @app.route('/users/<user_id>/boats', methods=['GET', 'DELETE'])
# def loads_put_delete_boat(load_id, boat_id):



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 3000))
