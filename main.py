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
from flask import make_response
from authlib.integrations.flask_client import OAuth
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

##### Auth routes
@app.route('/callback')
def callback_handling():
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

    ###### Get all users in order to check if user has already been created
    user_created = False
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    for e in results:
        # Search for user
        if userinfo['sub'] == e['auth0_id']:
            user_created = True # Don't create new user
            # But if their JWT has changed update it
            if id_token != e['jwt']:
                e['jwt'] = id_token
                client.put(e)

    if not user_created:
        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({"auth0_id": userinfo['sub'], "nickname": userinfo['nickname'],
                        "email": userinfo['email'], "jwt": id_token})
        client.put(new_user)

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

##### User routes
@app.route('/users', methods=['GET'])
def users_get():
    # If client request does not include JSON, return error
    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps({"Error": "Specified content type not supported"}), 406)

    if request.method == 'GET': # Get all users
        query = client.query(kind=constants.users)
    
        # Pagination
        q_limit = int(request.args.get('limit', '5'))
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

@app.route('/users/<id>/boats', methods=['GET'])
def user_get_boats(id):
    if request.method == 'GET':
        ###### Get all boats for specified user
        query = client.query(kind=constants.boats)
        query.add_filter('owner', '=', id)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
        return (json.dumps(results), 200)
    else:
        return 'Method not recognized'

##### Boats and Loads API

# Verify the provided JWT header matches the specified owner of the boat
def verify_jwt_header(user):
    '''
    This function checks to see if the token exists and matches the specified user/boat owner.

    @param user  the authenticated user
    @return None if no error, json with a return code if authentication was not successful
    '''
    # Make sure the authorization header exists
    jwt_header = request.headers.get('Authorization')
    if jwt_header == None:
        return (json.dumps({"Error": "You must be an authorized user to create or modify a boat"}), 401)

    # Check for the 'Bearer' prefix
    jwt_strings = jwt_header.split()
    jwt_prefix = jwt_strings[0]
    jwt_header_token = jwt_strings[1]

    if jwt_prefix != 'Bearer':
        return (json.dumps({"Error": "You must pass a Bearer token to authenticate"}), 401)
 
    # Get the user specified as owner of the boat and verify that their JWT matches the authorization header
    query = client.query(kind=constants.users)
    query.add_filter('auth0_id', '=', user)
    results = list(query.fetch())

    # Should only have 1 user result but just in case
    for e in results:
        if e["jwt"] != jwt_header_token:
            return (json.dumps({"Error": "You are not authorized to create or modify a boat owned by that user"}), 401)

    # Return None if successful
    return None

@app.route('/boats', methods=['POST','GET', 'PUT', 'DELETE'])
def boats_get_post_put_delete():
    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps({"Error": "Specified content type not supported"}), 406)

    if request.method == 'POST':
        content = request.get_json()

        # If any required fields are missing respond with error message and 400 Bad Request
        if content.get("name") == None or content.get("type") == None or content.get("length") == None or content.get("loads") == None or content.get("owner") == None:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)
        
        # Verify the provided JWT header matches the specified owner of the boat
        auth_error = verify_jwt_header(content["owner"])
        if auth_error:
            return auth_error

        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
          "length": content["length"], "loads": content["loads"], "owner": content["owner"]})
        client.put(new_boat)
        return (json.dumps({
            "id": new_boat.id, 
            "name": new_boat["name"], 
            "type": new_boat["type"],
            "length": new_boat["length"],
            "loads": new_boat["loads"],
            "owner": new_boat["owner"],
            "self": app_url + "/boats/" + str(new_boat.id)}), 201)        
    elif request.method == 'GET': # Get all boats
        query = client.query(kind=constants.boats)
    
        # Pagination
        q_limit = int(request.args.get('limit', '5'))
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
    elif request.method == 'PUT': # Unsupported edit all boats - 405
        return (json.dumps({"Error": "This API doesn't allow you to edit all boats!"}), 405) 
    elif request.method == 'DELETE': # Unsupported delete all boats - 405
        return (json.dumps({"Error": "This API doesn't allow you to delete all boats!"}), 405) 
    else:
        return 'Method not recognized'

@app.route('/boats/<id>', methods=['PATCH','PUT', 'DELETE', 'GET'])
def boats_patch_put_delete_get(id):
    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps({"Error": "Specified content type not supported"}), 406)

    if request.method == 'GET': # Get specific boat
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
            "owner": boat["owner"],
            "self": app_url + "/boats/" + str(boat_key.id)})
    elif request.method == 'DELETE': # Delete specific boat
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)

        # 404 Not Found if invalid boat ID
        if boat == None:
            return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)

        # Verify the provided JWT header matches the specified owner of the boat
        auth_error = verify_jwt_header(boat["owner"])
        if auth_error:
            return auth_error

        client.delete(boat_key)
        return ('',204)
    elif request.method == 'PATCH': # Allows updating any subset of attributes while the other attributes remain unchanged. 
        content = request.get_json()
        request_name = content.get("name")
        request_type = content.get("type")
        request_length = content.get("length")
        request_loads = content.get("loads")
        request_owner = content.get("owner")

         # 400 Bad Request if all fields are missing
        if request_name == None and request_type == None and request_length == None and request_loads == None and request_owner == None:
            return (json.dumps({"Error": "The request object has no valid attributes"}), 400)

        # Attempt to get the boat from the datastore
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key) 

        # 404 Not Found if invalid boat ID
        if boat == None:
            return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)

        # If owner specified verify the provided JWT header matches the owner
        if request_owner:
            auth_error = verify_jwt_header(content["owner"])
        else:
            auth_error = verify_jwt_header(boat["owner"])
        
        if auth_error:
            return auth_error

        # If the request updates the boat name, check if the name already exists 
        # and is not just the same as the specified boat's name
        new_boat_name = content.get("name") 
        if new_boat_name and new_boat_name != boat["name"]:
            # Get all boats in order to check if new boat name is unique
            query = client.query(kind=constants.boats)
            results = list(query.fetch())
            for e in results:
                if e["name"] == new_boat_name:
                    return (json.dumps({"Error": "That boat name already exists!"}), 403) # Return 403 if not unique
        
        # Update the datastore according to the fields entered
        if request_name:
            boat.update({"name": content["name"]})

        if request_type:
            boat.update({"type": content["type"]})

        if request_length:
            boat.update({"length": content["length"]})

        if request_loads:
            boat.update({"loads": content["loads"]})

        if request_owner:
            boat.update({"owner": content["owner"]})

        client.put(boat)

        return (json.dumps({
            "id": boat.id, 
            "name": boat["name"], 
            "type": boat["type"],
            "length": boat["length"],
            "loads": boat["loads"],
            "owner": boat["owner"],
            "self": app_url + "/boats/" + str(boat.id)}), 200)
    elif request.method == 'PUT':
        content = request.get_json()
        request_name = content.get("name")
        request_type = content.get("type")
        request_length = content.get("length")
        request_loads = content.get("loads")
        request_owner = content.get("owner")

        # 400 Bad Request if any required fields are missing
        if request_name == None or request_type == None or request_length == None or request_loads == None or request_owner == None:
            return (json.dumps({"Error": "The request object does not have all required attributes"}), 400)

        # Attempt to get the boat from the datastore
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)

        # 404 Not Found if invalid boat ID
        if boat == None:
            return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)

        # Verify the provided JWT header matches the specified owner of the boat
        auth_error = verify_jwt_header(content["owner"])
        if auth_error:
            return auth_error

        # Check if the name they're requesting already exists and is not the specified boat's name
        new_boat_name = content.get("name")

        if new_boat_name != boat["name"]:
            # Get all boats in order to check if new boat name is unique
            query = client.query(kind=constants.boats)
            results = list(query.fetch())
            for e in results:
                if e["name"] == new_boat_name:
                    return (json.dumps({"Error": "That boat name already exists!"}), 403) # Return 403 if not unique
            
        # Update the datastore
        boat.update({"name": content["name"], "type": content["type"],
          "length": content["length"], "loads": content["loads"], "owner": content["owner"]})
        client.put(boat)

        # Set header with location of boat
        boat_url = app_url + "/boats/" + str(boat.id)

        # Make JSON response
        res = make_response(json.dumps({
            "id": boat.id, 
            "name": boat["name"], 
            "type": boat["type"],
            "length": boat["length"],
            "loads": boat["loads"],
            "owner": boat["owner"],
            "self": boat_url}))
            
        res.mimetype = 'application/json'
        res.status_code = 303

        return res
    else:
        return 'Method not recognized'

@app.route('/loads', methods=['POST', 'GET', 'PUT', 'DELETE'])
def loads_get_post_put_delete():
    # If client request does not include JSON, return error
    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps({"Error": "Specified content type not supported"}), 406)

    if request.method == 'POST':
        content = request.get_json()
        
        # 400 Bad Request if the required field is missing
        if content.get("weight") == None or content.get("content") == None or content.get("delivery_date") == None:
            return (json.dumps({"Error": "The request object is missing a required field"}), 400)
        
        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update({"weight": content["weight"], "content": content["content"], 
                        "delivery_date": content["delivery_date"]})
        client.put(new_load)
        return (json.dumps({
            "id": new_load.id, 
            "weight": new_load["weight"],
            "content": new_load["content"],
            "delivery_date": new_load["delivery_date"],
            "self": app_url + "/loads/" + str(new_load.id)}), 201)
    elif request.method == 'GET': # Get all loads
        query = client.query(kind=constants.loads)

        # Pagination
        q_limit = int(request.args.get('limit', '5'))
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
    elif request.method == 'PUT': # Unsupported edit all boats - 405
        return (json.dumps({"Error": "This API doesn't allow you to edit all loads!"}), 405) 
    elif request.method == 'DELETE': # Unsupported delete all boats - 405
        return (json.dumps({"Error": "This API doesn't allow you to delete all loads!"}), 405)
    else:
        return 'Method not recognized'

@app.route('/loads/<id>', methods=['DELETE', 'GET', 'PUT', 'PATCH'])
def load_put_patch_delete_get(id):
    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps({"Error": "Specified content type not supported"}), 406)

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
                    auth_error = verify_jwt_header(e["owner"])
                    if auth_error:
                        return auth_error
                    e["loads"].pop(i)
                    client.put(e)

        # Remove the load from datastore
        client.delete(load_key)
        return ("", 204)
    elif request.method == 'PATCH': # Allows updating any subset of attributes while the other attributes remain unchanged. 
        content = request.get_json()
        request_weight = content.get("weight")
        request_content = content.get("content")
        request_delivery_date = content.get("delivery_date")

         # 400 Bad Request if all fields are missing
        if request_weight == None and request_content == None and request_delivery_date == None:
            return (json.dumps({"Error": "The request object has no valid attributes"}), 400)

        # Attempt to get the load from the datastore
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key) 

        # 404 Not Found if invalid load ID
        if load == None:
            return (json.dumps({"Error": "No load with this load_id exists"}), 404)
        
        # Update the datastore according to the fields entered
        if request_weight:
            load.update({"weight": content["weight"]})

        if request_content:
            load.update({"content": content["content"]})

        if request_delivery_date:
            load.update({"delivery_date": content["delivery_date"]})

        client.put(load)

        return (json.dumps({
            "id": load.id, 
            "weight": load["weight"],
            "content": load["content"],
            "delivery_date": load["delivery_date"],
            "self": app_url + "/loads/" + str(load.id)}), 200)
    elif request.method == 'PUT':
        content = request.get_json()
        request_weight = content.get("weight")
        request_content = content.get("content")
        request_delivery_date = content.get("delivery_date")

         # 400 Bad Request if any fields are missing
        if request_weight == None or request_content == None or request_delivery_date == None:
            return (json.dumps({"Error": "The request object does not have all required attributes"}), 400)

        # Attempt to get the load from the datastore
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        # 404 Not Found if invalid load ID
        if load == None:
            return (json.dumps({"Error": "No load with this load_id exists"}), 404)
            
        # Update the datastore
        load.update({"weight": content["weight"], "content": content["content"], 
                     "delivery_date": content["delivery_date"]})
        client.put(load)

        load_url = app_url + "/loads/" + str(load.id)

        # Make JSON response
        res = make_response(json.dumps({
            "id": load.id, 
            "weight": load["weight"], 
            "content": load["content"],
            "delivery_date": load["delivery_date"],
            "self": load_url}))

        res.mimetype = 'application/json'
        res.status_code = 303

        return res
    else:
        return 'Method not recognized'

# Get all loads on a boat
@app.route('/boats/<boat_id>/loads', methods=['GET'])
def get_boat_loads(boat_id):
    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps({"Error": "Specified content type not supported"}), 406)

    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)

    if request.method == 'GET':
        return (json.dumps({
            "loads": boat["loads"],
            "self": app_url + "/boats/" + str(boat_key.id) + "/loads"}), 200)

# Putting a load into a specific boat
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def loads_put_delete_boat(load_id, boat_id):
    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps({"Error": "Specified content type not supported"}), 406)

    # Get load and boat from datastore
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)

    # 404 Not Found if invalid load or boat ID
    if load == None or boat == None:
        return (json.dumps({"Error": "The specified boat and/or load don't exist"}), 404)

    # Verify the provided JWT header matches the specified owner of the boat
    auth_error = verify_jwt_header(boat["owner"])
    if auth_error:
        return auth_error

    if request.method == 'PUT':
        # Get all boats
        query = client.query(kind=constants.boats)
        results = list(query.fetch())

        # Check that the load does not already exist in any boat
        for e in results: # Each boat entity
            for l in e["loads"]: # Each load that boat carries
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
                 boat["loads"].pop(i) # Remove if so and update datastore
                 client.put(boat)
                 return ('',204)

        # If the load wasn't found in the boat, return 403
        return (json.dumps({"Error": "That load is not in the specified boat"}), 403)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 3000))
