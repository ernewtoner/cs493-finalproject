# cs493-finalproject
RESTful API using Python 3, Flask, and Google Cloud Platform

## API/Assignment Description

This API is modeled after Assignment 4, consisting of Boats, Loads, and Users entities. Like assignment 4, Loads can be placed in Boats, unlike assignment 4 each Boat has an owner that corresponds to a User. Only the User that owns the boat can modify that Boat or put a Load into it. The correct JWT token is needed for modifying protected resources.
  
User creation is handled by Auth0 so the unique identifier I have used for users is the auth0_id used in account creation. In order to authorize, you must go through the account creation URL then set the owner_auth0_id variable in Postman to the “sub” field displayed when creating an account or logging in with Auth0, example: auth0|5deaedd3146c770d1edeef57.  You can also access this field by getting /users in the API.
  
This application maps the JWT provided by Auth0 to the user by storing it along with the auth0_id in the User entity. When a user creates an account a corresponding User entity is created. During authentication if the JWT has changed, it is updated in the User entity. In this way the JWT should always be up to date with Auth0 for authorizing the user.
  
The User entity is related to Boats by the “owner” field of a Boat, the “owner” corresponds to an auth0_id that uniquely identifies that user.
