import os
import sys
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS
import logging
from logging import FileHandler, Formatter

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
'''
db_drop_and_create_all()


''' # Set up logging
error_log = FileHandler('error.log')
error_log.setFormatter(Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
error_log.setLevel(logging.INFO)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(error_log)
 '''
## ROUTES [API documentation is in README.md]
@app.route('/drinks', methods=['GET'])
def get_drinks():
    drinks = Drink.query.order_by(Drink.id).all()

    return jsonify({
        'success': True,
        'drinks': [drink.short() for drink in drinks]
    })

@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drink_detail(jwt):
    all_drinks = [drink.long() for drink in Drink.query.all()]
    return jsonify({
        'success': True,
        'drinks': all_drinks
    })

@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def new_drink(jwt):
    drink_data = request.get_json()

    print(json.dumps(drink_data), file=sys.stderr)
    if "title" and "recipe" not in drink_data:
        abort(422)

    title = drink_data['title']
    recipe = json.dumps(drink_data['recipe'])

    new_drink = Drink(title=title, recipe=recipe)
    new_drink.insert()

    return jsonify({
        'success': True,
        'drinks': [new_drink.long()]
    })

@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def edit_drink(jwt, drink_id):
    drink = Drink.query.get(drink_id)
    new_drink_data = request.get_json()

    if drink is None:
        abort(404)
    
    if 'title' in new_drink_data:
        drink.title = new_drink_data['title']

    if 'recipe' in new_drink_data:
        drink.recipe = json.dumps(new_drink_data['recipe'])

    drink.update()

    return jsonify({
        'success': True,
        'drinks': [drink.long()]
    })

@app.route('/drinks/<int:drink_id>', methods=["DELETE"])
@requires_auth('delete:drinks')
def delete_drink(jwt, drink_id):
    drink = Drink.query.get(drink_id)

    if drink is None:
        abort(404)

    drink.delete()

    return jsonify({
        'success': True,
        'delete': drink.id
    })

## Error Handling
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False, 
        "error": 422,
        "message": "Data received is malformed."
    }), 422

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "Resource not found."
    }), 404

@app.errorhandler(401)
def unauthorized_action(error):
    return jsonify({
        "success": False,
        "error": 401,
        "message": "User unauthorized to perform this action."
    })

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": "Bad request."
    })

@app.errorhandler(AuthError)
def auth_error(error):
    response = jsonify(error.error)
    response.status_code = error.status_code

    return response