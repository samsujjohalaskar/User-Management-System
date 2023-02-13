import datetime
from flask import Flask ,request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import hashlib
import gladiator as gl
from flask_marshmallow import Marshmallow

app = Flask(__name__)

# database connection
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:mypassword@localhost:5432/mydb"

db = SQLAlchemy(app)
ma = Marshmallow(app)

migrate = Migrate(app, db)
print ("Opened database successfully")

#database creation
class UserModel(db.Model):
    __tablename__ = 'users'
    __table_args__ = (
        db.UniqueConstraint('username', 'email'),
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(),unique = True, nullable = False)
    password = db.Column(db.String(),nullable = False)
    email = db.Column(db.String(),unique = True,nullable = False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def __init__(self,username,password,email):
        self.username = username
        self.password = password 
        self.email = email
        
    def __repr__(self) :
        return f"{self.id} : {self.username}" 

#Marshmallow implementation.
class UserModelSchema(ma.Schema):
    class Meta:
        fields = ("id","username","email","created_at")   #"password" excluded as instructed.

usermodel_schema = UserModelSchema()
usermodels_schema = UserModelSchema(many=True)

# to create the database. Below two lines need to run once.
# with app.app_context():
#     db.create_all() 
      
#validating and hashing the password   
    #First we have to validate the password. Because:
    #If the password is empty at time of creating and updating a user that would still generate a hash value with the help of 'salt'.
    #And later the dummy hash value could easily pass the validation process.
def passwordHashing(password_plain): 
    valid_data = {
        'password_plain':password_plain
    }
    field_validations = (
        ('password_plain',gl.required,gl.length_min(5)) #Field validation with the help of gladiator. If any field is empty then it'll be throwing error.
    )
    validate_password = gl.validate(field_validations,valid_data)
    #validation complete.

    #password hashing
    if bool(validate_password) :   
        salt = "5gz"
        db_password = password_plain+salt
        password_hash = hashlib.md5(db_password.encode())   
        password_hash_string = password_hash.hexdigest()

        return password_hash_string

def validateUserInfo(username,email):
        valid_data = {
            'username':username,
            'email':email
        }
        field_validations = (
            ('username',gl.required,gl.length_min(5)),
            ('email',gl.required,gl.length_min(5))
        )
        validate_new_user = gl.validate(field_validations,valid_data)   

        return bool(validate_new_user)

@app.route('/users', methods = ['POST'])
def create():
    if (request.method == 'POST'):
        if request.is_json:
            data = request.get_json()
            raw_password=data['password']
            username=data['username']
            email=data['email']

            hashed_password = passwordHashing(raw_password)     #hash function calling

            if validateUserInfo(username,email):
                new_user = UserModel(username=username, password=hashed_password, email=email)
            
                db.session.add(new_user)
                db.session.commit()
                return {"MESSAGE": f"User {username} has been created successfully."}  
              
            return ("ERROR: Please enter valid data.")
        
        return ("ERROR: Please insert JSON formated payload.")

@app.route('/users', methods = ['GET'])
def read():     
    if (request.method == 'GET'):
            users = UserModel.query.all()
            return usermodels_schema.dump(users)

@app.route('/users/<id>', methods=['GET'])
def readWithID(id):    

    if request.method == 'GET':
        user = UserModel.query.get_or_404(id)
        return usermodel_schema.dump(user)
    
@app.route('/users/<id>', methods=['PUT'])
def update(id):

    if request.method == 'PUT':
        user = UserModel.query.get_or_404(id)
        data = request.get_json()
        user.username = data['username']
        user.password = data['password']
        user.email = data['email']

        hashed_password = passwordHashing(user.password)
        user.password = hashed_password   #updatd the password with it's hash value
        if validateUserInfo(user.username,user.email):
            db.session.add(user)
            db.session.commit()
            return {"MESSAGE": f"User {user.username} updated successfully."}
            
        return ("ERROR: Please enter valid data.")

@app.route('/users/<id>', methods=['DELETE'])
def delete(id):

    if request.method == 'DELETE':
        user = UserModel.query.get_or_404(id)
        db.session.delete(user)
        db.session.commit()
        return {"MESSAGE": f"User {user.username} deleted successfully."}

if __name__ == "__main__":
    app.run(debug=True)