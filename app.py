from flask import Flask, request, jsonify
from models.user import User
from database import db
import bcrypt
from flask_login import LoginManager, login_user, current_user,logout_user, login_required


app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # conversão pra int evita warning

@app.route('/login', methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    if username and password:
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            return jsonify({"message": "Logado com Sucesso"})
    
    return jsonify({"message": "Credenciais inválidas"}), 400


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message":"Logout realizado com sucesso"})


@app.route('/user', methods=["POST"])
@login_required
def create_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password),bcrypt.gensalt())
        
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        
        return jsonify({"message": "cadastro com Sucesso"})
    
    return jsonify({"message": "Dados Invalidos"}) ,401

@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)
    
    if user:
            return {"username": user.username}
    
    return jsonify({"message": "Nenhum usuario encontrado"}),404


from flask_login import login_required

@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.get_json()
    user = User.query.get(id_user)

    if id_user != current_user and current_user.role == "user":
        return jsonify({"message":"Operação não permitida"})
    
    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message": f"Usuário {user.id} atualizado"}), 200

    return jsonify({"message": "Nenhum usuário encontrado"}), 404

@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def delete_user(id_user):
    
    user = User.query.get(id_user)
    
    if current_user.role != "admin":
        return jsonify({"message":"Operação não permitida"}),403
    
    if id_user == current_user.id:
        return jsonify({"message": "Deleção não permitida"}), 403

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "Usuário deletado"}), 200

    return jsonify({"message": "Nenhum usuário encontrado"}), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
