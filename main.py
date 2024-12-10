import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from msilib.schema import Environment

import psycopg2
import select
from Tools.scripts.make_ctype import method
from flask import Flask, render_template, request, make_response, redirect, jsonify
from jinja2 import FileSystemLoader
from sshtunnel import SSHTunnelForwarder

from ddbb import get_db_connection

from dotenv import load_dotenv
import os
import jwt

app = Flask(__name__)

conexion = None
tunnel = None

########################################################################################################################
########################################################################################################################

@app.route('/read_qr')
def read_qr():
    return render_template('read_qr.html')

@app.route('/qr_ok')
def qr_ok():
    return render_template('qr_ok.html')

@app.route('/qr_fail')
def qr_fail():
    return render_template('qr_fail.html')


@app.route('/qr-data', methods=['POST'])
def qr_data():
    if request.is_json:
        qr_content = request.json.get('qr_data')
        print("Contenido del QR:", qr_content)

        # Responder con JSON indicando éxito y redirigir en el cliente
        return jsonify({"message": "QR recibido", "content": "qr_fail"})

    else:
        return jsonify({"error": "No se recibió JSON válido"}), 400

########################################################################################################################
########################################################################################################################



# Función para generar token
def generate_token(userlogin):
    # Codifica el token JWT con el nombre de usuario y la clave secreta
    token = jwt.encode({'userlogin': userlogin}, os.getenv('SECRET_KEY'), algorithm='HS512')
    return token

# Función para verificar token
def verify_token(token, userlogin):
    try:
        # Verifica la firma del token JWT utilizando la clave secreta
        decoded_token = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=['HS512'])

        # Verificar si el nombre de usuario del token coincide con el usuario proporcionado
        if decoded_token['userlogin'] == userlogin:
            return True
    except jwt.ExpiredSignatureError:
        # Manejar el caso en que el token ha expirado
        return None
    except jwt.InvalidTokenError:
        # Manejar el caso en que el token es inválido
        return None


@app.route('/')

def home():
 return render_template('home.html')

@app.route('/form_login')  # Define la ruta para manejar solicitudes GET en '/form_login'
def login():
    # Renderiza la plantilla HTML llamada 'login_template.html' cuando se accede a la ruta '/form_login'
    return render_template('login_template.html')  # Devuelve la plantilla de login para que se muestre en el navegador

@app.route('/registrar')  # Define la ruta para manejar solicitudes GET en '/form_login'
def registrar():

    return render_template('registro.html')

@app.route('/register', methods=['POST'])
def register():
    # Obtener los datos del formulario
    nombre = request.form['nombre']
    email = request.form['email']
    passwd = request.form['passwd']
    telefono = request.form['telefono']
    direccion = request.form['direccion']

    try:
        # Obtener un cursor de la conexión
        cursor = conexion.cursor()


        cursor.callproc('registrar_usuario', (nombre, email, passwd, telefono, direccion))



        # Obtener el valor de retorno del procedimiento (booleano)
        result = cursor.fetchone()  # Debería devolver (True,) o (False,)
        cursor.connection.commit()
        if result and result[0]:
            print("Registro exitoso.")

            # Crear la respuesta
            return render_template('insertar_codigo.html')
        else:
            print("Registro incorrecto.")
            return render_template('registro.html')

    except Exception as e:
        print(f"Error al llamar al procedimiento almacenado: {e}")
        return 'Error registrarse.'

    finally:
        cursor.close()



@app.route('/sign_in', methods=['POST'])
def sign_in():
    # Obtener los datos del formulario
    login = request.form['login']
    passwd = request.form['passwd']

    try:
        # Obtener un cursor de la conexión
        cursor = conexion.cursor()

        # Llamar al procedimiento almacenado 'login_usuario'
        cursor.callproc('login_usuario', (login, passwd))

        # Obtener el valor de retorno del procedimiento (booleano)
        result = cursor.fetchone()  # Debería devolver (True,) o (False,)
        if result and result[0]:
            print("Login exitoso.")
            # Generar un token JWT utilizando el nombre de usuario
            token = generate_token(login)

            # Crear la respuesta
            response = make_response(redirect('/login_ok'))  # Redirigir a login_o

            # Establecer una cookie en la respuesta con el token JWT
            response.set_cookie('token', token)
            response.set_cookie('userlogin', login)

            # Devolver la respuesta con la cookie establecida
            return response

        else:
            print("Credenciales incorrectas.")
            return render_template('login_fail.html')

    except Exception as e:
        print(f"Error al llamar al procedimiento almacenado: {e}")
        return 'Error al verificar las credenciales.'

    finally:
        cursor.close()


@app.route('/login_ok')
def login_ok():
    # Obtener el token y el nombre de usuario desde las cookies de la solicitud
    token = request.cookies.get('token')         # Obtener el token JWT de la cookie
    userlogin = request.cookies.get('userlogin') # Obtener el nombre de usuario de la cookie

    # Verificar si el token o el nombre de usuario están ausentes
    if not token or not userlogin:
        # Si faltan el token o el nombre de usuario, renderizar una plantilla de error de token
        return render_template('token_fail.html')

    # Verificar la validez del token
    decoded_token = verify_token(token, userlogin)

    # Verificar si el token es válido
    if decoded_token:
        # Si el token es válido, renderizar la plantilla para la ruta protegida
        return render_template('login_ok_template.html')
    else:
        # Si el token no es válido, renderizar una plantilla de error de token
        return render_template('token_fail.html')


@app.route('/insertarCodigo', methods=['POST'])
def insertarCodigo():
    codigo = request.form['codigo']

    codigo = int(codigo.strip())


    try:
        # Obtener un cursor de la conexión
        cursor = conexion.cursor()

        # Llamar al procedimiento almacenado 'login_usuario'
        cursor.callproc('activar_registro', (codigo,))

        # Obtener el valor de retorno del procedimiento (booleano)
        result = cursor.fetchone()  # Debería devolver (True,) o (False,)
        cursor.connection.commit()
        if result and result[0]:
            print("Activacion exitosa.")

            # Crear la respuesta
            return render_template('login_template.html')
        else:
            print("Activacion incorrecta.")

    except Exception as e:
        print(f"Error al llamar al procedimiento almacenado: {e}")
        return 'Error al verificar las credenciales.'

    finally:
        cursor.close()


if __name__ == '__main__':
    conexion, tunnel = get_db_connection()
    # app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000, debug=True)
    app.run()
