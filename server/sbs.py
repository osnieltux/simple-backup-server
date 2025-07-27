#!/usr/bin/env python3

import argparse
import ast
import getpass
import grp
import os
from configparser import ConfigParser
from datetime import datetime
from functools import wraps
from subprocess import PIPE, run

from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import generate_csrf
from passlib.hash import pbkdf2_sha256
from werkzeug.utils import secure_filename

# format backups -> dataBase_description_user_date.bak

CONFIG_FILE = "config.conf"
DEFAULT_MSSQL_DATA = ""

config = ConfigParser()
BACKUP_NAME = []
ID_BACKUP_NAME = 1
DEBUG = False
PORT = 5000

group_info = grp.getgrnam("mssql")
GID = group_info.gr_gid


def check_configs():
    global GID
    global config, DEFAULT_MSSQL_DATA

    try:
        config.read(CONFIG_FILE)
    except Exception as e:
        print(e)
        exit(1)

    if "users" not in config:
        config["users"] = {}
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    if "server" not in config:
        config["server"] = {}
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    # backup_path
    if "backup_path" not in config["server"]:
        config["server"]["backup_path"] = "/var/sbs/backups"
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    if config["server"]["backup_path"] == "":
        print("backup_path is empty")
        exit(2)
    else:
        if os.path.isfile(config["server"]["backup_path"]):
            print(f'{config["server"]["backup_path"]}: is a file, not a directory')
            exit(2)

        if not os.path.isdir(config["server"]["backup_path"]):

            try:
                os.makedirs(config["server"]["backup_path"])
                os.chown(config["server"]["backup_path"], -1, GID)
            except Exception as e:
                print(e)
                exit(2)
        else:
            if os.stat(config["server"]["backup_path"]).st_gid != GID:
                print(
                    f"ERROR: backup_path is not owned by group mssql: {config['server']['backup_path']}"
                )
                exit(2)

        try:
            # checking permissions
            os.makedirs(os.path.join(config["server"]["backup_path"], "test"))
            os.rmdir(os.path.join(config["server"]["backup_path"], "test"))
        except Exception as e:
            print(e)
            exit(2)

    # DEFAULT_MSSQL_DATA
    if "DEFAULT_MSSQL_DATA" not in config["server"]:
        config["server"]["DEFAULT_MSSQL_DATA"] = "/var/opt/mssql/data"
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    if config["server"]["DEFAULT_MSSQL_DATA"] == "":
        print("DEFAULT_MSSQL_DATA is empty")
        exit(2)
    else:
        if not os.path.isdir(config["server"]["DEFAULT_MSSQL_DATA"]):
            print(f'{config["server"]["DEFAULT_MSSQL_DATA"]}: is not a directory')
            exit(2)

    # sqlcmd_path
    if "sqlcmd_path" not in config["server"]:
        config["server"]["sqlcmd_path"] = "/opt/mssql-tools/bin/sqlcmd"
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    if config["server"]["sqlcmd_path"] == "":
        print("sqlcmd_path is empty")
        exit(2)
    else:
        if not os.path.isfile(config["server"]["sqlcmd_path"]):
            print(f'{config["server"]["sqlcmd_path"]}: is not a file')
            exit(2)

    # user
    if "user" not in config["server"]:
        config["server"]["user"] = "sa"
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    if config["server"]["user"] == "":
        print("user is empty")
        exit(2)

    # blacklist
    if "blacklist" not in config["server"]:
        config["server"]["blacklist"] = '["tempdb", "model", "master", "msdb"]'
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    # user_password
    if "user_password" not in config["server"]:
        config["server"]["user_password"] = ""
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    if config["server"]["user_password"] == "":
        print("user_password is empty")
        exit(2)


check_configs()

print("Configurations loaded", config["server"]["backup_path"])

parser = argparse.ArgumentParser(description="Manage users")
parser.add_argument("-c", metavar="User", help="Create a new")
parser.add_argument("-p", metavar="port", help="port")
args = parser.parse_args()

if args.c:
    new_username = str(args.c)

    if new_username in config["users"]:
        print(f"user: {new_username}, already exist.")
        exit(3)

    password = getpass.getpass("Type a password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match")
        exit(4)
    else:
        config["users"][new_username] = pbkdf2_sha256.hash(password)
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        print(f"User: {new_username} created")
        exit(0)

if args.p:
    PORT = int(args.p)

BLACKLIST = ast.literal_eval(config["server"]["blacklist"])
BACKUP_PATH = config["server"]["backup_path"]
SETTINGS = config["server"]


USUARIOS = dict(config.items("users"))

if len(USUARIOS) == 0:
    if DEBUG:
        print("No users found")
    exit(5)

app = Flask(__name__)
app.permanent_session_lifetime = 60 * 10
app.secret_key = "clave_muy_secreta"


def update_BACKUP_NAME():
    global BACKUP_NAME, ID_BACKUP_NAME
    BACKUP_NAME = []

    tmp_list = []

    for file in os.listdir(BACKUP_PATH):
        if file.endswith(".bak"):
            tmp_list.append(os.path.join(BACKUP_PATH, file))

    # sorted by date
    archivos_ordenados = sorted(tmp_list, key=os.path.getctime)

    # just basename
    nombres_ordenados = [os.path.basename(f) for f in archivos_ordenados]

    # older backups first
    nombres_ordenados.reverse()

    for name in nombres_ordenados:
        # evitando que id crezca hasta el infinito
        if ID_BACKUP_NAME == 100000:
            ID_BACKUP_NAME = 1

        BACKUP_NAME.append({"id": ID_BACKUP_NAME, "name": name})
        ID_BACKUP_NAME += 1


def get_filename_from_id(id):
    global BACKUP_NAME
    for file in BACKUP_NAME:
        if file["id"] == id:
            return file["name"]
    return None


def get_bd_names_internal():

    setting = SETTINGS
    data = {}
    command = (
        f"{setting['sqlcmd_path']} -S localhost -U {setting['user']} -P {setting['user_password']} -Q "
        f'"select name from sys.databases"'
    )

    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

    # result = Popen(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    # log = command[:command.find("-P")] + "****** " + command[command.find("-Q"):]

    if DEBUG:
        log = command.replace(setting["user_password"], "*****")
        print(log)

    if result.returncode == 0:
        out = result.stdout.split("\n")[2:-3]
        bd_names = []
        for pos, value in enumerate(out):
            bd_names.append({"name": value.replace(" ", "")})
        data["bd_names"] = bd_names
        return data, None
    else:
        return None, result.returncode


# decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "inputUser" not in session:
            if request.path == "/":
                return redirect(url_for("login"))
            return jsonify({"status": "No autorizado"}), 401
        return f(*args, **kwargs)

    return decorated_function


# API
@app.route("/api/v1/get_cookie", methods=["GET"])
def get_cookie():
    csrf_token = generate_csrf()
    return jsonify({"csrf_token": csrf_token})


@app.route("/api/v1/login/", methods=["POST"])
def login_api():
    data = {"status": False}

    username = request.form["inputUser"]
    password = request.form["inputPassword"]

    if username and password:
        if username in USUARIOS and pbkdf2_sha256.verify(password, USUARIOS[username]):
            session["inputUser"] = username
            data["status"] = True

            response = make_response(jsonify(data))

            app.session_interface.save_session(app, session, response)

            set_cookie_header = response.headers.get("Set-Cookie")
            session_value = None

            if set_cookie_header and "session=" in set_cookie_header:
                session_value = set_cookie_header.split("session=")[1].split(";")[0]
                data["session"] = session_value

            return jsonify(data)

    return "", 401


# WEB
@app.route("/")
@login_required
def home():
    update_BACKUP_NAME()
    return render_template("index.html", usuario=session["inputUser"])


@app.route("/api/v1/restore_bd/", methods=["POST"])
@login_required
def restore_bd():
    global DEFAULT_MSSQL_DATA
    id = request.form["backup_id"]
    backup_name = request.form["backup_name"]
    restore_create_new = False
    bd_to_restore = backup_name.split("_")[0]
    status = "ok"

    if request.form["restore_create_new"] == "true":
        restore_create_new = True

    try:
        backup_id = int(id)
    except ValueError:
        return "Error: backup_id most by integer", 400

    filename = get_filename_from_id(backup_id)
    if filename is None:
        return jsonify({"status": "fail"}), 501

    file = os.path.join(BACKUP_PATH, filename)
    if os.path.isfile(file):
        if DEBUG:
            print(f"Restoring {filename}: ", backup_name, restore_create_new)

        if restore_create_new:
            bd = ""
            bd_log = ""
            command = (
                f'{SETTINGS["sqlcmd_path"]} -S localhost -U {SETTINGS["user"]} -P {SETTINGS["user_password"]} -Q '
                f"\"RESTORE FILELISTONLY FROM DISK=N'{file}' \" -h-1 -W"
            )

            command_log = command.replace(SETTINGS["user_password"], "*****")
            result = run(
                command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True
            )
            out = result.stdout.split("\n")

            for element in out:
                if len(element) == 0:
                    continue
                if element.count(" D ") == 1:
                    bd = element.split(" ")[0]
                    continue
                if element.count(" L ") == 1:
                    bd_log = element.split(" ")[0]

            command = (
                f"{SETTINGS['sqlcmd_path']} -S localhost -U {SETTINGS['user']} -P {SETTINGS['user_password']} -Q "
                f"\"RESTORE DATABASE [{bd_to_restore}] FROM DISK=N'{file}' WITH FILE = 1,"
                f"NOUNLOAD, REPLACE,MOVE '{bd}' TO '{os.path.join(DEFAULT_MSSQL_DATA, bd_to_restore)}.mdf',MOVE '{bd_log}' TO '{os.path.join(DEFAULT_MSSQL_DATA, bd_to_restore)}.ldf'"
                + '"'
            )
        else:
            command = (
                f"{SETTINGS['sqlcmd_path']} -S localhost -U {SETTINGS['user']} -P {SETTINGS['user_password']} -Q "
                f"\"RESTORE DATABASE [{bd_to_restore}] FROM DISK=N'{file}' WITH FILE = 1,"
                f'NOUNLOAD, REPLACE"'
            )

        command_log = command.replace(SETTINGS["user_password"], "*****")
        if DEBUG:
            print(f"restoring with command: {command_log}")

        n = os.system(command)
        if status != "ok":
            status = n

        if DEBUG:
            print("/api/v1/restore_bd/ code:", n)

        return jsonify({"status": "ok", "response": "Backup restored successfully"})
    else:
        return "File not found", 404


@app.route("/api/v1/delete_backup/", methods=["POST"])
@login_required
def delete_backup():
    id = request.form["backup_id"]

    try:
        backup_id = int(id)
    except ValueError:
        return "Error: backup_id must be an integer", 400

    filename = get_filename_from_id(backup_id)
    if filename is None:
        return jsonify({"status": "fail"}), 501

    file = os.path.join(BACKUP_PATH, filename)
    if os.path.isfile(file):
        os.remove(file)
        return jsonify({"status": "ok", "response": "Backup deleted successfully"})
    else:
        return "File not found", 404


@app.route("/api/v1/get_backups")
@login_required
def get_backups():
    global BACKUP_NAME
    update_BACKUP_NAME()
    backups = []

    for file in BACKUP_NAME:
        if file["name"].endswith(".bak"):
            file_data = file["name"].split(".")[0].split("_")
            # validating len
            if len(file_data) == 4:
                backups.append(
                    {
                        "id": file["id"],
                        "bd": file_data[0],
                        "file": file["name"],
                        "name": file_data[1],
                        "username": file_data[2],
                        "date": file_data[3],
                        # round(os.path.getsize(self.file) / (1024 * 1024), 2)
                        "size": round(
                            os.path.getsize(os.path.join(BACKUP_PATH, file["name"]))
                            / (1024 * 1024),
                            2,
                        ),
                    }
                )
            else:
                if DEBUG:
                    print(f"Error: {file} invalid format")

    data = {
        "status": "ok",
        "BackUpList": backups,
    }
    return jsonify(data)


@app.route("/api/v1/download_bd/<backup_id>")
@login_required
def download_bd(backup_id):
    if "inputUser" in session:
        try:
            backup_id = int(backup_id)
        except ValueError:
            return "Error: backup_id debe ser un número entero", 400

        filename = get_filename_from_id(backup_id)
        file = os.path.join(BACKUP_PATH, filename)
        if os.path.isfile(file):
            return send_file(file, as_attachment=True, download_name=f"{filename}")
        else:
            return "File not found", 404
    return redirect(url_for("login"))


@app.route("/api/v1/upload_bd/", methods=["POST"])
@login_required
def upload_bd():
    data = {"status": "error"}

    if "file" not in request.files:
        data["response"] = "no file in form"
        return jsonify(data)

    file = request.files["file"]

    if file.filename == "":
        data["response"] = "Empty filename"
        return jsonify(data)

    if not file.filename.endswith(".bak"):
        data["response"] = "invalid file extension"
        return jsonify(data)

    if file:
        filename = secure_filename(file.filename)
        filename_split = filename.split("_")

        if len(filename_split) != 4:
            data["response"] = "invalid filename format"
            return jsonify(data)

        custom_name = request.form["filename"]
        filename = f"{filename_split[0]}_{filename_split[1]}({custom_name})_{filename_split[2]}_{filename_split[3]}"

        try:
            file.save(os.path.join(BACKUP_PATH, filename))
            data["status"] = "ok"
            data["response"] = "uploaded"
            return jsonify(data)
        except Exception as e:
            data["response"] = "Error: " + str(e)
            return jsonify(data)

    else:
        data["response"] = "invalid file"
        return jsonify(data)


@app.route("/api/v1/get_bd_names")
@login_required
def get_bd_names():
    if "inputUser" in session:
        returncode = 0
        data, returncode = get_bd_names_internal()
        if data is not None:
            blacklist = BLACKLIST

            data["status"] = "ok"
            bd_black_names = []
            bd_names = []

            for element in data["bd_names"]:
                if blacklist.count(element["name"]) == 0:
                    bd_names.append({"name": element["name"]})

            data["bd_names"] = bd_names

            for db_blackname in blacklist:
                bd_black_names.append(db_blackname)

            data["bd_names_blacklist"] = bd_black_names
        else:
            data = {"status": "error", "response": f"Error: {returncode}"}
        return jsonify(data)

    return redirect(url_for("login"))


@app.route("/api/v1/create_backup/", methods=["GET", "POST"])
@login_required
def create_backup():
    data = {}
    exist = False

    if request.method != "POST":
        data["status"] = "error"
        data["response"] = "POST only allowed"
        return jsonify(data)

    create_backup_name = request.form["backup_cname"]
    create_backup_bd = request.form["backup_name"]

    if DEBUG:
        print(
            f"create_backup_name: {create_backup_name} create_backup_bd: {create_backup_bd}"
        )

    # validating backup name
    if len(create_backup_name) == 0:
        data["status"] = "error"
        data["response"] = "No BD description supplied"
        return jsonify(data)

    if len(create_backup_bd) == 0:
        data["status"] = "error"
        data["response"] = "No BD name supplied"
        return jsonify(data)

    # validating blacklist
    if create_backup_bd in BLACKLIST or create_backup_name in BLACKLIST:
        data["status"] = "error"
        data["response"] = "BD name not allowed"
        return jsonify(data)

    data, returncode = get_bd_names_internal()
    if data is not None:
        for element in data["bd_names"]:
            if element["name"] == create_backup_bd:
                exist = True
                break
    else:
        data = {"status": "error", "response": f"Error: {returncode}"}
        return jsonify(data)

    if not exist:
        data = {"status": "error", "response": "No BD name found in server"}
        return jsonify(data)

    if not os.path.isdir(BACKUP_PATH):
        os.makedirs(BACKUP_PATH)
        os.system(f"chown mssql {BACKUP_PATH}")

    file = f"{create_backup_bd}_{create_backup_name}_{session['inputUser']}_{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.bak"
    file = os.path.join(BACKUP_PATH, file)

    command = (
        f'{SETTINGS["sqlcmd_path"]} -S localhost -U {SETTINGS["user"]} -P {SETTINGS["user_password"]} -Q '
        f"\"BACKUP DATABASE [{create_backup_bd}] TO DISK=N'{file}' WITH INIT, COMPRESSION, NAME='{create_backup_bd}' \""
    )

    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

    if DEBUG:
        print(f"result: {result.stdout}")

    n = result.returncode
    if n == 0:
        data["status"] = "ok"
        data["response"] = "Created"
    elif n == 256:
        data = {"status": "error", "response": "Error: code 256 (password)"}
    else:
        data = {"status": "error", "response": f"{n}"}

    data["status"] = "ok"
    data["response"] = "Created"

    return jsonify(data)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["inputUser"]
        c = request.form["inputPassword"]

        if u in USUARIOS and pbkdf2_sha256.verify(c, USUARIOS[u]):
            session["inputUser"] = u
            return redirect(url_for("home"))
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/api/v1/logout/", methods=["POST"])
def logout_api():
    data = {"status": "no user"}
    if "inputUser" in session:
        session.pop("inputUser", None)
        data["status"] = "ok"

    return jsonify(data)


@app.route("/api/v1/checklogin")
@login_required
def checkLogin_api():
    data = {"status": True}
    return jsonify(data), 200


@app.route("/logout")
def logout():
    session.pop("inputUser", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    if os.path.isfile("cert.pem") and os.path.isfile("key.pem"):
        app.run(
            debug=DEBUG,
            host="0.0.0.0",
            port=PORT,
            ssl_context=("cert.pem", "key.pem"),
        )
    else:
        app.run(debug=DEBUG, host="0.0.0.0", port=PORT)
