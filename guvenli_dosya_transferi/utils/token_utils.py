
import jwt
import datetime

SECRET_KEY = "supergizlisifre"

def generate_token(username):
    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)  # 10 dakikalık token
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True, payload["username"]
    except jwt.ExpiredSignatureError:
        return False, "Token süresi dolmuş."
    except jwt.InvalidTokenError:
        return False, "Token geçersiz."
