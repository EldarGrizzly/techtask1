from fastapi import FastAPI,HTTPException
from schemas import Registration, Authorization, Authorization_response, Registration_response, Authorization_by_token_response, Token_scheme, User_Settings
from oauth2client.service_account import ServiceAccountCredentials
from fastapi.middleware.cors import CORSMiddleware
import httplib2, bcrypt, googleapiclient.discovery, jwt, datetime, re, uvicorn
app = FastAPI()
origins = ['*']
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
CREDENTIALS_FILE = 'userinfo.json'
SPREADSHEET_ID = '1nEHu43Ntpy8GpmeWHssj4N4Qz_uVjPluRsnGFzutpKg'
SECRET = "8FNds8h6KhkMstEgFLxTXTZJe3OX4IjFqpaJfkQXctrahBC0FFdyRiImZWH1zl4"
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
credentials = ServiceAccountCredentials.from_json_keyfile_name(
    CREDENTIALS_FILE,
    [
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/drive'
    ],
)
httpAuth = credentials.authorize(httplib2.Http())
service = googleapiclient.discovery.build('sheets', 'v4', http=httpAuth)


def get_user_by_login(login: str):
    values_get = service.spreadsheets().values().get(
        spreadsheetId=SPREADSHEET_ID,
        range="A:E",
        majorDimension="ROWS"
    ).execute()['values']
    for i in values_get:
        if i[0] == login:
            return i

    return False


def verify_password(given_password, current_password):
    return bcrypt.checkpw(given_password.encode('utf-8'), current_password[2:len(current_password)-1].encode('utf-8'))



@app.post('/registration', response_model= Registration_response)
def registration(data: Registration):
    values_get = service.spreadsheets().values().get(
        spreadsheetId=SPREADSHEET_ID,
        range="A:C",
        majorDimension="COLUMNS"
    ).execute()['values']
    ALL_USERNAMES = values_get[0]
    ALL_EMAILS = values_get[2]
    for i in range(0,len(ALL_USERNAMES)):
        if ALL_USERNAMES[i] == data.login or ALL_EMAILS[i] == data.email:
            raise HTTPException(status_code=404, detail="This user is already exists!")

    if re.fullmatch(regex,data.email):
        service.spreadsheets().values().batchUpdate(
            spreadsheetId=SPREADSHEET_ID,
            body={
                "valueInputOption": "USER_ENTERED",
                "data": [
                    {
                        "range": f"A{len(values_get[0]) + 1}:C",
                        "majorDimension": "ROWS",
                        "values": [
                            [f"{data.login}", f"{bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt())}",
                             f"{data.email}"]]
                    }
                ]
            }
        ).execute()

        return Registration_response(msg="The User is successfully registered!")
    else:
        return {
            "msg": "Invalid email!"
        }

@app.post("/login", response_model=Authorization_response)
def auth_by_info(data: Authorization):
    user = get_user_by_login(data.login)
    if not user or not verify_password(data.password, user[1]):
        raise HTTPException(status_code=404, detail="Wrong login or password!")

    payload = {
        "login": user[0],
        "email": user[2],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    jwt_encode = jwt.encode(payload=payload,
                              key=SECRET,
                              algorithm="HS256")
    return Authorization_response(jwt_token=jwt_encode)


@app.post("/token")
def auth_by_token(token: Token_scheme):
    try:
        decoded_token = jwt.decode(jwt=token.token,
                                   key=SECRET,
                                   algorithms=["HS256"])
        user = get_user_by_login(decoded_token['login'])
        if not user:
            raise HTTPException(status_code=404, detail="This User doesn't exist!")

        return Authorization_by_token_response(login=decoded_token['login'], email=decoded_token['email'])
    except:
        raise HTTPException(status_code=404, detail="Token is expired!")



@app.post("/settings")
def set_user_settings(user: User_Settings):
    values_get = service.spreadsheets().values().get(
        spreadsheetId=SPREADSHEET_ID,
        range="A:C",
        majorDimension="COLUMNS"
    ).execute()['values']
    ALL_USERNAMES = values_get[0]
    for i in range(0,len(ALL_USERNAMES)):
        if ALL_USERNAMES[i] == user.login:
            service.spreadsheets().values().batchUpdate(
                spreadsheetId=SPREADSHEET_ID,
                body={
                    "valueInputOption": "USER_ENTERED",
                    "data": [
                        {
                            "range": f"D{i+1}:E",
                            "majorDimension": "ROWS",
                            "values": [[f"{user.app_id}", f"{user.app_hash}"]]
                        }
                    ]
                }
            ).execute()
            return {"msg": "Successfully changed!"}

    raise HTTPException(status_code=404, detail="This User doesn't exist!")


@app.post('/validate_token')
def validate_token(token: Token_scheme):
    try:
        decoded_token = jwt.decode(jwt=token.token,key=SECRET,algorithms=["HS256"])
        return True

    except:
        return False


@app.get('/get_settings/{token}')
def get_user_settings(token: str):
    try:
        decoded_token = jwt.decode(jwt=token, key=SECRET, algorithms=["HS256"])
        user = get_user_by_login(decoded_token['login'])
        if len(user) == 3:
                return {"msg": "This User doesn't have settings!"}
        return User_Settings(login=user[0], app_id=user[3], app_hash=user[4])
    except:
        raise HTTPException(status_code=404, detail="This User doesn't exist!")


if __name__ == "__main__":
    uvicorn.run(app, host='0.0.0.0', port=8000)
