from pydantic import BaseModel


class Registration(BaseModel):
    login: str
    password: str
    email: str


class Registration_response(BaseModel):
    msg: str


class Authorization(BaseModel):
    login: str
    password: str


class Authorization_response(BaseModel):
    jwt_token: str


class Authorization_by_token_response(BaseModel):
    login: str
    email: str


class Token_scheme(BaseModel):
    token: str


class User_Settings(BaseModel):
    login: str
    app_id: str
    app_hash: str


