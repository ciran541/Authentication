from pydantic import BaseModel, Extra

class SignUpSchema(BaseModel):
    email: str
    password: str
    
    class Config:
        extra = Extra.allow  
        json_schema_extra = {
            "example": {
                "email": "sample@gmail.com",
                "password": "samplepass123"
            }
        }

class LoginSchema(BaseModel):
    email: str
    password: str    

    class Config:
        extra = Extra.allow
        json_schema_extra = {
            "example": {
                "email": "sample@gmail.com",
                "password": "samplepass123"
            }
        }
