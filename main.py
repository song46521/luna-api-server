from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, DateTime, Integer, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import requests
import datetime
import uvicorn
import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Database Setup ---
DATABASE_URL = "sqlite:///./luna_minecraft_users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Models ---
class AccountDB(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    is_verified = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)

class BlacklistDB(Base):
    __tablename__ = "blacklist"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    uuid = Column(String, unique=True)
    reason = Column(String)
    country = Column(String, default="Unknown")
    added_at = Column(DateTime, default=datetime.datetime.now)

class GlobalAlertDB(Base):
    __tablename__ = "global_alerts"
    id = Column(Integer, primary_key=True, index=True)
    message = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.now)

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    uuid = Column(String, unique=True)
    skin_url = Column(String)
    last_seen = Column(DateTime, default=datetime.datetime.now)

class ReportDB(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    reporter = Column(String)
    target_name = Column(String)
    reason = Column(Text)
    status = Column(String, default="PENDING")
    created_at = Column(DateTime, default=datetime.datetime.now)

class AppealDB(Base):
    __tablename__ = "appeals"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    uuid = Column(String)
    message = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now)

class ServerApplyDB(Base):
    __tablename__ = "server_applies"
    id = Column(Integer, primary_key=True, index=True)
    owner_name = Column(String)
    email = Column(String)
    server_address = Column(String)
    server_type = Column(String)
    status = Column(String, default="PENDING")
    created_at = Column(DateTime, default=datetime.datetime.now)

Base.metadata.create_all(bind=engine)

# --- API App ---
app = FastAPI(title="Luna Guard enterprise API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Auth Endpoints ---
@app.post("/auth/login")
def login(req: dict, db: Session = Depends(get_db)):
    user = db.query(AccountDB).filter(AccountDB.username == req['username']).first()
    if user and pwd_context.verify(req['password'], user.hashed_password):
        return {"username": user.username, "is_admin": user.is_admin}
    raise HTTPException(401, "Fail")

@app.post("/blacklist/auto-report")
def auto_report_ban(username: str, reason: str, server_name: str, db: Session = Depends(get_db)):
    try:
        # 1. Mojang 데이터 가져오기
        r = requests.get(f"https://api.mojang.com/users/profiles/minecraft/{username}", timeout=10)
        if r.status_code != 200:
            raise HTTPException(status_code=404, detail="Minecraft 유저를 Mojang에서 찾을 수 없습니다.")
        
        data = r.json()
        target_uuid = data["id"]
        target_name = data["name"]

        # 2. 이미 블랙리스트에 있는지 확인 (중복 방지)
        existing = db.query(BlacklistDB).filter(BlacklistDB.uuid == target_uuid).first()
        
        if existing:
            # 기존 사유에 추가
            existing.reason = f"{existing.reason} | [{server_name}] {reason}"
            existing.added_at = datetime.datetime.now()
        else:
            # 새로 추가
            db.add(BlacklistDB(
                username=target_name, 
                uuid=target_uuid, 
                reason=f"[{server_name}] {reason}"
            ))

        # 3. 전역 알림 생성
        db.add(GlobalAlertDB(message=f"🚨 Threat Blocked: {target_name} on {server_name}!"))
        
        db.commit()
        return {"ok": True, "message": "Successfully reported"}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        db.rollback() # 오류 발생 시 롤백
        print(f"Server Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.get("/alerts/latest")
def get_latest_alert(db: Session = Depends(get_db)):
    return db.query(GlobalAlertDB).order_by(GlobalAlertDB.created_at.desc()).first()

@app.get("/user/{uuid_or_name}")
def get_user(uuid_or_name: str, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter((UserDB.uuid == uuid_or_name) | (UserDB.username == uuid_or_name)).first()
    if not user:
        r = requests.get(f"https://api.mojang.com/users/profiles/minecraft/{uuid_or_name}").json()
        user = UserDB(username=r["name"], uuid=r["id"], skin_url=f"https://crafatar.com/renders/body/{r['id']}?overlay")
        db.add(user)
        db.commit()
        db.refresh(user)
    is_bl = db.query(BlacklistDB).filter(BlacklistDB.uuid == user.uuid).first() is not None
    return {"username": user.username, "uuid": user.uuid, "skin_url": user.skin_url, "is_blacklisted": is_bl}

@app.get("/users")
def list_users(db: Session = Depends(get_db)):
    return db.query(UserDB).order_by(UserDB.last_seen.desc()).all()

@app.get("/blacklist")
def list_blacklist(db: Session = Depends(get_db)):
    return db.query(BlacklistDB).all()

@app.post("/apply")
def submit_apply(a: dict, db: Session = Depends(get_db)):
    db.add(ServerApplyDB(**a))
    db.commit()
    return {"ok": True}

@app.post("/report")
def submit_report(r: dict, db: Session = Depends(get_db)):
    db.add(ReportDB(**r))
    db.commit()
    return {"ok": True}

@app.post("/appeal")
def submit_appeal(username: str, uuid: str, message: str, db: Session = Depends(get_db)):
    db.add(AppealDB(username=username, uuid=uuid, message=message))
    db.commit()
    return {"ok": True}

@app.get("/admin/reports")
def admin_reports(db: Session = Depends(get_db)):
    return db.query(ReportDB).all()

@app.get("/admin/applies")
def admin_applies(db: Session = Depends(get_db)):
    return db.query(ServerApplyDB).all()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
