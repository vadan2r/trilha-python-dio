# Passo a Passo para o desafio da API Bancária Assíncrona com FastAPI:

```markdown
# API Bancária Assíncrona com FastAPI

Este projeto demonstra a criação de uma API RESTful assíncrona usando FastAPI para gerenciar operações bancárias de depósitos e saques vinculadas a contas correntes. A API utiliza autenticação JWT e segue as práticas recomendadas de design de API.

## Objetivos

*   Permitir o cadastro de transações bancárias, como depósitos e saques.
*   Implementar um endpoint para exibir o extrato de uma conta, mostrando todas as transações realizadas.
*   Utilizar JWT (JSON Web Tokens) para garantir que apenas usuários autenticados possam acessar os endpoints que exigem autenticação.

## Requisitos Técnicos

*   FastAPI
*   Modelagem de Dados
*   Validação das operações
*   Segurança (JWT)
*   Documentação com OpenAPI

## Passo a Passo

### 1. Configuração do Ambiente

*   **Instalação do Python:** Certifique-se de ter o Python 3.7+ instalado.
*   **Ambiente Virtual:** Recomenda-se criar um ambiente virtual para isolar as dependências do projeto.

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # No Linux/macOS
    .\venv\Scripts\activate  # No Windows
    ```

*   **Instalação das Dependências:**

    ```bash
    pip install fastapi uvicorn python-jose passlib bcrypt python-multipart
    ```

    *   `fastapi`: Framework web assíncrono.
    *   `uvicorn`: Servidor ASGI para executar a aplicação.
    *   `python-jose`: Para lidar com JWT.
    *   `passlib`: Para hash de senhas.
    *   `bcrypt`: Algoritmo de hash de senhas.
    *   `python-multipart`: Para suporte a `multipart/form-data`, necessário para o FastAPI.

### 2. Estrutura do Projeto

Crie uma estrutura de diretórios para organizar o projeto:

```
async_bank_api/
├── app/
│   ├── __init__.py
│   ├── database.py   # Lógica de conexão com o banco de dados
│   ├── models.py     # Definição dos modelos de dados (Conta, Transação, Usuário)
│   ├── schemas.py    # Schemas Pydantic para validação e serialização
│   ├── security.py   # Funções de segurança (hash de senha, JWT)
│   ├── endpoints/
│   │   ├── __init__.py
│   │   ├── auth.py     # Endpoints de autenticação (login, registro)
│   │   ├── accounts.py # Endpoints para contas (extrato, etc.)
│   │   ├── transactions.py # Endpoints para transações (depósito, saque)
│   └── main.py       # Ponto de entrada da aplicação FastAPI
├── README.md
```

### 3. Implementação

#### 3.1. Modelos de Dados (app/models.py)

Defina os modelos de dados para representar as entidades do sistema (ex: usando SQLAlchemy):

```python
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

DATABASE_URL = "sqlite:///./bank.db"  # Use SQLite para simplicidade

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    accounts = relationship("Account", back_populates="owner")

class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    balance = Column(Float, default=0.0)

    owner = relationship("User", back_populates="accounts")
    transactions = relationship("Transaction", back_populates="account")

class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("accounts.id"))
    amount = Column(Float)
    transaction_type = Column(String)  # "deposit" ou "withdrawal"
    timestamp = Column(DateTime, default=datetime.utcnow)

    account = relationship("Account", back_populates="transactions")

def create_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    create_db()
```

#### 3.2. Schemas Pydantic (app/schemas.py)

Defina os schemas Pydantic para validação dos dados de entrada e saída:

```python
from pydantic import BaseModel
from datetime import datetime

class UserSchema(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

class UserCreate(BaseModel):
    username: str
    password: str

class AccountSchema(BaseModel):
    id: int
    owner_id: int
    balance: float

    class Config:
        orm_mode = True

class TransactionSchema(BaseModel):
    id: int
    account_id: int
    amount: float
    transaction_type: str
    timestamp: datetime

    class Config:
        orm_mode = True

class TransactionCreate(BaseModel):
    account_id: int
    amount: float
    transaction_type: str  # "deposit" ou "withdrawal"
```

#### 3.3. Segurança (app/security.py)

Implemente funções para hash de senhas e geração/validação de JWT:

```python
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt

# Configuração da senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuração do JWT
SECRET_KEY = "YOUR_SECRET_KEY"  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
```

#### 3.4. Endpoints (app/endpoints/\*.py)

Implemente os endpoints da API:

*   **Autenticação (app/endpoints/auth.py):** Registro de usuário e login (geração de JWT).
*   **Contas (app/endpoints/accounts.py):** Exibição de extrato.
*   **Transações (app/endpoints/transactions.py):** Depósito e saque.

Exemplo de um endpoint (app/endpoints/transactions.py):

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import models, schemas
from app.database import get_db
from app.security import decode_token

router = APIRouter()

# Dependency to get the current user
def get_current_user(token: str, db: Session = Depends(get_db)):
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = db.query(models.User).filter(models.User.id == payload["sub"]).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/deposit/")
async def create_deposit(transaction: schemas.TransactionCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    if transaction.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    db_account = db.query(models.Account).filter(models.Account.id == transaction.account_id).first()
    if not db_account:
        raise HTTPException(status_code=404, detail="Account not found")

    db_transaction = models.Transaction(**transaction.dict())
    db.add(db_transaction)

    db_account.balance += transaction.amount
    db.commit()
    db.refresh(db_transaction)
    return db_transaction
```

#### 3.5. Ponto de Entrada (app/main.py)

Configure a aplicação FastAPI e inclua os roteadores:

```python
from fastapi import FastAPI
from app.endpoints import auth, accounts, transactions
from app.database import create_db

app = FastAPI()

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(accounts.router, prefix="/accounts", tags=["accounts"])
app.include_router(transactions.router, prefix="/transactions", tags=["transactions"])

@app.on_event("startup")
async def startup_event():
    create_db() # Create database tables

@app.get("/")
async def read_root():
    return {"message": "Welcome to the Async Bank API"}
```

### 4. Execução

Execute a aplicação usando Uvicorn:

```bash
uvicorn app.main:app --reload
```

A API estará disponível em `http://127.0.0.1:8000`.

### 5. Documentação

Acesse a documentação automática da API em:

*   `http://127.0.0.1:8000/docs` (Swagger UI)
*   `http://127.0.0.1:8000/redoc` (ReDoc)

### 6. Testes

Implemente testes unitários e de integração para garantir a qualidade do código.

```bash
pytest
```

## Considerações Adicionais

*   **Banco de Dados:** Para um ambiente de produção, considere usar um banco de dados mais robusto como PostgreSQL.
*   **Segurança:** Reforce a segurança da API com medidas como rate limiting, proteção contra ataques CSRF, etc.
*   **Logging:** Implemente um sistema de logging para monitorar a aplicação.
*   **Testes:** Escreva testes abrangentes para todas as funcionalidades da API.
```

Este é um guia inicial para construir sua API.
