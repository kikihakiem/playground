# Hello Fast-API

## What I did

Note: All commands below use Python 3.13.0 and pip 24.2

1. Install dependencies

```shell
python -m venv venv/
source venv/bin/activate
python -m pip install fastapi "uvicorn[standard]"
```

2. Make a hello world app
3. Run the app

```shell
uvicorn main:app --reload
```