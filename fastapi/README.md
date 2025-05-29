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

## What I learned

1. Decorator syntactic sugar (a.k.a [pie syntax](https://realpython.com/primer-on-python-decorators/#adding-syntactic-sugar))

```python
@app.get("/")
async def root():
    return {"message": "Hello World"}
```

is equivalent to:

```python
async def root():
    return {"message": "Hello World"}
root = app.get("/")(root)
```

2. Python functions can accept arbitrary positional and keyword args, just like Ruby method do

```python
def foo(*args, **kwargs):
  # do something with args and kwargs
```
