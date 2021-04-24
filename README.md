# Start server

```
py -3 -m venv venv
venv\Scripts\activate
pip install Flask 
pip install Flask-cors
pip install requests
```

# Linux
```
export FLASK_APP=server
flask run --host=0.0.0.0
```
# Windows
```
set FLASK_APP=server
flask run --host=0.0.0.0
```