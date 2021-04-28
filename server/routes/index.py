from server import app

@app.route('/')
def index():
    return f'Core System'

@app.errorhandler(404)
@app.route("/404")
def page_not_found(error):
    return f'Page not found!'

@app.errorhandler(500)
@app.route("/500")
def requests_error(error):
    return f'Internal Server Error!'