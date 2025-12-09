from app import app, db
print('SQLALCHEMY_DATABASE_URI =', app.config.get('SQLALCHEMY_DATABASE_URI'))
with app.app_context():
    try:
        print('Engine URL:', str(db.engine.url))
    except Exception as e:
        print('Error getting engine URL:', e)
