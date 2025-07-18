
from models.entities.User import User

class ModelUser:

    @classmethod
    def login(cls, db, user):
        try:
            cursor = db.connection.cursor()
            sql = "SELECT id, username, password FROM user WHERE username = %s"
            cursor.execute(sql, (user.username,))
            row = cursor.fetchone()
            if row and row[2] == user.password:
                return User(row[0], row[1], row[2])
        except Exception as ex:
            print(ex)
        return None

    @classmethod
    def get_by_id(cls, db, id):
        try:
            cursor = db.connection.cursor()
            sql = "SELECT id, username FROM user WHERE id = %s"
            cursor.execute(sql, (id,))
            row = cursor.fetchone()
            if row:
                return User(row[0], row[1], None)
        except Exception as ex:
            print(ex)
        return None
