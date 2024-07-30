import mysql.connector
from mysql.connector import Error
from config import cfg


class MySQLDatabase:
    def __init__(self):
        self.config = cfg['mysql']
        self.connection = None

    def connect(self):
        if self.connection is None or not self.connection.is_connected():
            try:
                self.connection = mysql.connector.connect(
                    host=self.config['host'],
                    port=self.config['port'],
                    user=self.config['username'],
                    password=self.config['password'],
                    database=self.config['database'],
                    charset='utf8mb4'
                )
            except Error as e:
                print(f"Error: {e}")
                self.connection = None

    def close(self):
        if self.connection is not None and self.connection.is_connected():
            self.connection.close()

    def execute_query(self, query, params=None):
        self.connect()
        if self.connection is None:
            print("Failed to connect to the database")
            return

        cursor = self.connection.cursor()
        try:
            cursor.execute(query, params)
            self.connection.commit()
        except Error as e:
            print(f"Error: {e}")
        cursor.close()

    def fetch_results(self, query, params=None):
        self.connect()
        if self.connection is None:
            print("Failed to connect to the database")
            return []

        cursor = self.connection.cursor()
        results = []
        try:
            cursor.execute(query, params)
            results = cursor.fetchall()
        except Error as e:
            print(f"Error: {e}")
        cursor.close()
        return results

    def insert_vulnerability(self,  data):
        query = f"""
        INSERT INTO vulnerabilities (name, cve, severity, description, source, date, link)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            name=VALUES(name),
            cve=VALUES(cve),
            severity=VALUES(severity),
            description=VALUES(description),
            source=VALUES(source),
            date=VALUES(date),
            link=VALUES(link)
        """
        self.execute_query(query, (
            data['name'], data['cve'], data['severity'], data['description'], data['source'], data['date'], data['link']
        ))

    def check_vulnerability_exists(self, key, value):
        query = f"SELECT EXISTS(SELECT 1 FROM vulnerabilities WHERE {key}=%s)"
        result = self.fetch_results(query, (value,))
        return result[0][0] if result else False
