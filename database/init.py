from .db_class import MySQLDatabase


def create_db():
    db = MySQLDatabase()
    create_vulnerabilities_table = """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name TEXT CHARACTER SET utf8mb4,
    cve VARCHAR(255),
    severity VARCHAR(20),
    description TEXT CHARACTER SET utf8mb4,
    source VARCHAR(50),
    date DATETIME,
    link VARCHAR(255)
) CHARACTER SET utf8mb4;
        """

    db.execute_query(create_vulnerabilities_table)