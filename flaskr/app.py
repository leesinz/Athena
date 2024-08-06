from flask import Flask, render_template, request
from database.db_class import MySQLDatabase

app = Flask(__name__)
mysql_db = MySQLDatabase()


@app.route('/')
@app.route('/index')
def index():
    try:

        latest_vulnerabilities_query = "SELECT * FROM vulnerabilities ORDER BY date DESC LIMIT 10"
        latest_vulnerabilities = mysql_db.fetch_results(latest_vulnerabilities_query)


        severity_data_query = """
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
                   SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
                   SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
                   SUM(CASE WHEN severity = '' THEN 1 ELSE 0 END) as none_count
            FROM vulnerabilities
        """
        severity_data = mysql_db.fetch_results(severity_data_query)[0]

        source_data_query = "SELECT source, COUNT(*) as count FROM vulnerabilities GROUP BY source"
        source_data = mysql_db.fetch_results(source_data_query)

        cve_data_query = "SELECT COUNT(*) as total, SUM(CASE WHEN cve <> '' THEN 1 ELSE 0 END) as cve_count FROM vulnerabilities"
        cve_data = mysql_db.fetch_results(cve_data_query)[0]

        trend_data_query = """
            SELECT DATE(date) as date, COUNT(*) as count
            FROM vulnerabilities
            WHERE date >= CURDATE() - INTERVAL 7 DAY
            GROUP BY DATE(date)
            ORDER BY DATE(date)
        """
        trend_data = mysql_db.fetch_results(trend_data_query)

        return render_template('index.html', latest_vulnerabilities=latest_vulnerabilities,
                               severity_data=severity_data, source_data=source_data, cve_data=cve_data,
                               trend_data=trend_data)
    except Exception as err:
        return f"Error: {err}"

@app.route('/vuls', methods=['GET'])
def vuls():
    try:
        search = request.args.get('search', '')
        per_page = int(request.args.get('per_page', 10))
        page = int(request.args.get('page', 1))
        offset = (page - 1) * per_page

        if search:
            query = """
                SELECT * FROM vulnerabilities
                WHERE name LIKE %s OR cve LIKE %s OR severity LIKE %s OR description LIKE %s OR source LIKE %s
                ORDER BY date DESC
                LIMIT %s, %s
            """
            params = (f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%', offset, per_page)
            vulnerabilities = mysql_db.fetch_results(query, params)

            count_query = """
                SELECT COUNT(*) as total
                FROM vulnerabilities
                WHERE name LIKE %s OR cve LIKE %s OR severity LIKE %s OR description LIKE %s OR source LIKE %s
            """
            count_params = (f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%')
        else:
            query = "SELECT * FROM vulnerabilities ORDER BY date DESC LIMIT %s, %s"
            params = (offset, per_page)
            vulnerabilities = mysql_db.fetch_results(query, params)

            count_query = "SELECT COUNT(*) as total FROM vulnerabilities"
            count_params = ()

        total_result = mysql_db.fetch_results(count_query, count_params)[0]
        total = total_result['total']

        return render_template('vuls.html', vulnerabilities=vulnerabilities, total=total, per_page=per_page, page=page, search=search)
    except Exception as err:
        return f"Error: {err}"

@app.route('/daily/<date>')
def daily(date):
    try:
        vulnerabilities_query = "SELECT * FROM vulnerabilities WHERE DATE(date) = %s ORDER BY date DESC"
        vulnerabilities = mysql_db.fetch_results(vulnerabilities_query, (date,))

        severity_data_query = """
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
                   SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
                   SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
                   SUM(CASE WHEN severity = '' THEN 1 ELSE 0 END) as none_count
            FROM vulnerabilities
            WHERE DATE(date) = %s
        """
        severity_data = mysql_db.fetch_results(severity_data_query, (date,))[0]

        source_data_query = "SELECT source, COUNT(*) as count FROM vulnerabilities WHERE DATE(date) = %s GROUP BY source"
        source_data = mysql_db.fetch_results(source_data_query, (date,))


        cve_data_query = "SELECT COUNT(*) as total, SUM(CASE WHEN cve <> '' THEN 1 ELSE 0 END) as cve_count FROM vulnerabilities WHERE DATE(date) = %s"
        cve_data = mysql_db.fetch_results(cve_data_query, (date,))[0]

        vuln_count = len(vulnerabilities)

        return render_template('daily.html', date=date, vulnerabilities=vulnerabilities,
                               severity_data=severity_data, source_data=source_data, cve_data=cve_data,
                               vuln_count=vuln_count)
    except Exception as err:
        return f"Error: {err}"

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404
