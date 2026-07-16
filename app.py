from flask import Flask, render_template, jsonify
import psutil
import requests
import time
import platform
import subprocess
import threading
import webbrowser

app = Flask(__name__)

class CyberAnalyzer:
    def __init__(self):
        self.safe_ports = {80, 443, 53, 22, 21, 8080, 8443}
        self.last_io = psutil.net_io_counters()
        self.last_time = time.time()

    def get_live_traffic(self):
        current_io = psutil.net_io_counters()
        current_time = time.time()
        time_diff = current_time - self.last_time

        if time_diff > 0:
            upload = (current_io.bytes_sent - self.last_io.bytes_sent) / time_diff / 1024
            download = (current_io.bytes_recv - self.last_io.bytes_recv) / time_diff / 1024
        else:
            upload, download = 0, 0

        self.last_io = current_io
        self.last_time = current_time
        return {"upload": round(upload, 2), "download": round(download, 2)}

    def run_full_scan(self):
        report = {}
        score = 100

        # 1. Локация
        try:
            resp = requests.get("http://ip-api.com/json/", timeout=3).json()
            if resp.get("status") == "success":
                report['ip'] = resp.get('query', 'Неизвестно')
                report['location'] = f"{resp.get('city', '')}, {resp.get('country', '')}"
                report['isp'] = resp.get('isp', 'Нет данных')
                report['lat'] = resp.get('lat', 0)
                report['lon'] = resp.get('lon', 0)
            else:
                raise Exception("API Error")
        except:
            report['ip'] = "Офлайн"
            report['location'] = "Локальная сеть"
            report['isp'] = "Нет соединения"
            report['lat'], report['lon'] = 0, 0
            score -= 20

        # 2. Пинг
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            start = time.time()
            subprocess.check_output(['ping', param, '1', '8.8.8.8'], stderr=subprocess.STDOUT)
            ping = round((time.time() - start) * 1000, 2)
            report['ping'] = ping
            if ping > 100: score -= 15
        except:
            report['ping'] = 0
            score -= 30

        # 3. Соединения
        sus_conns = 0
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port not in self.safe_ports:
                        sus_conns += 1
            report['suspicious'] = sus_conns
            score -= min(sus_conns * 2, 40)
        except:
            report['suspicious'] = 0

        # 4. Выводы
        report['score'] = max(0, score)
        advice, action_plan = [], []
        
        if score == 100:
            advice.append("Система в идеальном состоянии. Угроз не обнаружено.")
            action_plan.append("Продолжайте соблюдать базовые правила цифровой гигиены.")
        else:
            advice.append("ВНИМАНИЕ: Обнаружены потенциальные уязвимости или сетевые аномалии.")
            
        if report.get('ping', 0) > 100:
            action_plan.append("Задержка слишком высокая. Убедитесь, что канал не перегружен фоновыми загрузками.")
            
        if sus_conns > 0:
            action_plan.append(f"Найдено {sus_conns} неизвестных соединений. Откройте консоль (cmd) и введите 'netstat -ano'.")
            action_plan.append("Проверьте систему антивирусом.")
            
        report['advice'] = " | ".join(advice)
        report['actions'] = action_plan
        return report

analyzer = CyberAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def api_scan():
    return jsonify(analyzer.run_full_scan())

@app.route('/api/traffic')
def api_traffic():
    return jsonify(analyzer.get_live_traffic())

def open_browser():
    time.sleep(1.5)
    webbrowser.open_new("http://127.0.0.1:5000")

if __name__ == '__main__':
    threading.Thread(target=open_browser).start()
    app.run(port=5000)