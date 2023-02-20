from flask import Flask, request, render_template
import docker

app = Flask(__name__)
client = docker.from_env()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    query = request.form['query']
    container = client.containers.get('getsploit')
    cmd = f'getsploit {query}'
    result = container.exec_run(cmd)
    return render_template('search.html', result=result.output.decode())

if __name__ == '__main__':
    app.run(debug=True)
