from flask import Flask, jsonify, request, render_template
from constant import *

from multiprocessing import Process


class Web(Process):
    def __init__(self, node_name):
        self.node_name = node_name
        self.name = f"{node_name} Web Server"
        super().__init__(name = self.name)
        self.neighbors = []
        self.delta_time = 0

    def run(self):
        app = Flask(__name__)

        @app.route("/time", methods=['POST'])
        def set_time():
            body = request.get_json()
            self.delta_time = body['delta_time']
            return jsonify(self.delta_time) 
            
        @app.route("/time", methods=['GET'])
        def get_time():
            return jsonify(self.delta_time)
        
        @app.route("/")
        def index():
            return render_template('index.html', node_name=self.node_name, ip=RX_IPADDR)
        
        @app.route("/neighbors", methods=['GET'])
        def get_neighbors():
            return jsonify(self.neighbors)

        @app.route("/neighbors", methods=['POST'])
        def add_neighbor():
            body = request.get_json()
            self.neighbors.append(body)
            return jsonify(self.neighbors)
        
        @app.route("/neighbors", methods=['DELETE'])
        def delete_neighbor():
            body = request.get_json()
            if body in self.neighbors:
                self.neighbors.remove(body)
            return jsonify(self.neighbors)

        app.run(host=RX_IPADDR, port=WEB_PORT)
        