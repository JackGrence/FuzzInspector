import flask
import json
from flask import Flask
from flask import request
from flask import Response
from visualize import BitmapReceiver
from visualize import BlockParser
block_info = BlockParser('./rootfs/usr/sbin/admin.cgi')
bitmap = BitmapReceiver('hello')
bitmap.start()
app = Flask(__name__)


@app.route('/')
def hello_world():
    address = request.args.get('address')
    b_info = block_info.get_func_block(address)
    return flask.render_template('index.html', address=address, block_info=b_info)


@app.route('/bitmap/get')
def bitmap_get():
    return bitmap.data


@app.route('/basicblock/disassemble')
def assembly_get():
    address = request.args.get('address')
    result = block_info.basicblock_disasm(address)
    return Response(json.dumps(result),  mimetype='application/json')
