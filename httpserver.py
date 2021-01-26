import flask
import json
from flask import Flask
from flask import request
from flask import Response
from visualize import BitmapReceiver
from visualize import BlockParser
block_info = BlockParser('./rootfs/usr/sbin/admin.cgi')
bitmap = BitmapReceiver()
bitmap.start()
app = Flask(__name__)


@app.route('/')
def hello_world():
    address = request.args.get('address')
    b_info = block_info.get_func_block(address)
    return flask.render_template('index.html', address=address, block_info=b_info)


@app.route('/bitmap/get')
def bitmap_get():
    result = {x: y['hit'] for x, y in bitmap.data.items()}
    return result


@app.route('/basicblock/disassemble')
def assembly_get():
    address = request.args.get('address')
    result = block_info.basicblock_disasm(address)
    return Response(json.dumps(result),  mimetype='application/json')


@app.route("/cpustate")
def basicblock_cpustate():
    address = request.args.get('address')
    result = bitmap.cpustate(address, block_info.get_block_addr(address))
    result = {'result': result}
    return Response(json.dumps(result),  mimetype='application/json')


@app.route("/fuzzer")
def fuzzer():
    return "0 0x198b0 2 ./afl_inputs/vlanIntfs ./afl_inputs/vlan 2 r1 0 0x197d0 0x4141"


@app.route("/seed")
def seed():
    filename = request.args.get('fn')
    bitmap.queue.put(filename)
    return "OK"
