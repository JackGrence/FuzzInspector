import flask
import json
from flask import Flask
from flask import request
from flask import Response
from visualizer import BitmapReceiver
from visualizer import BlockParser
from visualizer import BinaryWorker
bitmap = BitmapReceiver()
bitmap.start()
block_info = bitmap.bin_info
app = Flask(__name__)


@app.route('/')
def hello_world():
    address = int(request.args.get('address'), 0)
    b_info = block_info.get_func_block(address)
    dot = block_info.get_basic_block_func_dot(address)
    return flask.render_template('index.html', address=hex(address), block_info=b_info, dot=dot)


@app.route('/bitmap/get', methods=['GET', 'POST'])
def bitmap_get():
    result = dict(bitmap.data)
    blocks = request.values.get('blocks')
    if blocks:
        blocks = blocks.split('_');
        blocks = map(lambda x: hex(int(x, 0)), blocks)
        result['bitmap'] = {}
        for block in blocks:
            if block not in bitmap.data['bitmap']:
                result['bitmap'][block] = {'hit': 0}
            else:
                result['bitmap'][block] = {'hit': bitmap.data['bitmap'][block]['hit']}
    return Response(json.dumps(result),  mimetype='application/json')


@app.route('/basicblock/disassemble')
def assembly_get():
    address = int(request.args.get('address'), 0)
    result = block_info.basicblock_disasm(address)
    return Response(json.dumps(result),  mimetype='application/json')


@app.route("/cpustate")
def basicblock_cpustate():
    address = int(request.args.get('address'), 0)
    context = request.args.get('context').strip()
    context = context.split(' ') if context else []
    context = context + ['default']
    basicblock = block_info.get_block_addr(address)
    seeds = bitmap.data['bitmap'][basicblock]['seed']
    worker = BinaryWorker(BinaryWorker.ACTION_CPUSTATE,
                          address=address,
                          basicblock=basicblock,
                          seeds=seeds,
                          context=context)
    bitmap.queue.put(worker)

    return Response(json.dumps({"status": 0}),  mimetype='application/json')


@app.route("/fuzzer")
def fuzzer():
    return bitmap.data.get('constraint', '0')


@app.route("/seed")
def seed():
    filename = request.args.get('fn')
    worker = BinaryWorker(BinaryWorker.ACTION_BITMAP,
                          seeds=[filename])
    bitmap.queue.put(worker)
    return Response(json.dumps({"status": 0}),  mimetype='application/json')


@app.route("/relationship")
def relationship():
    address = int(request.args.get('address'), 0)
    context = request.args.get('context').strip()
    context = context.split(' ') if context else []
    basicblock = block_info.get_block_addr(address)
    seeds = bitmap.data['bitmap'][basicblock]['seed']
    worker = BinaryWorker(BinaryWorker.ACTION_RELATION,
                          address=address,
                          basicblock=basicblock,
                          context=context,
                          seeds=seeds)
    bitmap.queue.put(worker)
    return Response(json.dumps({"status": 0}),  mimetype='application/json')


@app.route("/constraint")
def constraint():
    context = request.args.get('context').strip()
    context = context.split(' ') if context else []
    worker = BinaryWorker(BinaryWorker.ACTION_CONSTRAINT,
                          context=context)
    bitmap.queue.put(worker)
    return Response(json.dumps({"status": 0}),  mimetype='application/json')
