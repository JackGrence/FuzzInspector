import flask
import json
import os
from flask import Flask
from flask import request
from flask import Response
from visualizer import BitmapReceiver
from visualizer import BlockParser
from visualizer import BinaryWorker
from visualizer import VisualizeHelper
bitmap = BitmapReceiver()
bitmap.start()
block_info = bitmap.bin_info
app = Flask(__name__)

VisualizeHelper.init_from_afl_output(bitmap)


@app.route('/')
def hello_world():
    address = int(request.args.get('address'), 0)
    fix, dot = block_info.get_basic_block_func_dot(address)
    return flask.render_template('index.html', address=hex(address), addr_fix=fix, dot=dot)


@app.route('/path/get', methods=['GET', 'POST'])
def path_get():
    seed = request.values.get('seed')
    blocks = request.values.get('blocks')
    if not blocks:
        blocks = []
    else:
        blocks = blocks.split('_');
    blocks = list(map(lambda x: hex(int(x, 0)), blocks))
    # follow my way
    result = {'path': []}
    for block in blocks:
        if block in bitmap.data['bitmap']:
            # set current path
            if seed in bitmap.data['bitmap'][block]['seeds']:
                result['path'].append(block)
    return Response(json.dumps(result),  mimetype='application/json')


'''
Args:
    blocks: 0x41_0x42_0x43
    bitmapCnt: N
    cpustateCnt: N
    relationshipCnt: N
Return:
    bitmapCnt: N
    cpustateCnt: N
    relationshipCnt: N
    bitmap: {addr: {hit: N}}
    seeds: [id_0,id_1]
    cpustate: html...
    relationship: html...
'''
@app.route('/bitmap/get', methods=['GET', 'POST'])
def bitmap_get():
    # parse blocks
    blocks = request.values.get('blocks')
    if not blocks:
        blocks = []
    else:
        blocks = blocks.split('_');
    # prepare to_json argument
    blocks = list(map(lambda x: hex(int(x, 0)), blocks))
    bitmap_cnt, cpustate_cnt, relationship_cnt = 0, 0, 0
    log_cnt = 0
    if request.method == 'POST':
        bitmap_cnt = int(request.form['bitmapCnt'], 0)
        cpustate_cnt = int(request.form['cpustateCnt'], 0)
        relationship_cnt = int(request.form['relationshipCnt'], 0)
        log_cnt = int(request.form['logCnt'], 0)
    result = bitmap.to_json(blocks, bitmap_cnt, cpustate_cnt,
                            relationship_cnt, log_cnt)
    return Response(result, mimetype='application/json')


@app.route('/basicblock/disassemble')
def assembly_get():
    address = int(request.args.get('address'), 0)
    result = {}
    result['disasm'] = block_info.basicblock_disasm(address)
    seeds = bitmap.data['bitmap'].get(hex(address), {'seeds': []})['seeds']
    # convert seeds set to sorted list
    result['seeds'] = sorted(seeds)
    return Response(json.dumps(result),  mimetype='application/json')


@app.route("/cpustate")
def basicblock_cpustate():
    address = int(request.args.get('address'), 0)
    context = request.args.get('context').strip()
    context = context.split(' ') if context else ['default']
    context = context
    basicblock = block_info.get_block_addr(address)
    seed = request.args.get('seed').strip()
    seeds = bitmap.data['bitmap'][basicblock]['seeds']
    if seed in seeds:
        seeds = [seed]
    # convert seeds set to sorted list
    seeds = sorted(seeds)
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
    pid = int(request.args.get('pid'))
    filename = request.args.get('fn')
    filename = os.path.relpath(filename, '.')
    worker = BinaryWorker(BinaryWorker.ACTION_BITMAP,
                          seeds=[filename], pid=pid)
    bitmap.queue.put(worker)
    return Response(json.dumps({"status": 0}),  mimetype='application/json')


@app.route("/relationship")
def relationship():
    address = int(request.args.get('address'), 0)
    context = request.args.get('context').strip()
    context = context.split(' ') if context else []
    basicblock = block_info.get_block_addr(address)
    seed = request.args.get('seed').strip()
    seeds = bitmap.data['bitmap'][basicblock]['seeds']
    if seed in seeds:
        seeds = [seed]
    # convert seeds set to sorted list
    seeds = sorted(seeds)
    worker = BinaryWorker(BinaryWorker.ACTION_RELATION,
                          address=address,
                          basicblock=basicblock,
                          context=context,
                          seeds=seeds)
    bitmap.queue.put(worker)
    return Response(json.dumps({"status": 0}),  mimetype='application/json')


@app.route("/constraint")
def constraint():
    # [globaldelm][delm]type[delm]data1[delm]data2[globaldeml]...
    # |,range32,100,400|,str,aaa,bbb
    pid = int(request.args.get('pid'), 0)
    context = request.args.get('context')
    if len(context) <= 2:
        context = []
    else:
        global_delm = context[0]
        context = context[1:].split(global_delm)
    worker = BinaryWorker(BinaryWorker.ACTION_CONSTRAINT,
                          context=context,
                          pid=pid)
    bitmap.queue.put(worker)
    return Response(json.dumps({"status": 0}),  mimetype='application/json')

@app.route("/funccov")
def funccov():
    context = request.args.get('context', '').strip()
    context = [] if not context else context.split(' ')
    return bitmap.funccov(context)
