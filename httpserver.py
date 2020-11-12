import flask
from flask import Flask
from flask import request
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
