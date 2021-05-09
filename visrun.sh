#!/bin/bash
FLASK_ENV=development FLASK_APP=httpserver.py FLASK_RUN_PORT=`cat visport` flask run
