#!/bin/bash
FLASK_ENV=development FLASK_APP=httpserver.py flask run FLASK_RUN_PORT=`cat visport` flask run
