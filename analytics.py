from cProfile import run
from crypt import methods
from lib2to3.pytree import type_repr
from re import L
from sched import scheduler
import socket
from urllib import response
#from click import password_option
import psycopg2
from flask import Flask, jsonify,render_template,request,url_for,redirect,session,make_response,Response,send_file
import hashlib
import requests
from sqlalchemy import null
from flask_apscheduler import APScheduler
import configparser
import time
import threading
from flask_cors import CORS
import networkx as nx
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
import os
import io
import random
import json
from analytics_logic import AnalyticSupportService
import psutil

app = Flask(__name__,template_folder="../Dashboardnew/templates", static_folder="../Dashboardnew/static")
CORS(app)

config = configparser.ConfigParser()
config.read('environment_config.ini')

analyticsSupportService = AnalyticSupportService()

@app.route("/getstatus")
def getOperationStatus():
    cpu_usage = psutil.cpu_percent()
    mem_usage = psutil.virtual_memory().percent
    msg = "Ok"
    if cpu_usage > 80 or mem_usage > 80:
        msg = "Warning"
    return jsonify(cpu_usage=cpu_usage, mem_usage=mem_usage, msg=msg)    

@app.route("/getInfo")
def testService():
    # count = request.args.get('count')
    # runQoSTest(thread_id=1,test_count=0,concurrent_users=1,loop_times=1)
    # runQoSTest(thread_id=2,test_count=0,concurrent_users=1,loop_times=1)
    # re = dttsaSupportServices.qosSpecificTestExecutionStatus("i")
    # repAttackCheck()
    dts = analyticsSupportService.getDTDetails()
    print(len(dts))
    dt_count = len(dts)
    analysis_count = len(analyticsSupportService.getAnalysisCyclesCount())
    rep_attacks_count = len(analyticsSupportService.getRepAttackCount())
    avg_trust_score = analyticsSupportService.getAvgTrustScore()
    val = {
        "series": [
            {
                "name": 'Trust Score',
                "data": [random.randint(0,100), random.randint(0,100), random.randint(0,100), random.randint(0,100), random.randint(0,100), random.randint(0,100), 65,100]
            }
        ],
        "labels": ['1', '2', '3', '4', '5', '6', '7','8'],
        "cards": [
  {
    "icon": '<img src="https://www.shutterstock.com/image-vector/explore-concept-digital-twins-this-600nw-2366323277.jpg" alt="Trulli" width="500" height="333">',
    "title": 'Number of DTs',
    "total": dt_count,
  },
  {
    "icon": '<img src="https://static.vecteezy.com/system/resources/previews/026/306/689/original/chart-analysis-icon-statistics-business-finance-research-growth-sales-magnify-glass-sign-symbol-black-artwork-graphic-illustration-clipart-eps-vector.jpg" alt="Trulli" width="500" height="333">',
    "title": 'Analysis Cycles',
    "total": analysis_count,
  },
  {
    "icon": '<img src="https://p7.hiclipart.com/preview/428/736/877/security-hacker-cyberattack-computer-icons-computer-security-cybercrime-cyber-crime.jpg" alt="Trulli" width="500" height="333">',
    "title": 'Rep: Attacks',
    "total": rep_attacks_count,
  },
  {
    "icon": '<img src="https://media.istockphoto.com/id/1426831333/vector/handshake-line-icon-deal-partner-business-symbol-editable-stroke-design-template-vector.jpg?s=1024x1024&w=is&k=20&c=Vb66JT7X5Tf-Kwzo_9v_cfFRTT3q_e9Gmf5to4rH9DQ=" alt="Trulli" width="500" height="333">',
    "title": 'Avg: Trust Score',
    "total": avg_trust_score[0][0],
  }
]
    }
    return val


@app.route("/getdtnetwork")
def getDTNetwork():
    icon_list = ["&#xf049","&#xe04b"]
    dt_list = analyticsSupportService.getDTTypes()
    print(len(dt_list))
    if len(dt_list) > 0:
        nodes = [
            {"name": "DT "+str(dt[0]), "size": 40, "color": "green" if dt[1] == "n" else "yellow" if dt[1] == "c" else "red" if dt[1] == "m" else "gray" , "label": "true", "icon": random.choice (icon_list)}
        for dt in dt_list]
    else:
        dt_details = analyticsSupportService.getDTDetails()
        nodes = [
            {"name": "DT "+str(dt[0]), "size": 40, "color": "gray" , "label": "true", "icon": random.choice (icon_list)}
        for dt in dt_details]

    nodes_dict = {}
    for n in nodes:
        key = n["name"].split(" ")[1]
        nodes_dict[key] = n

    dt_subs = analyticsSupportService.getDTSubs()
    edges = [
        { "source": e[0], "target": e[1], "width": 2, "color": "black" }
    for e in dt_subs]

    edges_dict = {}
    for i,e in enumerate(edges):
        key = "edge"+str(i)
        edges_dict[key] = e 

    # print(nodes2)
    # nodes = {
    # 1: { "name": "DT 1", "size": 40, "color": "gray", "label": "true", "icon": "&#xf049" },
    # 2: { "name": "DT 2", "size": 40, "color": "green", "label": "true", "icon": "&#xe04b"},
    # 3: { "name": "DT 3", "size": 40, "color": "orange", "label": "true", "icon": "&#xf049" },
    # 4: { "name": "DT 4", "size": 40, "color": "green", "label": "true", "icon": "&#xe04b" },
    # 5: { "name": "DT 5", "size": 40, "color": "red", "label": "true", "icon": "&#xf049" },
    # }
    # edges = {
    # "edge1": { "source": "1", "target": "2", "width": 2, "color": "black" },
    # "edge2": { "source": "2", "target": "3", "width": 2, "color": "black" },
    # "edge3": { "source": "3", "target": "4", "width": 2, "color": "black" },
    # "edge4": { "source": "4", "target": "1", "width": 2, "color": "black" },
    # "edge5": { "source": "5", "target": "2", "width": 2, "color": "black" },
    # "edge6": { "source": "3", "target": "1", "width": 2, "color": "black" },
    # "edge7": { "source": "4", "target": "5", "width": 2, "color": "black" },
    # }
    # layout = {
    #     "nodes": {
    #         1: { "x": 0, "y": 0 },
    #         2: { "x": 80, "y": 80 },
    #         3: { "x": 160, "y": 0 },
    #         4: { "x": 240, "y": 80 },
    #         5: { "x": 320, "y": 0 },
    #     },
    # }

    res = {
        "nodes" : nodes_dict,
        "edges" : edges_dict,
        # "layout": layout
    }

    return res

@app.route("/gettrustscores")
def getTrustScores():
    dt_id = request.args.get('dtid')
    print(dt_id)
    ret_value = analyticsSupportService.getDTTrustScores(dt_id)
    trust_scores = []
    iteration_ids = []
    for t in ret_value:
        trust_scores.append(round(t[6], 2))
        iteration_ids.append(t[1])

    # print(iteration_ids)
    val = {
        "series": [
            {
                "name": 'Trust Score',
                "data": trust_scores
            }
        ],
        "labels": iteration_ids
    }
    return val

@app.route("/gettrustscoreseffects")
def getTrustScoresTrustEffects():
    dt_id = request.args.get('dtid')
    res_t_effects = analyticsSupportService.getDTTrustEffect(dt_id)
    res_t_scores = analyticsSupportService.getDTTrustScores(dt_id)
    trust_scores = []
    trust_effects = []
    iteration_ids = []
    for t in res_t_scores:
        trust_scores.append(round(t[6], 2))
        iteration_ids.append(t[1])

    for t in res_t_effects:
        trust_effects.append(round(t[2], 2))
    chartData = {
        "series": [
            {
            "name": 'Trust Score (%)',
            "data": trust_scores
            },

            {
            "name": 'Trust Effect',
            "data": trust_effects
            }
        ],
        "labels": iteration_ids
        }
    return chartData

@app.route("/typescount")
def DTTypeCount():
    dt_id = request.args.get('dtid')
    ret_type_counts = analyticsSupportService.getDTTypeCounts(dt_id)
    type_count = [0,0,0,0]
    for i in ret_type_counts:
        if i[0] == "n":
            type_count[0] = i[1]
        elif i[0] == "c":
            type_count[1] = i[1]
        elif i[0] == "m":
            type_count[2] = i[1]
        else:
            type_count[3] = 1

    chartData = {
        "series": type_count,
        "labels": ['Normal', 'Unpredictable', 'Malicious', 'Unknown']
    }
    return chartData




def start_server(args):
    app.run(host='0.0.0.0',port=9001,use_reloader=False)

def main(args):
    start_server(args)

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    #parser.add_argument('-a')
    #args = parser.parse_args()
    args = ""
    main(args)
        
