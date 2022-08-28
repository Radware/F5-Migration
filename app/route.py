#!/usr/bin/python

from flask import Flask, render_template, request, send_file, redirect, flash
from werkzeug.utils import secure_filename
import re, os, datetime, tarfile
from app import app
from app.f5_mig import *

@app.route('/',  endpoint='home', methods = ['GET'])
def home():
  return render_template('homepage.html')

@app.route('/validate_name', methods=['POST'])
@app.route('/validate_name.js')
def validate_js():
    if request.method == 'GET':
        return send_file('validate_name.js')
    elif request.method == 'POST':
       check_user_file = str(request.form['ProjectName'])
       if not check_user_file:
           return render_template('file_status.html', file_status="empty")
       elif os.path.isfile("app/%s.tar" % (check_user_file)) == True:
           return render_template('file_status.html', file_status="error")
       else:
           return render_template('file_status.html', file_status="ok")

@app.route('/jquery-1.11.2.min.js')
def jquery():
    return send_file('jquery-1.11.2.min.js')

@app.route('/f5_tmsh_finish',  endpoint='f5_tmsh_finish', methods = ['GET'])
def f5_tmsh_finish():
  filename=request.args.get('filename')+'.tar'
  try:
    return send_file(os.path.join(filename), attachment_filename=filename, as_attachment=True)
  except Exception as e:
    return str(e)

@app.route('/f5_tmsh_uploader', endpoint='f5_tmsh_uploader', methods = ['GET', 'POST'])
def f5_tmsh_uploader():
  if request.method == 'GET':
    return render_template('f5_tmsh_upload.html')
  if request.method == 'POST':
    uploaded_files = request.files.getlist("configfile")
    projectName=str(request.form['ProjectName'])
    #print (request.form)
    ## check if the post request has the file part
    # if user does not select file, browser also
    # submit a empty part without filename
    #file = request.files['file']
    files2run=''
    for file in uploaded_files:
      #print (file.filename)
      if not file:
        flash('No file part')
        return redirect(request.url)
      if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
      filename = secure_filename(file.filename)
      path_name=os.path.join('app/', filename)
      if os.path.exists(path_name):
        path_name+=datetime.datetime.now().strftime("%y_%m_%d_%H_%M")
      file.save(path_name)
      files2run=files2run+'$val$'+path_name
    #return '<!doctype html>\r\n    <title>Upload</title>\r\n    <h1> File uwas successfully uploaded!</h1>\r\n    <a href="/f5_start?filename='+files2run+'&projectName='+projectName+'">To run the script</a>'
    return redirect('/f5_start?filename='+files2run+'&projectName='+projectName)

@app.route('/f5_start',  endpoint='f5start', methods = ['GET'])
def f5start():
	return fun_f5_mig( request.args.get('filename'), request.args.get('projectName'), 1)
