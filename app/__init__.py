try:
	from flask import Flask
	app = Flask(__name__)
except Exception as e:
	print("No flask installed!")

try:
	from app import route
except Exception as e:
	print ("route import failed!")
