try:
	from flask import Flask
	app = Flask(__name__)
except Exception as e:
	print("No flask installed!")

try:
	from app import route
except Exception as e:
	print ("route import failed!")


#from app import routes
#from app import lp_6_12_to_lpng
