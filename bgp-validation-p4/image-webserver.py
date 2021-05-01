from http.server import *
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument('--img_path', default="legit-duck.jpg")
FLAGS = parser.parse_args()

class Handler(SimpleHTTPRequestHandler):

    path_to_image = FLAGS.img_path
    img = open(path_to_image, 'rb')
    statinfo = os.stat(path_to_image)
    img_size = statinfo.st_size

    print("Image size: %sB"%(img_size))

    # Disable logging DNS lookups
    def address_string(self):
        return str(self.client_address[0])
    
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "image/jpg")
        self.send_header("Content-length", img_size)
        self.end_headers()

    def do_GET(self):
        path_to_image = FLAGS.img_path
        img = open(path_to_image, 'rb')
        statinfo = os.stat(path_to_image)
        img_size = statinfo.st_size

        self.send_response(200)
        self.send_header("Content-type", "image/jpg")
        self.send_header("Content-length", img_size)
        self.end_headers()
        f = open(path_to_image, 'rb')
        self.wfile.write(f.read())
        f.close()
        # self.wfile.flush()


PORT = 80
httpd = HTTPServer(("", PORT), Handler)
httpd.serve_forever()
