import pyqrcode
import click

uris = open('uris.txt').readlines()

count = 0

for uri in uris:
    count += 1
    uri = uri.strip()
    if not uri:
        continue
    qr = pyqrcode.create(uri, error="H")
    qr.png(f'{count:d}.png', scale=6)



