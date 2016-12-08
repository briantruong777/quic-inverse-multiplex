import sys

sf = ''
with open(sys.argv[1], 'r') as f:
  sf = f.read()
  body_begin_pos = sf.find('\r\n\r\n') + 4
  sf = list(sf)
  sf[body_begin_pos] = chr(0)
  sf[body_begin_pos + (len(sf) - body_begin_pos) / 2] = chr(1)
  sf = ''.join(sf)
with open(sys.argv[1], 'w') as f:
  f.write(sf)
