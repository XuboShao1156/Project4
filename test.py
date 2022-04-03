#!/bin/bash
import os

files = {
    'project4.php': 'https://david.choffnes.com/classes/cs4700sp22/project4.php',
    '2MB.log': 'https://david.choffnes.com/classes/cs4700sp22/2MB.log',
    '10MB.log': 'https://david.choffnes.com/classes/cs4700sp22/10MB.log',
    '50MB.log': 'https://david.choffnes.com/classes/cs4700sp22/50MB.log',
}

for f, l in files.items():
    print('testing {}...'.format(f))

    os.system('sudo python3 main.py {} > /dev/null'.format(l))
    os.system('wget -O gold_{} -q --content-on-error {}'.format(f, l))

    get = os.popen('md5sum ' + f).read().split()[0]
    want = os.popen('md5sum gold_' + f).read().split()[0]

    if get == want:
        print("{} passed!".format(f))
    else:
        print("{}: want '{}', but get '{}!'".format(f, want, get))

    os.system('rm {} gold_{}'.format(f, f))
    print()
