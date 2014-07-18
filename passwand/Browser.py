'''
Functionality for retrieving the current URL being viewed in your browser. This
required starting Chromium or Chrome with the switch --remote-debugging-port.
'''

import argparse, json, sys, urllib2

def get_data(url):
    resp = urllib2.urlopen(url)
    return resp

def get_current_url(port=9222):
    data = get_data('http://localhost:%d/json' % port)
    pages = json.load(data)
    if len(pages) == 0:
        return None
    return pages[0]['url']

# For testing.
def main(argv):
    parser = argparse.ArgumentParser(
        description='retrieve the current webpage being viewed in Chrome')
    parser.add_argument('--port', '-p', type=int, default=9222,
        help='port the Chrome debugger is running on')
    opts = parser.parse_args(argv[1:])

    print get_current_url(opts.port)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
