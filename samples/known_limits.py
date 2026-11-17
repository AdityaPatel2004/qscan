# Two cases where a text-search scanner is wrong. Kept on purpose for the demo.
from hashlib import md5 as h


def known_miss(data):
    # KNOWN MISS: md5 is used through the alias "h", so no pattern matches this line.
    return h(data).hexdigest()


def known_false_alarm():
    # KNOWN FALSE ALARM: the next line only prints text, but it contains a pattern.
    print("We removed hashlib.md5 from this project last year")
