import os
import sys
import json
import fileinput

from collections import OrderedDict
from operator import itemgetter

def _readline():
    for line in fileinput.input():
        yield line
    while True:
        yield None


class Reader(object):
    def __init__(self):
        self.progress = 0
        self.buffer = []
        self._readline = _readline()

    def readline(self):
        if self.buffer:
            return self.buffer.pop()
        else:
            self.progress += 1
            return next(self._readline)

    def readline_filtered(self):
        line = self.readline()
        while (
                line is not None and (
                    line.startswith('#') or
                    not line
                )
        ):
            line = self.readline()
        return line

    def push_back(self, line):
        line is not None and self.buffer.insert(0, line)


class Event(object):
    __slots__ = ['event', 'bytes_req', 'bytes_alloc', 'pages_alloc']
    def __init__(self, event, bytes_req=0, bytes_alloc=0, pages_alloc=0):
        self.event = event
        self.bytes_req = bytes_req
        self.bytes_alloc = bytes_alloc
        self.pages_alloc = pages_alloc


class Node(object):
    __slots__ = ['bytes_req', 'bytes_alloc', 'pages_alloc']

    def __init__(self, name):
        self.bytes_req = 0
        self.bytes_alloc = 0
        self.pages_alloc = 0
        self.callsites = {
            # func_foo/+0x80: <Tracepoint>
            # func_bar/+0xf0: <Tracepoint>
        }

    def update(self, evnet: Event):
        self.bytes_req += event.bytes_req
        self.bytes_alloc += event.bytes_alloc
        self.pages_alloc += event.pages_alloc

    def as_dict(self, depth=3):
        _dict = {
            'bytes_req': self.bytes_req,
            'bytes_alloc': self.bytes_alloc,
            'pages_alloc': self.pages_alloc,
        }

        if depth > 0:
            depth -= 1
            _dict['callsites'] = dict(
                (k, v.as_dict(depth=depth))
                for k, v in self.callsites.items())
        else:
            _dict['callsites'] = "...truncated..."
        return _dict


class Tracepoint(Node):
    def __init__(self, callsite):
        super(Tracepoint, self).__init__(callsite)
        self.callsite = callsite  # Func name or addr
        self.events = None

    def as_dict(self, *args, **kwargs):
        _dict = super(Tracepoint, self).as_dict(*args, **kwargs)
        _dict['callsite'] = self.callsite
        return _dict


class Task(Node):
    total_alloc = 0
    total_free = 0

    def __init__(self, name):
        super(Task, self).__init__(name)
        self.name = name
        self.events = {}

    def update(self, event: Event):
        super(Task, self).update(event)

    def as_dict(self, *args, **kwargs):
        _dict = super(Task, self).as_dict(*args, **kwargs)
        _dict['name'] = self.name
        return _dict


SELF_PID = "%s" % os.getpid()
Tasks = {}

task = None
event = None
reader = Reader()

while True:
    try:
        line = reader.readline_filtered()
        if line is None:
            break

        task_info, event_info = line.split(': ', 1)
        task_n_pid, cpu, flags, timestamp = task_info.split()

        # if task_n_pid.endswith(SELF_PID):
        #     pass

        if event_info.strip() == '<stack trace>':
            if not event or not task:
                # Stack track without event, can't handle it
                # TODO
                raise RuntimeError()

            stacktrace = []
            line = reader.readline_filtered()
            while line is not None and line.strip().startswith('=>'):
                callsite = line.lstrip(' => ')
                stacktrace.insert(0, callsite)
                line = reader.readline_filtered()

            reader.push_back(line)
            tracepoint = task
            for callsite in stacktrace:
                tracepoint = tracepoint.callsites.setdefault(callsite, Tracepoint(callsite))
                tracepoint.update(event)

            if tracepoint.events:
                tracepoint.events.append(event)
            else:
                tracepoint.events = [event]

            event, task = None, None

        else:
            if event and task:
                # Previous event not handled, stacktrace not enabled, currently only works with stacktrace
                # TODO
                pass

            event, callsite, *args = event_info.split()
            ptr, bytes_req, bytes_alloc, gfp_flag = None, 0, 0, 0
            if event == 'kmem_cache_alloc:':
                ptr, bytes_req, bytes_alloc, gfp_flag = args
                bytes_req = int(bytes_req.split('=')[1])
                bytes_alloc = int(bytes_alloc.split('=')[1])
            elif event == 'kmalloc:':
                ptr, bytes_req, bytes_alloc, gfp_flag = args
                bytes_req = int(bytes_req.split('=')[1])
                bytes_alloc = int(bytes_alloc.split('=')[1])

            task = Tasks.setdefault(task_n_pid, Task(task_n_pid))
            event = Event(event, bytes_req, bytes_alloc)
            task.update(event)
    except Exception as error:
        print("Got error during processing line: {}".format(line))
        raise error

result = dict((k, v.as_dict(3)) for k, v in Tasks.items())

ordered_rec = OrderedDict(sorted(result.items(), key=lambda item:item[1]['bytes_alloc'], reverse=True))

print(
    json.dumps(ordered_rec, indent=' ')
)
