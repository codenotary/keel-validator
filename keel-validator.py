#!/usr/bin/python3
# Copyright 2022 Codenotary Inc. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#         http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import urllib.request
import argparse
import base64
import json
from dateutil.parser import isoparse
import datetime
import pytz
import subprocess
import logging
import time

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
parser = argparse.ArgumentParser(description="keel vcn-based approver service")
parser.add_argument('--service', required=True, help="address:port of keel service")
parser.add_argument('--username', required=True, help="keel username ")
parser.add_argument('--password', required=True, help="keel password")
parser.add_argument('--signerID', required=False, help="signed ID")
parser.add_argument('--apikey', required=True, help="TC API KEY")
parser.add_argument('--registry-username', required=False, help="docker registry username")
parser.add_argument('--registry-password', required=False, help="docker registry password ")
parser.add_argument('--registry-password-file', required=False, help="file containing docker registry password ")
parser.add_argument('--force', required=False, default=False, action='store_true', help="Force upgrade even if not authenticated")
parser.add_argument('--poll', required=False, type=int, default=0, help="Keep running, polling time")
parser.add_argument('--mm-notify-hook', required=False, help="Mattermost notification hook")

args = parser.parse_args()

if args.registry_username is not None and args.registry_password_file is not None:
    with open(args.registry_password_file) as f:
        args.registry_password = f.read()


def newAuthorizedRequest(url, username, password):
    auth_string = "{}:{}".format(username, password)
    b64auth = base64.b64encode(auth_string.encode())
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Basic {auth}".format(auth=b64auth.decode()))
    return req


def newApprovalHttpReq():
    url = "http://{service}/v1/approvals".format(service=args.service)
    req = newAuthorizedRequest(url, args.username, args.password)
    return req


def handleApproval(xID, identifier, action):
    url = "http://{service}/v1/approvals".format(service=args.service)
    req = newAuthorizedRequest(url, args.username, args.password)
    data = {"id": xID, "identifier": identifier, "action": action, "voter": "keel-validator"}
    status = None
    with urllib.request.urlopen(req, data=json.dumps(data).encode()) as resp:
        status = resp.status
    logging.info("{action} {id}: {stat}".format(action=action, id=xID, stat=status))

def processApproval(appro):
    image = appro["event"]["repository"]["name"]
    tag = appro["event"]["repository"]["tag"]
    digest = appro["event"]["repository"]["digest"]
    ref = "image://{image}@{digest}".format(image=image, digest=digest)
    vcnArgs = [
        "vcn", "authenticate",
        "--lc-host", "cnc-ci.codenotary.io",
        "--lc-api-key", args.apikey,
        ref,
    ]
    if args.registry_username is not None and args.registry_password is not None:
        vcnArgs.extend([
            "--image-registry-user", args.registry_username,
            "--image-registry-password", args.registry_password
        ])
    if args.signerID is not None:
        vcnArgs.extend(["--signerID", args.signerID])
    vcnExit = subprocess.run(vcnArgs)
    if vcnExit.returncode != 0 and not args.force:
        logging.info("image {}:{} not authenticated, stop".format(image, tag))
        return
    logging.info("image {}:{} authenticated, go go go".format(image, tag))
    handleApproval(appro["id"], appro["identifier"], "approve")
    notifyApproval(image, tag, digest)

def notifyApproval(image, tag, digest):
    if args.mm_notify_hook!=None:
        req = urllib.request.Request(args.mm_notify_hook)
        req.add_header("Content-Type","application/json")
        data = {"text": "## Keel validator:\nNew image for {image}:{tag} has been verified and deployed.\nNew digest is {digest}".format(image=image, tag=tag, digest=digest)}
        status = None
        with urllib.request.urlopen(req, data=json.dumps(data).encode()) as resp:
            status = resp.status
        logging.info("Mattermost notification, status: {status}".format(status))
        
def pollCycle():
    req = newApprovalHttpReq()
    delTreshold = datetime.datetime.now().replace(tzinfo=pytz.UTC) - datetime.timedelta(days=15)
    with urllib.request.urlopen(req) as response:
        jresp = json.load(response)
        for r in jresp:
            deadline = isoparse(r["deadline"])
            logging.info("ID: {} Archived: {} Deadline: {}".format(r["id"], r["archived"], deadline.isoformat()))
            if not r["archived"]:
                processApproval(r)
            if r["archived"] and deadline < delTreshold:
                handleApproval(r["id"], r["identifier"], "delete")


if __name__ == "__main__":
    if args.poll == 0:
        pollCycle()
    else:
        t0 = datetime.datetime.now()
        while True:
            logging.info("Starting poll")
            pollCycle()
            t0 = t0 + datetime.timedelta(seconds=args.poll)
            t1 = datetime.datetime.now()
            if t1 < t0:
                sleeptime = (t0 - t1).total_seconds()
            else:
                overshoot = (t1 - t0).total_seconds()
                sleeptime = (1 + overshoot / args.poll) * args.poll
            logging.info("sleeping {} seconds".format(sleeptime))
            time.sleep(sleeptime)
