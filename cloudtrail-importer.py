# === Copyright
#
# Copyright 2014 Atlassian Pty Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# == cloudtrailImporter.py
#
#
#
# === Examples
#
#
#
# === Authors
#
# Mike Fuller <mfuller@atlassian.com>
#

import sys
import argparse
import socket
import json
import gzip
import datetime
import subprocess
import os
import requests
import glob
import boto.sqs
import time
from boto.sqs.message import RawMessage
from boto.s3.connection import S3Connection
from boto.s3.key import Key
import StringIO


class CloudtrailImporter:

    def __init__(self,
                 dryRun=False,
                 logstashServer=None,
                 ):
        """
        Initialise the cloudtrailImporter

        Attributes:
        esServer (str|list): String or List of Strings containing the hostname:port of the es server(s) to upload to
        mapping (str): es mapping to set on all net indices
        dryRun (bool): if True wont do any import or SQS delete actions
        """
        self.dryRun = dryRun

        if not logstashServer:
            raise Exception("no logstash server specified")

        logstashServer = logstashServer.split(':')

        self.logstash_host = logstashServer[0]
        self.logstash_port = int(logstashServer[1])
        self.recordsImported = 0

        self._init_logstash_socket()

    def connectS3Bucket(self, bucket):
        """
        Initialises a connection to an AWS S3 Bucket and returns a (Boto) bucket object

        Attributes:
        bucket (str): name of the bucket to connect to.
        """
        conn = S3Connection()
        return conn.get_bucket(bucket)

    def _init_logstash_socket(self):
        self.logstash_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logstash_socket.connect((self.logstash_host, self.logstash_port))

    def importRecordToLogstash(self, record):
        """
        Import event object into Logstash

        Attributes:
        record (dict): Event object to be imported
        """
        if self.dryRun:
            print 'DryRun:'
            print record
            return True
        if self.recordsImported > 0 and self.recordsImported % 1000 == 0:
            print "Records Imported {0}".format(self.recordsImported)

        message = json.dumps(record) + "\n"
        sent = False

        for try_num in xrange(1, 11):
            try:
                self.logstash_socket.sendall(message)
                sent = True
                break
            except socket.error, e:
                print >> sys.stderr, "socket error: %s" % e
                time.sleep(10)
                self.logstash_socket.close()
                self._init_logstash_socket()

        if not sent:
            sys.exit("Failed to send message after %d tries: %s" % (try_num, message))

        self.recordsImported += 1
        return True

    def importRecordSet(self, recordset):
        """
        Breaks a full cloudtrail recordset into individual events for import

        Attributes:
        recordset (dict): Full cloudtrail log data as read from file
        """
        status = False
        if 'Records' in recordset:
            for record in recordset['Records']:
                status = self.importRecordToLogstash(record)
                if not status:
                    return status
        else:
            print recordset
        return status

    def importLocalFile(self, filename):
        """
        Opens local file and imports the log

        Attributes:
        filename (str): name of the file to open and import
        """
        return self.importRecordSet(json.loads(gzip.open(filename).read()))

    def importLocalFolder(self, foldername):
        """
        Opens all json.gz files in folder and imports them

        Attributes:
        foldername (str): name of the folder to search (this is recursive)
        """
        for root, dirs, files in os.walk(foldername):
            for name in files:
                if name.endswith(".json.gz"):
                    status = self.importLocalFile("{0}/{1}".format(root, name))
                    if not status:
                        return status
        return status

    def importS3Key(self, key):
        """
        imports log from Boto S3 Key

        Attributes:
        key (boto.s3.Key): key object to import
        """
        return self.importRecordSet(json.loads(gzip.GzipFile(fileobj=StringIO.StringIO(key.get_contents_as_string())).read()))

    def importS3File(self, bucket, filename):
        """
        Connects to S3 bucket and imports file

        Attributes:
        bucket (str): name of the bucket the file is inside
        filename (str): name of the file in the S3 bucket to import
        """
        bucket = self.connectS3Bucket(bucket)
        key = bucket.get_key(filename)
        return self.importS3Key(key)

    def importS3Folder(self, bucket, foldername):
        """
        Connects to S3 bucket and imports all objects inside (not recursive)

        Attributes:
        bucket (str): name of the bucket the folder is inside
        foldername (str): path of the folder in the S3 bucket
        """
        bucket = self.connectS3Bucket(bucket)
        keys = bucket.list(foldername)
        status = False
        for key in keys:
            status = self.importS3Key(key)
            if not status:
                return status
        return status

    def getSQSQueue(self, sqsQueueName='cloudtrail', sqsRegion='us-east-1'):
        """
        Gets connection to SQS queue

        Attributes:
        sqsQueueName (str): name of the SQS queue to connect to
        sqsRegion (str): Region the SQS queue is in
        """
        conn = boto.sqs.connect_to_region(sqsRegion)
        sqsQueue = conn.get_queue(sqsQueueName)
        sqsQueue.set_message_class(RawMessage)
        return sqsQueue

    def releaseSQSMessage(self, message):
        """
        Put message back on SQS queue
        """
        return message.change_visibility(0)

    def importSQSMessage(self, message):
        """
        Process SQS message and import the cloudtrail it refers to

        Attributes:
        message (sqs.message): the SQS message as pulled from the queue
        """
        messageBody = json.loads(message.get_body())
        if(messageBody['Type'] == 'SubscriptionConfirmation'):
            print "SubscriptionConfirmation Awaiting"
            self.releaseSQSMessage(message)
            return False
        if(messageBody['Message'] == 'CloudTrail validation message.'):
            print 'CloudTrail validation message.'
            return True
        item = json.loads(messageBody['Message'])
        status = False
        for filename in item['s3ObjectKey']:
            print filename
            status = self.importS3File(bucket=item['s3Bucket'], filename=filename)
            if not status:
                return status
        return status

    def deleteJobFromSQS(self, sqsQueue, message):
        """
        Remove message from SQS queue

        Attributes:
        sqsQueueName (str): name of the SQS queue to connect to
        message (sqs.message): the SQS message as pulled from the queue
        """
        if self.dryRun:
            return True
        return sqsQueue.delete_message(message)

    def getJobFromSQS(self, sqsQueueName='cloudtrail', sqsRegion='us-east-1', messageCount=1):
        """
        Gets cloudtrail SNS notifications from an SQS queue and reads the
        path to the cloudtrail file for import

        Attributes:
        sqsQueueName (str): name of the SQS queue to connect to
        sqsRegion (str): Region the SQS queue is in
        messageCount (int): number of messages to consume from the queue
        """
        sqsQueue = self.getSQSQueue(sqsQueueName=sqsQueueName, sqsRegion=sqsRegion)
        rs = sqsQueue.get_messages(messageCount)
        status = 0
        for message in rs:
            status = self.importSQSMessage(message)
            if not status:
                return status
            else:
                status = self.deleteJobFromSQS(sqsQueue, message)
                if not status:
                    return -1
        return status

    def getAllJobsFromSQS(self, sqsQueueName='cloudtrail', sqsRegion='us-east-1', sqsPollInterval=None):
        """
        Gets cloudtrail SNS notifications from an SQS queue and reads the
        path to the cloudtrail file for import until queue is empty

        Attributes:
        sqsQueueName (str): name of the SQS queue to connect to
        sqsRegion (str): Region the SQS queue is in
        """
        while True:
            status = True
            while status:
                status = self.getJobFromSQS(sqsQueueName=sqsQueueName, sqsRegion=sqsRegion, messageCount=10)
            if status == -1:
                return False
            else:
                if sqsPollInterval:
                    sys.stdout.flush()
                    time.sleep(sqsPollInterval)
                else:
                    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true', dest='dryrun',
                        help="Pretend to perform actions but don't do them")
    parser.add_argument('--import-file', default=False, type=str,
                        dest='syncfilename', help='Import json.gz file')
    parser.add_argument('--import-folder', default=False, type=str,
                        dest='syncfolder',
                        help='Import all json.gz files from folder (recursive)')
    parser.add_argument('--import-s3-file', default=False, type=str,
                        dest='s3file', help='Perform import from s3 file')
    parser.add_argument('--import-s3-folder', default=False, type=str,
                        dest='s3folder', help='Perform import from s3 file')
    parser.add_argument('--s3-bucket', default=False, type=str,
                        dest='s3bucket',
                        help='Bucket containing the file/folder to import from')
    parser.add_argument('--logstash-server', type=str, default='127.0.0.1:10000',
                        dest='logstashServer',
                        help='Logstash server:port (using tcp input with json_lines codec)')
    parser.add_argument('--import-sqs', default=False, type=str,
                        dest='sqsQueueName',
                        help='Initiate SQS import from queue name')
    parser.add_argument('--sqs-region', default='us-east-1', type=str,
                        dest='sqsRegion',
                        help='Region queue is located (Default: us-east-1)')
    parser.add_argument('--sqs-number-of-messages', default=0, type=int,
                        dest='numberOfMessages',
                        help='Number of messages to consume before exiting. (Default: all)')
    parser.add_argument('--sqs-poll-interval', default=None, type=int, dest='sqsPollInterval', metavar='SECONDS',
                        help='Poll the SQS queue repeatedly, pausing SECONDS between each poll.')
    args = parser.parse_args()

    ci = CloudtrailImporter(logstashServer=args.logstashServer, dryRun=args.dryrun)
    if args.syncfilename:
        ci.importLocalFile(args.syncfilename)
    if args.syncfolder:
        ci.importLocalFolder(args.syncfolder)
    if args.s3file and args.s3bucket:
        ci.importS3File(args.s3bucket, args.s3file)
    if args.s3folder and args.s3bucket:
        ci.importS3Folder(args.s3bucket, args.s3folder)
    if args.sqsQueueName and args.numberOfMessages == 0:
        ci.getAllJobsFromSQS(sqsQueueName=args.sqsQueueName,
                             sqsRegion=args.sqsRegion,
                             sqsPollInterval=args.sqsPollInterval)
    if args.sqsQueueName and args.numberOfMessages > 0:
        ci.getJobFromSQS(sqsQueueName=args.sqsQueueName,
                         sqsRegion=args.sqsRegion,
                         messageCount=args.numberOfMessages)
