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

import slimes
import json
import gzip
import datetime
import subprocess
import os
import requests
import requests_cache
import glob
import boto.sqs
import time
from boto.sqs.message import RawMessage
from boto.s3.connection import S3Connection
from boto.s3.key import Key
import StringIO


class cloudtrailImporter:

    def __init__(self,
                 esServer='localhost:9200',
                 mapping='{ "mappings": { "_default_": { "dynamic_templates": [ { "string_template": { "match": "*", "match_mapping_type": "string", "mapping": { "type": "string", "index": "not_analyzed" } } } ] } } }',
                 dryRun=False,
                 ):
        """
        Initialise the cloudtrailImporter

        Attributes:
        esServer (str|list): String or List of Strings containing the hostname:port of the es server(s) to upload to
        mapping (str): es mapping to set on all net indices
        dryRun (bool): if True wont do any import or SQS delete actions
        """
        self.dryRun = dryRun
        self.esServer = esServer
        self.mapping = mapping
        self.slimesRequester = slimes.Requester([self.esServer])
        self.recordsImported = 0
        requests_cache.install_cache('cloudtrailImporter', expire_after=120)

    def connectS3Bucket(self, bucket):
        """
        Initialises a connection to an AWS S3 Bucket and returns a (Boto) bucket object

        Attributes:
        bucket (str): name of the bucket to connect to.
        """
        conn = S3Connection()
        return conn.get_bucket(bucket)

    def importRecordToES(self, record):
        """
        Import event object into ElasticSearch

        Attributes:
        record (dict): Event object to be imported
        """
        if self.dryRun:
            print 'DryRun:'
            print record
            return True
        if self.recordsImported > 0 and self.recordsImported % 1000 == 0:
            print "Records Imported {0}".format(self.recordsImported)
            time.sleep(10)
            r = requests.get("http://{0}/{1}".format(self.esServer, record['@index']))
            if r.status_code != 200:
                r = requests.put("http://{0}/{1}".format(self.esServer, record['@index']), data=self.mapping)
            r.connection.close()
        try:
            self.slimesRequester.request(method="post",
                                         myindex=record['@index'],
                                         mytype=record['eventName'],
                                         mydata=record)
        except:
            print 'Error with import'
            print json.dumps(record)
            return False
        self.recordsImported += 1
        return True

    def prepareRecord(self, record):
        """
        Prepares a raw cloudtrail event to be imported into ElasticSearch.
        Adds a @timestamp key with the transformed timestamp to be used by Kibana
        Removes the eventTime key as this is not needed
        Adds a @index key for use by the importRecordToES() to know where to import the record

        Attributes:
        record (dict): original event object as read from a cloudtrail file
        """
        try:
            timestamp = datetime.datetime.strptime(record['eventTime'], '%Y-%m-%dT%H:%M:%SZ')
            record['@timestamp'] = timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            record.pop('eventTime', None)
            record['@index'] = "cloudtrail-{0}-{1:%Y}-{1:%m}".format(record['userIdentity']['accountId'], timestamp)
        except:
            print 'failed to prepare record'
        return record

    def importRecordSet(self, recordset):
        """
        Breaks a full cloudtrail recordset into individual events for import into ElasticSearch

        Attributes:
        recordset (dict): Full cloudtrail as read from file
        """
        status = False
        if 'Records' in recordset:
            for record in recordset['Records']:
                status = self.importRecordToES(self.prepareRecord(record))
                if not status:
                    return status
        else:
            print recordset
        return status

    def importLocalFile(self, filename):
        """
        Opens local file and imports the cloudtrail into ElasticSearch

        Attributes:
        filename (str): name of the file to open and import
        """
        return self.importRecordSet(json.loads(gzip.open(filename).read()))

    def importLocalFolder(self, foldername):
        """
        Opens all json.gz files in folder andimports the cloudtrails into ElasticSearch

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
        imports Boto S3 Key into ElasticSearch

        Attributes:
        key (boto.s3.Key): key object to import into ElasticSearch
        """
        return self.importRecordSet(json.loads(gzip.GzipFile(fileobj=StringIO.StringIO(key.get_contents_as_string())).read()))

    def importS3File(self, bucket, filename):
        """
        Connects to S3 bucket and imports file into ElasticSearch

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
        if(messageBody['message'] == 'CloudTrail validation message.'):
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
        path to the cloudtrail file for import to ElasticSearch

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

    def getAllJobsFromSQS(self, sqsQueueName='cloudtrail', sqsRegion='us-east-1'):
        """
        Gets cloudtrail SNS notifications from an SQS queue and reads the
        path to the cloudtrail file for import to ElasticSearch until queue is empty

        Attributes:
        sqsQueueName (str): name of the SQS queue to connect to
        sqsRegion (str): Region the SQS queue is in
        """
        status = True
        while status:
            status = self.getJobFromSQS(sqsQueueName=sqsQueueName, sqsRegion=sqsRegion)
        if status == -1:
            return False
        return True
