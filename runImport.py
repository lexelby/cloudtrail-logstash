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
# == runImport.py
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

import cloudtrailImporter
import argparse

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
parser.add_argument('--es-server', type=str, default='127.0.0.1:9200',
                    dest='esServer',
                    help='List of es servers inc port (eg. localhost:9200)')
parser.add_argument('--import-sqs', default=False, type=str,
                    dest='sqsQueueName',
                    help='Initiate SQS import from queue name')
parser.add_argument('--sqs-region', default='us-east-1', type=str,
                    dest='sqsRegion',
                    help='Region queue is located (Default: us-east-1)')
parser.add_argument('--sqs-number-of-messages', default=0, type=int,
                    dest='numberOfMessages',
                    help='Number of messages to consume before exiting. (Default: all)')
args = parser.parse_args()


ci = cloudtrailImporter.cloudtrailImporter(esServer=args.esServer,
                                            dryRun=args.dryrun)
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
                            sqsRegion=args.sqsRegion)
if args.sqsQueueName and args.numberOfMessages > 0:
    ci.getJobFromSQS(sqsQueueName=args.sqsQueueName,
                        sqsRegion=args.sqsRegion,
                        messageCount=args.numberOfMessages)

