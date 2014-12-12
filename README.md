cloudtrailImporter

Tool to import AWS cloudtrail logs into Elasticsearch and allow them to be filtered/visualised in Kibana.

Script requires the python modules listed in requirements.txt and environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION)

Quickstart
-------

```
sudo pip install -r requirements.txt
export AWS_ACCESS_KEY_ID=<redacted>
export AWS_SECRET_ACCESS_KEY=<redacted>
export AWS_DEFAULT_REGION=us-east-1
python ./runImport.py -h
```

Help runImport.py
-------

```
usage: runImport.py [-h] [--dry-run] [--import-file SYNCFILENAME]
                    [--import-folder SYNCFOLDER] [--import-s3-file S3FILE]
                    [--import-s3-folder S3FOLDER] [--s3-bucket S3BUCKET]
                    [--es-server ESSERVER] [--import-sqs SQSQUEUENAME]
                    [--sqs-region SQSREGION]
                    [--sqs-number-of-messages NUMBEROFMESSAGES]

optional arguments:
  -h, --help            show this help message and exit
  --dry-run             Pretend to perform actions but don't do them
  --import-file SYNCFILENAME
                        Import json.gz file
  --import-folder SYNCFOLDER
                        Import all json.gz files from folder (recursive)
  --import-s3-file S3FILE
                        Perform import from s3 file
  --import-s3-folder S3FOLDER
                        Perform import from s3 file
  --s3-bucket S3BUCKET  Bucket containing the file/folder to import from
  --es-server ESSERVER  List of es servers inc port (eg. localhost:9200)
  --import-sqs SQSQUEUENAME
                        Initiate SQS import from queue name
  --sqs-region SQSREGION
                        Region queue is located (Default: us-east-1)
  --sqs-number-of-messages NUMBEROFMESSAGES
                        Number of messages to consume before exiting.
                        (Default: all)
```

License
-------
Apache 2.0


Contact
-------
Mike Fuller <mfuller@atlassian.com>

Support
-------
None provided :)
