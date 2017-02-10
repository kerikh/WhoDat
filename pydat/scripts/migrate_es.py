#!/usr/bin/env python

import sys
import os
import json
import time
import argparse
import threading
from threading import Event
import Queue
import elasticsearch
from elasticsearch import helpers
from elasticsearch_populate import connectElastic, configTemplate,\
                                   optimizeIndexes, unOptimizeIndexes,\
                                   WHOIS_META_FORMAT_STRING,\
                                   WHOIS_ORIG_WRITE_FORMAT_STRING,\
                                   WHOIS_DELTA_WRITE_FORMAT_STRING,\
                                   WHOIS_ORIG_SEARCH_FORMAT_STRING,\
                                   WHOIS_DELTA_SEARCH_FORMAT_STRING

read_docs = 0
written_docs = 0


def progressThread(stop, total_docs):
    maxLength = len(str(total_docs))
    format_string = "\rTotal: %%.%dd\t[%%.%dd/%%.%dd]" % (maxLength, maxLength, maxLength)
    while not stop.isSet():
        sys.stdout.write(format_string % (total_docs, read_docs, written_docs))
        sys.stdout.flush()
        time.sleep(.2)

    sys.stdout.write(format_string % (total_docs, read_docs, written_docs))
    sys.stdout.write("\n")
    sys.stdout.flush()

def rollOverAlias(es, alias, add_aliases, max_docs):
    try:
        body = {"conditions": {"max_docs": max_docs}}

        if add_aliases is not None:
            body['aliases'] = add_aliases

        result = es.indices.refresh(index=alias)
        result = es.indices.rollover(alias=alias, body = body)
    except Exception as e:
        sys.stderr.write("Error attempting rollover %s\n" % (str(e)))

def bulkThread(scanFinished, des, dest, bulkQueue, add_aliases, max_docs, bulkOpts):
    global written_docs
    def bulkIter():
        while not (scanFinished.isSet() and bulkQueue.empty()):
            try:
                req = bulkQueue.get_nowait()
            except Queue.Empty:
                time.sleep(.01)
                continue

            yield req

    for success, response in helpers.parallel_bulk(des, bulkIter(), thread_count=bulkOpts['threads'], chunk_size=bulkOpts['size']):
        written_docs += 1
        if not success:
            sys.stdout.write("Error: %s\n" % response)
        if (max_docs is not None) and (written_docs % max_docs == 0):
            rollOverAlias(des, dest, add_aliases, max_docs)

def scanThread(scanFinished, es, source, dest, bulkQueue, preserveID):
    global read_docs
    for doc in helpers.scan(es, index=source):
        _id = doc['_id']
        _type = doc['_type']
        _source = doc['_source']

        bulkRequest = {
            '_op_type': 'index',
            '_index': dest,
            '_type': _type,
            '_source': _source
        }

        if preserveID:
            bulkRequest['_id'] = _id

        read_docs += 1
        bulkQueue.put(bulkRequest)

    scanFinished.set()

def copyIndices(total_docs, es, des, source, dest, max_docs=None, preserveID=True, add_aliases=None, bulkOpts=None):
    scanFinished = Event()
    stop = Event()

    global read_docs, written_docs
    read_docs = 0
    written_docs = 0

    bulkQueue = Queue.Queue(maxsize=10000)

    progress_thread = threading.Thread(target=progressThread, args=(stop, total_docs))
    progress_thread.start()

    # Start up bulk thread
    bulk_thread = threading.Thread(target=bulkThread, args=(scanFinished, des, dest, bulkQueue, add_aliases, max_docs, bulkOpts))
    bulk_thread.start()

    scan_thread = threading.Thread(target=scanThread, args=(scanFinished, es, source, dest, bulkQueue, preserveID))
    scan_thread.start()

    scan_thread.join()
    bulk_thread.join()
    stop.set()
    progress_thread.join()


def main():
    parser = argparse.ArgumentParser(description="Script to migrate previous format 'delta' indexes to new format")

    parser.add_argument("-u", "--es-uri", nargs="*", dest="source_uri",
        default=['localhost:9200'], help="Location(s) of ElasticSearch server (e.g., foo.server.com:9200) can take multiple endpoints")
    parser.add_argument("-p", "--index-prefix", action="store", dest="index_prefix",
        default='whois', help="Index prefix to use in ElasticSearch (default: whois)")

    parser.add_argument("-d", "--dest-es-uri", nargs="*", dest="dest_uri",
        default=['localhost:9200'], help="Location(s) of destination ElasticSearch server (e.g., foo.server.com:9200) can take multiple endpoints")
    parser.add_argument("-n", "--dest-index-prefix", action="store", dest="dest_index_prefix",
        default='whois', help="Index prefix to use in destination ElasticSearch (default: whois)")
    parser.add_argument("-r", "--rollover-size", action="store", type=int, dest="rollover_docs",
        default=1000000000, help="Set the number of documents after which point a new index should be created, defaults to 1 billion, note that this is fuzzy so should be reasonably below 2,147,483,519 per ES shard")

    parser.add_argument("--bulk-threads", type=int, dest="bulk_threads", default=4, help="Number of bulk threads to use with destination ES cluster")
    parser.add_argument("--bulk-size", type=int, dest="bulk_size", default=1000, help="Number of records to batch when making bulk requests")

    options = parser.parse_args()

    bulk_options = {'threads': options.bulk_threads,
                    'size': options.bulk_size}

    data_template = None
    template_path = os.path.dirname(os.path.realpath(__file__))

    try:
        with open("%s/es_templates/data.template" % template_path, 'r') as dtemplate:
            data_template = json.loads(dtemplate.read())
    except Exception as e:
        sys.stderr.write("Unable to read data template\n")
        sys.exit(1)

    major = elasticsearch.VERSION[0]
    if major != 5:
        sys.stderr.write("Python ElasticSearch library version must coorespond to version of ElasticSearch being used -- Library major version: %d\n" % (major))
        sys.exit(1)

    try:
        source_es = connectElastic(options.source_uri)
    except elasticsearch.exceptions.TransportError as e:
        sys.stderr.write("Unable to connect to ElasticSearch ... %s\n" % (str(e)))
        sys.exit(1)

    try:
        dest_es = connectElastic(options.dest_uri)
    except elasticsearch.exceptions.TransportError as e:
        sys.stderr.write("Unable to connect to ElasticSearch ... %s\n" % (str(e)))
        sys.exit(1)

    try:
        es_version = [int(i) for i in dest_es.cat.nodes(h='version').split('.')]
    except Exception as e:
        sys.stderr.write("Unable to retrieve destination ElasticSearch version ... %s\n" % (str(e)))
        sys.exit(1)

    if es_version[0] < 5 or (es_version[0] >= 5 and es_version[1] < 2):
        sys.stderr.write("Destination ElasticSearch version must be 5.2 or greater\n")
        sys.exit(1)

    try:
        doc = source_es.get(index="@%s_meta" % (options.index_prefix), id=0)
        if 'deltaIndexes' not in doc['_source'] or not doc['_source']['deltaIndexes']:
            sys.stderr.write("Cannot migrate data which is not using delta indexes")
            sys.exit(1)
    except:
        sys.stderr.write("Unable to fetch data from metadata index")
        sys.exit(1)


    global WHOIS_META, WHOIS_ORIG_WRITE, WHOIS_DELTA_WRITE, WHOIS_ORIG_SEARCH, WHOIS_DELTA_SEARCH

    WHOIS_META          = WHOIS_META_FORMAT_STRING % (options.dest_index_prefix)
    WHOIS_ORIG_WRITE    = WHOIS_ORIG_WRITE_FORMAT_STRING % (options.dest_index_prefix)
    WHOIS_DELTA_WRITE   = WHOIS_DELTA_WRITE_FORMAT_STRING % (options.dest_index_prefix)
    WHOIS_ORIG_SEARCH   = WHOIS_ORIG_SEARCH_FORMAT_STRING % (options.dest_index_prefix)
    WHOIS_DELTA_SEARCH  = WHOIS_DELTA_SEARCH_FORMAT_STRING % (options.dest_index_prefix)

    # Initialize template in destination cluster
    configTemplate(dest_es, data_template, options.dest_index_prefix)

    # Create Metadata Index
    dest_es.indices.create(index=WHOIS_META, body = {"settings" : {
                                                            "index" : {
                                                                "number_of_shards" : 1,
                                                                "analysis" : {
                                                                    "analyzer" : {
                                                                        "default" : {
                                                                            "type" : "keyword"
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    })

    # Create the first whois rollover index
    index_name = "%s-000001" % (options.index_prefix)
    dest_es.indices.create(index=index_name,
                        body = {"aliases":{
                                    WHOIS_ORIG_WRITE: {},
                                    WHOIS_ORIG_SEARCH: {}
                               }
                        })

    # Create the first whois delta rollover index
    delta_name = "%s-delta-000001" % (options.index_prefix)
    dest_es.indices.create(index=delta_name,
                        body = {"aliases":{
                                    WHOIS_DELTA_WRITE: {},
                                    WHOIS_DELTA_SEARCH: {}
                               }
                        })


    optimizeIndexes(dest_es)

    try:
        meta_count = source_es.count(index="@%s_meta" % (options.index_prefix))['count']
    except:
        sys.stderr.write("Unable to get number of entries\n")
        sys.exit(1)


    sys.stdout.write("Migrating Metadata Index ... \n")
    # Copy over metadata
    copyIndices(meta_count, source_es, dest_es, "@%s_meta" % (options.index_prefix), WHOIS_META, bulkOpts=bulk_options)
    sys.stdout.write("Done\n")

    try:
        delta_count = source_es.count(index="%s-*-d" % (options.index_prefix))['count']
    except:
        sys.stderr.write("Unable to get number of metadata entries\n")
        sys.exit(1)

    sys.stdout.write("Migrating Delta Indices ... \n")
    # Copy over delta data
    copyIndices(delta_count, source_es, dest_es, "%s-*-d" % (options.index_prefix), WHOIS_DELTA_WRITE, max_docs=options.rollover_docs, preserveID=False, add_aliases={WHOIS_DELTA_SEARCH:{}}, bulkOpts=bulk_options)
    sys.stdout.write("Done\n")

    try:
        orig_count = source_es.count(index="%s-*-o" % (options.index_prefix))['count']
    except:
        sys.stderr.write("Unable to get number of metadata entries\n")
        sys.exit(1)

    sys.stdout.write("Migrating Original Indices ... \n")
    # Copy over original data
    copyIndices(orig_count, source_es, dest_es, "%s-*-o" % (options.index_prefix), WHOIS_ORIG_WRITE, max_docs=options.rollover_docs, preserveID=True, add_aliases={WHOIS_ORIG_SEARCH:{}}, bulkOpts=bulk_options)
    sys.stdout.write("Done\n")

    unOptimizeIndexes(dest_es, data_template)

if __name__ == "__main__":
    main()
