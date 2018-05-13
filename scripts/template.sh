#!/usr/bin/env bash

# Run this script before you do anything else with espcap
# to make sure all dates are properly mapped to date types
# in Elasticsearch.

if [[ $# -ne 1 ]] ; then
    echo "usage: template.sh node"
    exit
fi

curl --header "content-type: application/JSON" -XPUT 'http://'$1'/_template/packets-template' -d '{
    "template": "packets-*",
    "mappings": {
        "_default_": {
            "dynamic_date_formats" : [
                "yyyy-MM-dd HH:mm:SS"
            ]
        }
    }
}'

echo
