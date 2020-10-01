import jbxapi
import base64
import io
import json
import logging
import sys
import zipfile
import re

from urllib.parse import urljoin
from pymisp import MISPAttribute, MISPEvent


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
fmt = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
sh.setFormatter(fmt)
log.addHandler(sh)

moduleinfo = {
    "version": "1.0",
    "author": "Joe Security LLC",
    "description": "Submit files and URLs to Joe Sandbox",
    "module-type": ["expansion", "hover"]
}
moduleconfig = [
    "apiurl",
    "apikey",
    "accept-tac",
    "report-cache",
    "systems",
    "secondary-results",
    "localized-internet-country",
    "ssl-inspection",
    "analysis-time",
    "tags"
]

mispattributes = {
    "input": ["attachment", "malware-sample", "url", "domain"],
    "output": ["link"],
    "format": "misp_standard"
}


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    apiurl = request["config"].get("apiurl") or "https://jbxcloud.joesecurity.org/api"
    apikey = request["config"].get("apikey")

    # systems
    systems = request["config"].get("systems") or ""
    systems = [s.strip() for s in re.split(r"[\s,;]", systems) if s.strip()]

    # tags
    tags = request["config"].get("tags") or ""
    tags = [s.strip() for s in re.split(r"[\s,;]", tags) if s.strip()]

    # others
    lia = request["config"].get("localized-internet-country") or ""
    analysis_time = request["config"].get("analysis-time") or 120

    try:
        accept_tac = _parse_bool(request["config"].get("accept-tac"), "accept-tac")
        report_cache = _parse_bool(request["config"].get("report-cache"), "report-cache")
        secondary_results = _parse_bool(request["config"].get("secondary-results"), "secondary-results")
        ssl_inspection = _parse_bool(request["config"].get("ssl-inspection"), "ssl-inspection")
    except _ParseError as e:
        return {"error": str(e)}

    comments = {
        "source": "misp",
        "event_id": request["event_id"],
        "attribute_id": request["attribute"]["id"],
        "attribute_uuid": request["attribute"]["uuid"],
        "attribute_type": request["attribute"]["type"],
        "attribute_category": request["attribute"]["category"]
    }

    params = {
        "report-cache": report_cache,
        "systems": systems,
        "secondary-results": secondary_results,
        "localized-internet-country": lia,
        "ssl-inspection": ssl_inspection,
        "analysis-time": analysis_time,
        "comments": json.dumps(comments),
        "tags": tags
    }

    if not apikey:
        return {"error": "No API key provided"}

    joe = jbxapi.JoeSandbox(apiurl=apiurl, apikey=apikey, user_agent="MISP joesandbox_submit", accept_tac=accept_tac)

    try:
        is_url_submission = "url" in request or "domain" in request

        if is_url_submission:
            url = request.get("url") or request.get("domain")

            log.info("Submitting URL: %s", url)
            result = joe.submit_url(url, params=params)
        else:
            attr_type = request['attribute']['type']
            attr_value = request['attribute']['value']
            attr_data = request['attribute']['data']

            if attr_type == "malware-sample":
                filename = attr_value.split("|", 1)[0]
                data = _decode_malware(attr_data, True)
            elif attr_type == "attachment":
                filename = attr_value
                data = _decode_malware(attr_data, False)

            data_fp = io.BytesIO(data)
            log.info("Submitting sample: %s", filename)
            result = joe.submit_sample((filename, data_fp), params=params)

        assert "submission_id" in result
    except jbxapi.JoeException as e:
        log.error("ERROR: %s" % str(e))
        return {"error": str(e)}

    link_to_analysis = urljoin(apiurl, "../submissions/{}".format(result["submission_id"]))

    attribute = MISPAttribute()
    attribute.from_dict(**{'type': 'link', 'value': link_to_analysis, 'to_ids': False})
    misp_event = MISPEvent()
    misp_event.add_attribute(**attribute)
    event = json.loads(misp_event.to_json())
    results = {key: event[key] for key in ('Attribute', 'Object', 'Tag') if (key in event and event[key])}
    log.debug(results)
    return {'results': results} 
    


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def _decode_malware(data, is_encrypted):
    data = base64.b64decode(data)

    if is_encrypted:
        with zipfile.ZipFile(io.BytesIO(data)) as zipf:
            data = zipf.read(zipf.namelist()[0], pwd=b"infected")

    return data


class _ParseError(Exception):
    pass


def _parse_bool(value, name="bool"):
    if value is None or value == "":
        return None

    if value == "true":
        return True

    if value == "false":
        return False

    raise _ParseError("Cannot parse {}. Must be 'true' or 'false'".format(name))
