import logging
import requests

from reprounzip.parameters import _bundled_parameters
from reprounzip.utils import itervalues


logger = logging.getLogger(__name__)


def check_vagrant():
    error = False

    # Get all Vagrant boxes from bundled parameters
    boxes = set()
    for distribution in itervalues(
        _bundled_parameters['vagrant_boxes']['boxes'],
    ):
        for version in distribution['versions']:
            for image in itervalues(version['architectures']):
                boxes.add(image)

    # Check that they exist
    for box in boxes:
        # Get metadata
        url = 'https://vagrantcloud.com/' + box
        metadata = requests.get(
            url,
            headers={
                'Accept': 'application/json',
                'User-Agent': 'reprozip testsuite',
            },
        )
        if metadata.status_code != 200:
            logger.error(
                "Vagrant box not found: %d %s",
                metadata.status_code, url,
            )
            error = True
            continue
        metadata = metadata.json()

        # Find most recent version
        versions = [
            v for v in metadata.get('versions', ())
            if v.get('status') == 'active'
        ]
        if not versions:
            logger.error("No versions for Vagrant box %s", box)
            error = True
            continue
        max_version = max(metadata['versions'], key=lambda v: v['version'])

        # Go over each provider
        for provider in max_version['providers']:
            url = provider['url']
            res = requests.head(
                url,
                headers={
                    'Accept': 'application/json',
                    'User-Agent': 'reprozip testsuite',
                },
            )
            # Status should be 200
            if res.status_code != 200:
                logger.error(
                    "Got %d getting Vagrant box %s: %s",
                    res.status_code, box, url,
                )
                error = True
            # Content-Type should not start with "text/" (but can be unset)
            elif res.headers.get('Content-Type', '').startswith('text/'):
                logger.error(
                    "Got type %s getting Vagrant box %s: %s",
                    res.headers['Content-Type'], box, url,
                )
                error = True
            # Size should be at least 10 MB
            elif int(res.headers.get('Content-Length', 1E8)) < 1E7:
                logger.error(
                    "Got file size %s getting Vagrant box %s: %s",
                    res.headers['Content-Length'], box, url,
                )
                error = True
            else:
                logger.info("Vagrant box ok: %s (%s)", box, provider['name'])

    if error:
        raise AssertionError("Missing Vagrant boxes")


def check_docker():
    pass
