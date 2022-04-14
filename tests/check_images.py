# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import logging
import re
import requests
import time

from reprounzip.parameters import _bundled_parameters
from reprounzip.utils import itervalues, iteritems, PY3


if PY3:
    from urllib.parse import urlencode
else:
    from urllib import urlencode


logger = logging.getLogger(__name__)


def _vagrant_req(method, url, json):
    headers = {'User-Agent': 'reprozip testsuite'}
    if json:
        headers['Accept'] = 'application/json'
    for _ in range(5):
        res = requests.request(
            method,
            url,
            headers=headers,
            allow_redirects=True,
        )
        if res.status_code == 429:
            logger.info("(got 429, sleeping)")
            time.sleep(60)
        else:
            return res


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
        metadata = _vagrant_req(
            'GET',
            url,
            True,
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
            res = _vagrant_req(
                'HEAD',
                url,
                False,
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


def list_docker_tags(repository, token=None):
    headers = {}
    if token is not None:
        headers['Authorization'] = 'Bearer %s' % token
    res = requests.get(
        'https://%s/v2/%s/%s/tags/list' % (
            repository[0], repository[1], repository[2],
        ),
        headers=headers,
    )
    if token is None and res.status_code == 401:
        # Authenticate
        m = re.match(
            r'Bearer realm="([^"]+)",service="([^"]+)"',
            res.headers['www-authenticate'],
        )
        if m is None:
            res.raise_for_status()
        scope = 'repository:%s/%s:pull' % (repository[1], repository[2])
        res = requests.get(
            m.group(1) + '?' + urlencode({
                'service': m.group(2),
                'scope': scope,
            }),
        )
        res.raise_for_status()
        token = res.json()['token']
        # Try again with token
        return list_docker_tags(repository, token)

    res.raise_for_status()

    return res.json()['tags']


def check_docker():
    error = False

    # Get all Docker images from bundled parameters
    images = set()
    for distribution in itervalues(
        _bundled_parameters['docker_images']['images'],
    ):
        for version in distribution['versions']:
            images.add(version['image'])

    # Rewrite images in canonical format, organize by repository
    repositories = {}
    for image in images:
        image = image.split('/')
        if ':' in image[-1]:
            image[-1], tag = image[-1].split(':', 1)
        else:
            tag = 'latest'
        if len(image) == 1:
            image = ['index.docker.io', 'library'] + image
        elif len(image) == 2:
            image = ['index.docker.io'] + image
        repositories.setdefault(tuple(image[:3]), set()).add(tag)

    # Check that each repository has the required tags
    for repository, tags in iteritems(repositories):
        try:
            actual_tags = list_docker_tags(repository)
        except requests.HTTPError as e:
            logger.error(
                "Docker repository not found: %d %s",
                e.response.status_code,
                e.request.url,
            )
            error = True
            continue
        actual_tags = set(actual_tags)
        for tag in tags:
            if tag not in actual_tags:
                logger.error(
                    "Docker repository %s missing tag %s",
                    '/'.join(repository),
                    tag,
                )
                error = True
            else:
                logger.info(
                    "Docker image ok: %s:%s",
                    '/'.join(repository),
                    tag,
                )

    if error:
        raise AssertionError("Missing Docker boxes")
