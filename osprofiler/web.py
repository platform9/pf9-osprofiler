# Copyright 2014 Mirantis Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re
import uuid

import webob.dec

from osprofiler import _utils as utils
from osprofiler import profiler


# Trace keys that are required or optional, any other
# keys that are present will cause the trace to be rejected...
_REQUIRED_KEYS = ("base_id", "hmac_key")
_OPTIONAL_KEYS = ("parent_id",)

#: Http header that will contain the needed traces data.
X_TRACE_INFO = "X-Trace-Info"

#: Http header that will contain the traces data hmac (that will be validated).
X_TRACE_HMAC = "X-Trace-HMAC"

# pf9 start: W3C Trace Context support for distributed tracing
W3C_TRACEPARENT = "traceparent"

_W3C_TRACEPARENT_RE = re.compile(
    r'^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$'
)


def extract_w3c_context(headers):
    """Extract W3C trace context from request headers."""
    traceparent = headers.get(W3C_TRACEPARENT) or headers.get('Traceparent')
    if not traceparent:
        return None, None
    match = _W3C_TRACEPARENT_RE.match(traceparent.lower())
    if match:
        version, trace_id, parent_id, flags = match.groups()
        if version == "00":
            return trace_id, parent_id
    return None, None


def generate_traceparent(trace_id=None, parent_id=None, sampled=True):
    """Generate W3C traceparent header."""
    if trace_id is None:
        trace_id = uuid.uuid4().hex
    if parent_id is None:
        parent_id = uuid.uuid4().hex[:16]
    flags = "01" if sampled else "00"
    return "00-{}-{}-{}".format(trace_id, parent_id, flags)


def get_trace_id_headers():
    """Get trace headers for outgoing requests."""
    p = profiler.get()
    if p and p.hmac_key:
        headers = {}
        # pf9: add W3C traceparent 
        if p.get_id() != p.get_base_id():
            base_id = p.get_base_id().replace("-", "")
            span_id = format(utils.shorten_id(p.get_id()), '016x')
            headers[W3C_TRACEPARENT] = generate_traceparent(base_id, span_id)

        data = {"base_id": p.get_base_id(), "parent_id": p.get_id()}
        pack = utils.signed_pack(data, p.hmac_key)
        headers[X_TRACE_INFO] = pack[0]
        headers[X_TRACE_HMAC] = pack[1]
        return headers
    return {}
# pf9 end


_ENABLED = None
_HMAC_KEYS = None


def disable():
    """Disable middleware."""
    global _ENABLED
    _ENABLED = False


def enable(hmac_keys=None):
    """Enable middleware.

    :param hmac_keys: Comma-separated HMAC keys for traditional tracing.
    """
    global _ENABLED, _HMAC_KEYS
    _ENABLED = True
    _HMAC_KEYS = utils.split(hmac_keys or "")


# pf9 start: WsgiMiddleware with W3C traceparent support
class WsgiMiddleware:
    """WSGI Middleware that enables tracing for an application."""

    def __init__(self, application, hmac_keys=None, enabled=False, **kwargs):
        """Initialize middleware with api-paste.ini arguments.

        :param application: wsgi app
        :param hmac_keys: Only trace header signed with these keys will be
                          processed.
        :param enabled: Enable/disable middleware.
        :param kwargs: Other keyword arguments (ignored).
        """
        self.application = application
        self.name = "wsgi"
        self.enabled = self._str_to_bool(enabled)
        self.hmac_keys = utils.split(hmac_keys or "")

    @staticmethod
    def _str_to_bool(value):
        """Convert string to boolean (for paste.deploy config)."""
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).lower() in ('true', '1', 'yes', 'on')

    @classmethod
    def factory(cls, global_conf, **local_conf):
        def filter_(app):
            return cls(app, **local_conf)
        return filter_

    def _trace_is_valid(self, trace_info):
        if not isinstance(trace_info, dict):
            return False
        trace_keys = set(trace_info.keys())
        if not all(k in trace_keys for k in _REQUIRED_KEYS):
            return False
        if trace_keys.difference(_REQUIRED_KEYS + _OPTIONAL_KEYS):
            return False
        return True

    @webob.dec.wsgify
    def __call__(self, request):
        if (_ENABLED is not None and not _ENABLED
                or _ENABLED is None and not self.enabled):
            return request.get_response(self.application)

        trace_info = utils.signed_unpack(request.headers.get(X_TRACE_INFO),
                                         request.headers.get(X_TRACE_HMAC),
                                         _HMAC_KEYS or self.hmac_keys)

        if not self._trace_is_valid(trace_info):
            return request.get_response(self.application)

        # Use W3C trace context for cross-service correlation
        w3c_trace_id, w3c_parent_id = extract_w3c_context(request.headers)
        if w3c_trace_id:
            trace_info["base_id"] = "{}-{}-{}-{}-{}".format(
                w3c_trace_id[:8], w3c_trace_id[8:12], w3c_trace_id[12:16],
                w3c_trace_id[16:20], w3c_trace_id[20:])
            if w3c_parent_id:
                trace_info["parent_id"] = w3c_parent_id

        profiler.init(**trace_info)

        info = {
            "request": {
                "path": request.path,
                "query": request.query_string,
                "method": request.method,
                "scheme": request.scheme
            }
        }
        try:
            with profiler.Trace(self.name, info=info):
                return request.get_response(self.application)
        finally:
            profiler.clean()
# pf9 end
