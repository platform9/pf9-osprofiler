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

import json
from unittest import mock

from oslo_config import cfg

from osprofiler.drivers import otlp
from osprofiler import opts
from osprofiler.tests import test


class OTLPTestCase(test.TestCase):

    def setUp(self):
        super().setUp()

        opts.set_defaults(cfg.CONF)

        self.payload_start = {
            "name": "api-start",
            "base_id": "4e3e0ec6-2938-40b1-8504-09eb1d4b0dee",
            "trace_id": "1c089ea8-28fe-4f3d-8c00-f6daa2bc32f1",
            "parent_id": "e2715537-3d1c-4f0c-b3af-87355dc5fc5b",
            "timestamp": "2018-05-03T04:31:51.781381",
            "info": {
                "host": "test"
            }
        }

        self.payload_stop = {
            "name": "api-stop",
            "base_id": "4e3e0ec6-2938-40b1-8504-09eb1d4b0dee",
            "trace_id": "1c089ea8-28fe-4f3d-8c00-f6daa2bc32f1",
            "parent_id": "e2715537-3d1c-4f0c-b3af-87355dc5fc5b",
            "timestamp": "2018-05-03T04:31:51.781381",
            "info": {
                "host": "test",
                "function": {
                    "result": 1
                }
            }
        }

        self.driver = otlp.OTLP(
            "otlp://127.0.0.1:6831",
            project="nova", service="api",
            conf=cfg.CONF)

    def test_notify_start(self):
        self.driver.notify(self.payload_start)
        self.assertEqual(1, len(self.driver.spans))
        self.assertIn(self.payload_start["trace_id"], self.driver.spans)

    def test_notify_stop(self):
        mock_end = mock.MagicMock()
        self.driver.notify(self.payload_start)
        self.driver.spans[self.payload_start["trace_id"]].end = mock_end
        self.driver.notify(self.payload_stop)
        mock_end.assert_called_once()

    def test_notify_stop_without_start_does_not_raise(self):
        self.driver.notify(self.payload_stop)
        self.assertEqual(0, len(self.driver.spans))

    def test_notify_pairs_interleaved_spans_by_trace_id(self):
        payload_start_a = dict(self.payload_start, trace_id="trace-a")
        payload_start_b = dict(self.payload_start, trace_id="trace-b")
        payload_stop_a = dict(self.payload_stop, trace_id="trace-a")
        payload_stop_b = dict(self.payload_stop, trace_id="trace-b")

        self.driver.notify(payload_start_a)
        self.driver.notify(payload_start_b)

        end_a = mock.MagicMock()
        end_b = mock.MagicMock()
        self.driver.spans["trace-a"].end = end_a
        self.driver.spans["trace-b"].end = end_b

        self.driver.notify(payload_stop_a)
        end_a.assert_called_once()
        end_b.assert_not_called()

        self.driver.notify(payload_stop_b)
        end_b.assert_called_once()

    def test_name_start_suffix_truncation(self):
        payload = {"name": "rbac.filter-start", "info": {}}
        self.assertEqual("rbac.filter", self.driver._name(payload))

    def test_create_span_tags_generic_passthrough(self):
        payload = {
            "info": {
                "host": "test",
                "rbac": {
                    "decision": "deny",
                    "count": 3,
                    "context": {"project_id": "p1"},
                },
            }
        }
        tags = self.driver.create_span_tags(payload)
        self.assertEqual("deny", tags["rbac.decision"])
        self.assertEqual(3, tags["rbac.count"])
        self.assertNotIn("host", tags)
        self.assertEqual({"project_id": "p1"},
                         json.loads(tags["rbac.context"]))

    def test_create_span_tags_skips_non_dict_namespaces(self):
        payload = {"info": {"host": "test", "flag": True}}
        tags = self.driver.create_span_tags(payload)
        self.assertEqual({}, tags)

    def test_notify_stop_merges_extra_namespace_attributes(self):
        self.driver.notify(self.payload_start)
        span = self.driver.spans[self.payload_start["trace_id"]]
        span.end = mock.MagicMock()

        payload_stop = dict(self.payload_stop)
        payload_stop["info"] = dict(self.payload_stop["info"])
        payload_stop["info"]["rbac"] = {"decision": "deny"}

        self.driver.notify(payload_stop)
        self.assertEqual("deny", span.attributes["rbac.decision"])

    def test_service_name_default(self):
        self.assertEqual("pr1-svc1", self.driver._get_service_name(
            cfg.CONF, "pr1", "svc1"))

    def test_service_name_prefix(self):
        cfg.CONF.set_default(
            "service_name_prefix", "prx1", "profiler_otlp")
        self.assertEqual("prx1-pr1-svc1", self.driver._get_service_name(
            cfg.CONF, "pr1", "svc1"))

    def test_process_tags(self):
        # Need to be implemented.
        pass
