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

from unittest import mock

import testtools

from osprofiler import initializer


class InitializerTestCase(testtools.TestCase):

    @mock.patch("osprofiler.notifier.set")
    @mock.patch("osprofiler.notifier.create")
    @mock.patch("osprofiler.web.enable")
    def test_initializer(self, web_enable_mock, notifier_create_mock,
                         notifier_set_mock):
        conf = mock.Mock()
        conf.profiler.connection_string = "driver://"
        conf.profiler.hmac_keys = "hmac_keys"
        context = {}
        project = "my-project"
        service = "my-service"
        host = "my-host"

        notifier_mock = mock.Mock()
        notifier_create_mock.return_value = notifier_mock

        initializer.init_from_conf(conf, context, project, service, host)

        notifier_create_mock.assert_called_once_with(
            "driver://", context=context, project=project, service=service,
            host=host, conf=conf)
        notifier_set_mock.assert_called_once_with(mock.ANY)
        web_enable_mock.assert_called_once_with(hmac_keys="hmac_keys")

        # the wrapper passed to notifier.set() must tee to the log and
        # still call the real notifier
        wrapper = notifier_set_mock.call_args[0][0]
        self.assertIsNot(wrapper, notifier_mock)

        payload = {"name": "api-start", "info": {"host": "test"}}
        with mock.patch("osprofiler.initializer.LOG") as log_mock:
            wrapper(payload)

        notifier_mock.assert_called_once_with(payload)
        self.assertEqual(1, log_mock.info.call_count)
        args, _ = log_mock.info.call_args
        logged = args[0] % args[1:] if len(args) > 1 else args[0]
        self.assertIn("osprofiler_trace", logged)

    @mock.patch("osprofiler.notifier.set")
    @mock.patch("osprofiler.notifier.create")
    @mock.patch("osprofiler.web.enable")
    def test_initializer_tee_calls_notifier_even_if_log_serialization_fails(
            self, web_enable_mock, notifier_create_mock, notifier_set_mock):
        conf = mock.Mock()
        conf.profiler.connection_string = "driver://"
        conf.profiler.hmac_keys = "hmac_keys"

        notifier_mock = mock.Mock()
        notifier_create_mock.return_value = notifier_mock

        initializer.init_from_conf(
            conf, {}, "my-project", "my-service", "my-host")

        wrapper = notifier_set_mock.call_args[0][0]

        class Unserializable(object):
            def __repr__(self):
                raise TypeError("nope")

        payload = {"name": "api-start", "info": {"bad": Unserializable()}}

        with mock.patch("osprofiler.initializer.LOG"):
            wrapper(payload)

        notifier_mock.assert_called_once_with(payload)
