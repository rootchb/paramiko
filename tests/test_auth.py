# Copyright (C) 2008  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Some unit tests for authenticating over a Transport.
"""

import sys
import threading
import unittest

from paramiko import (
    Transport, RSAKey, DSSKey, BadAuthenticationType,
    AuthenticationException,
)
from pytest import raises

from ._loop import LoopSocket
from ._util import _support, slow, NullServer, _pwd


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.socks = LoopSocket()
        self.sockc = LoopSocket()
        self.sockc.link(self.socks)
        self.tc = Transport(self.sockc)
        self.ts = Transport(self.socks)

    def tearDown(self):
        self.tc.close()
        self.ts.close()
        self.socks.close()
        self.sockc.close()

    def start_server(self):
        host_key = RSAKey.from_private_key_file(_support('test_rsa.key'))
        self.public_host_key = RSAKey(data=host_key.asbytes())
        self.ts.add_server_key(host_key)
        self.event = threading.Event()
        self.server = NullServer()
        self.assertTrue(not self.event.is_set())
        self.ts.start_server(self.event, self.server)

    def verify_finished(self):
        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())


class TestEdgeCaseFailures(TestAuth):
    """
    Tests situations not involving successful or attempted-but-failed auth.

    E.g. disconnects, invalid auth types, etc.
    """

    def test_bad_auth_type(self):
        """
        verify that we get the right exception when an unsupported auth
        type is requested.
        """
        self.start_server()
        with raises(BadAuthenticationType) as info:
            self.tc.connect(username='unknown', password='error')
        assert info.value.allowed_types == ['publickey']

    def test_auth_gets_disconnected(self):
        """
        verify that we catch a server disconnecting during auth, and report
        it as an auth failure.
        """
        self.start_server()
        self.tc.connect()
        with raises(AuthenticationException):
            self.tc.auth_password('bad-server', 'hello')

    @slow
    def test_auth_non_responsive(self):
        """
        verify that authentication times out if server takes to long to
        respond (or never responds).
        """
        self.tc.auth_timeout = 1  # 1 second, to speed up test
        self.start_server()
        self.tc.connect()
        with raises(AuthenticationException, match='Authentication timeout'):
            self.tc.auth_password('slowdive', 'unresponsive-server')


class TestPasswordAuth(TestAuth):
    # TODO: store as new suite along w/ successful password tests (The utf8
    # ones below I think)
    def test_bad_password(self):
        """
        verify that a bad password gets the right exception, and that a retry
        with the right password works.
        """
        self.start_server()
        self.tc.connect()
        with raises(AuthenticationException):
            self.tc.auth_password(username='slowdive', password='error')
        self.tc.auth_password(username='slowdive', password='pygmalion')
        self.verify_finished()

    def test_interactive_auth_fallback(self):
        """
        verify that a password auth attempt will fallback to "interactive"
        if password auth isn't supported but interactive is.
        """
        self.start_server()
        self.tc.connect()
        remain = self.tc.auth_password('commie', 'cat')
        self.assertEqual([], remain)
        self.verify_finished()

    def test_auth_utf8(self):
        """
        verify that utf-8 encoding happens in authentication.
        """
        self.start_server()
        self.tc.connect()
        remain = self.tc.auth_password('utf8', _pwd)
        self.assertEqual([], remain)
        self.verify_finished()

    def test_auth_non_utf8(self):
        """
        verify that non-utf-8 encoded passwords can be used for broken
        servers.
        """
        self.start_server()
        self.tc.connect()
        remain = self.tc.auth_password('non-utf8', '\xff')
        self.assertEqual([], remain)
        self.verify_finished()


class TestInteractiveAuth(TestAuth):
    # TODO: identify other test cases to expand around this one
    def test_interactive_auth(self):
        """
        verify keyboard-interactive auth works.
        """
        self.start_server()
        self.tc.connect()

        def handler(title, instructions, prompts):
            self.got_title = title
            self.got_instructions = instructions
            self.got_prompts = prompts
            return ['cat']
        remain = self.tc.auth_interactive('commie', handler)
        self.assertEqual(self.got_title, 'password')
        self.assertEqual(self.got_prompts, [('Password', False)])
        self.assertEqual([], remain)
        self.verify_finished()


class TestMultipartAuth(TestAuth):
    # TODO: clarify the name of this to show it's only one specific multipart
    # auth style
    def test_multipart_auth(self):
        """
        verify that multipart auth works.
        """
        self.start_server()
        self.tc.connect()
        remain = self.tc.auth_password(
            username='paranoid',
            password='paranoid',
        )
        self.assertEqual(['publickey'], remain)
        key = DSSKey.from_private_key_file(_support('test_dss.key'))
        remain = self.tc.auth_publickey(username='paranoid', key=key)
        self.assertEqual([], remain)
        self.verify_finished()
