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

from paramiko import (
    DSSKey, BadAuthenticationType, AuthenticationException,
)
from pytest import raises

from ._util import _support, slow, utf8_password


class TestPasswordAuth:
    def test_auth_utf8(self, trans):
        """
        verify that utf-8 encoding happens in authentication.
        """
        # TODO: this doesn't seem to actually verify anything!
        trans.connect()
        remains = trans.auth_password('utf8', utf8_password)
        assert remains == []

    def test_auth_non_utf8(self, trans):
        """
        verify that non-utf-8 encoded passwords can be used for broken
        servers.
        """
        trans.connect()
        remains = trans.auth_password('non-utf8', '\xff')
        assert remains == []


class TestInteractiveAuth:
    # TODO: identify other test cases to expand around this one
    def test_interactive_auth(self, trans):
        """
        verify keyboard-interactive auth works.
        """
        trans.connect()
        # TODO: mock the server transport harder instead of using these
        # globals, ew.
        global got_title, got_instructions, got_prompts
        got_title, got_instructions, got_prompts = None, None, None
        def handler(title, instructions, prompts):
            # Big meh.
            global got_title, got_instructions, got_prompts
            got_title = title
            got_instructions = instructions
            got_prompts = prompts
            return ['cat']
        remains = trans.auth_interactive('commie', handler)
        assert got_title == 'password'
        assert got_prompts == [('Password', False)]
        assert remains == []


class TestMultipartAuth:
    # TODO: clarify the name of this to show it's only one specific multipart
    # auth style
    def test_multipart_auth(self, trans):
        """
        verify that multipart auth works.
        """
        trans.connect()
        remains = trans.auth_password(
            username='paranoid',
            password='paranoid',
        )
        assert remains == ['publickey']
        key = DSSKey.from_private_key_file(_support('test_dss.key'))
        remains = trans.auth_publickey(username='paranoid', key=key)
        assert remains == []
