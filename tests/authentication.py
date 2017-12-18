from pytest import skip, raises

from paramiko import BadAuthenticationType, AuthenticationException

from ._util import slow, utf8_password


# NOTE: GSSAPI is kind of a standalone feature and has its own tests in
# test_kex_gss.py, test_ssh_gss.py and test_gssapi.py.

# NOTE: test arguments are pytest fixtures, which can be found in conftest.py


#
# Edge/error cases that aren't strongly tied to a given success case
#

class EdgeCases:
    def server_does_not_support_our_requested_auth_type(self, trans):
        with raises(BadAuthenticationType) as info:
            # TODO: Authenticator(trans).authenticate('unknown',
            # PasswordAuth('error'))
            trans.connect(username='unknown', password='error')
        # TODO: new hybrid subclass w/ single PasswordAuth->failure pairing,
        # value is BadAuthType w/ some list of allowed_types
        assert info.value.allowed_types == ['publickey']

    def disconnections(self, trans):
        # Disconnections during auth step show up as an auth exception
        trans.start_client()
        with raises(AuthenticationException):
            trans.auth_password('bad-server', 'hello')

    @slow
    def non_responsive_servers_raise_auth_exception_with_timeout(self, trans):
        trans.auth_timeout = 1  # 1 second, to speed up test
        trans.start_client()
        with raises(AuthenticationException, match='Authentication timeout'):
            trans.auth_password('slowdive', 'unresponsive-server')


#
# Single auth sources
#

class None_:
    def raises_BadAuthenticationType_if_server_rejects(self, trans):
        # TODO: given this is usually called just as a no-op to check what a
        # server allows, we may want to offer a wrapper for this instead of
        # requiring oddball exception flow?
        with raises(BadAuthenticationType) as info:
            # TODO: Authenticator(trans).authenticate('paranoid',
            # NoneAuthOrWhatever())
            trans.start_client()
            trans.auth_none('paranoid')
        # TODO: the new overarching exception instead of a
        # BadAuthenticationType
        assert info.value.allowed_types == ['publickey', 'password']

    def may_be_accepted_by_extremely_naughty_servers(self, trans):
        # Yes, this is a thing that exists in reality & it's supported by the
        # RFC as well!
        # TODO: Authenticator(trans).authenticate('whatever',
        # NoneAuthOrWhatever())
        # TODO: return value would be our hybrid result object whose iterable
        # is the single NoneAuthOrWhatever + success signifier
        trans.start_client()
        assert trans.auth_none('nobody') == []


class Password:
    pass


class Interactive:
    # TODO: how exactly is auth_interactive different from auth_password?
    # TODO: and what's the diff between transport's interactive vs
    # interactive_dumb?
    # TODO: and how (is?) it different from what's used for TOTP
    pass


class UnencryptedPubKey:
    pass


class EncryptedPubKey:
    pass


#
# Multiple auth sources, of which only one is needed/valid
#

class ManyAuthsEnterOneAuthLeaves:
    pass


#
# True multi-factor auth, where more than one source is needed/required
#

class MultiFactor:
    pass


#
# Unit-style tests for actual new auth APIs, insofar as they're not 100% tested
# in the above tests.
#

class Authenticator_:
    class init:
        def requires_a_Transport(self):
            skip()   

        def transport_must_already_be_started(self):
            skip()

    class authenticate_with_kwargs:
        def one_kwarg_becomes_an_auth_source(self):
            skip()

        def another_kwarg_becomes_another_auth_source(self):
            skip()

        # ...

    class authenticate:
        # TODO: @raises(AuthenticationError or subclass)
        def must_be_given_at_least_one_auth_source(self):
            # a.authenticate()
            skip()

        # TODO: @raises(TypeError or ValueError or w/e)
        def args_must_be_AuthSource_objects(self):
            # a.authenticate(object())
            skip()

        def tries_given_sources_in_order(self):
            # a.authenticate(password, key) calls auth_password (which should
            # fail), then auth_publickey (& succeed, I guess)
            skip()

        def returns_AuthenticationResult(self):
            skip()


# TODO: name it AuthResult instead?
class AuthenticationResult_:
    pass
