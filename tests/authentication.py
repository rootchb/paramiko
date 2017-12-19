from pytest import skip, raises

from paramiko import BadAuthenticationType, AuthenticationException, DSSKey

from ._util import slow, _support


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
        # TODO: Authenticator(trans).authenticate('bad-server',
        # Password('hello')) -> password step has auth exception
        trans.start_client()
        with raises(AuthenticationException):
            trans.auth_password('bad-server', 'hello')

    @slow
    def non_responsive_servers_raise_auth_exception_with_timeout(self, trans):
        # TODO: Authenticator(trans).authenticate('slowdive',
        # Password('unresponsive-server')) -> auth exception, password step
        # says 'auth timeout' (so...is this a nested AuthenticationException?
        # Guess it has to be.)
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


class Password_:
    def success_case(self):
        # TODO: Authenticator(trans).authenticate('slowdive',
        # Password('pygmalion')) -> password success
        skip()

    def failure_case(self, trans):
        # TODO: Authenticator(trans).authenticate('slowdive',
        # Password('error')) -> password failure
        with raises(AuthenticationException):
            trans.start_client()
            trans.auth_password(username='slowdive', password='error')


class Interactive:
    def custom_handler_base_case(self, trans):
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

    def raises_auth_exception_on_single_auth_failure(self):
        skip()

    def multiple_internal_steps_success(self):
        # TODO: i.e. multiple 'internal' auth steps (since interactive is
        # phrased as potentially being N cycles of info-request ->
        # info-response! even though I'm unaware of common real-world scenarios
        # where this is used, instead of being multiple top level auth requests
        # as in a later suite)
        # TODO: how should this look in terms of AuthenticationResult? It
        # breaks the usual "N input sources -> N output results" because there
        # will only be a single input source ("I want interactive auth and
        # here's my handler callback") but there may be M interactions with the
        # user, depending entirely on server configuration. Probably means the
        # actual 'value' objects in the Result need to be heterogenous, and in
        # this scenario it'd be an inner iterable?
        skip()

    def multiple_internal_steps_eventual_failure(self):
        # TODO: same as above except the final step is a failure. Includes same
        # problem re: representation in AuthenticationResult.
        skip()

    def dumb_defaults_to_a_printing_handler(self):
        # interactive_dumb is just regular interactive which defaults to a
        # useful CLI-level default handler.
        # TODO: separate auth class or just a param for the regular interactive
        # one?
        # TODO: Prove that 'dumb' style interactive auth just prints the
        # title/instructions/prompts by default.
        skip()


class UnencryptedPubKey:
    def base_case(self):
        # TODO: Authenticator(trans).authenticate(username,
        # PubKey(RSAKey(xxx)))? Or just accept the key object itself? How does
        # that change encrypted vs unencrypted exactly?
        skip()

    def unauthorized_key_raises_auth_exception(self):
        # TODO: that
        skip()

    def invalid_key_material_raises_other_exception(self):
        # TODO: this may be out of scope pending determination of what exact
        # type of objs we accept, if we are still doing file loading on user
        # behalf then this needs filling out.
        skip()

    def supports_all_implemented_key_types(self):
        # TODO: Iterate over all our key classes. pytest fixtures around
        # base_case instead?
        skip()


class EncryptedPubKey:
    def base_case(self):
        # TODO: Authenticator for an encrypted key obj (see above re: whether
        # that's a 'real' source obj or if we just hand in the key; in this
        # case, we may or may not want to try a passphrase? I.e. what does
        # authenticate_with_kwargs(username, key_filename=[foo],
        # passphrase='bar') turn into for its call to authenticate()??
        # - Does it handle the decryption, allowing authenticate() proper to
        # say "I only handle already-decrypted key objects"?
        # - Does it turn into a higher-level object representing key material +
        # passphrase? (I.e. authenticate() does perform decryption) - what's
        # the benefit here exactly? Does save users a bit of manual work if all
        # they have is key + a passphrase from somewhere...
        # - Can we still get by with just-a-PKey?
        skip()

    def unauthorized_key_raises_auth_exception(self):
        # TODO: that
        skip()

    def invalid_key_material_raises_other_exception(self):
        # TODO: this may be out of scope pending determination of what exact
        # type of objs we accept, if we are still doing file loading on user
        # behalf then this needs filling out.
        skip()

    def other_key_classes(self):
        # TODO: same as with unencrypted keys
        skip()


#
# Multiple auth sources, of which only one is needed/valid
#

class ManyAuthsEnterOneAuthLeaves:
    def can_send_good_password_after_bad(self, trans):
        trans.start_client()
        with raises(AuthenticationException):
            # Will raise an auth exception (wrong password)
            trans.auth_password(username='slowdive', password='error')
        # Should succeed
        rest = trans.auth_password(username='slowdive', password='pygmalion')
        assert rest == []

    def bad_password_after_good_is_not_used(self):
        # TODO: i.e. authenticate(Password('good'), Password('bad')) never
        # submits the bad password down the pipe - success is success.
        skip()

    # TODO: probably a good place for pytest parameterization; would be rad to
    # test all combinatoric combos of each auth type before or after others,
    # with each type either being valid or invalid.
    # TODO: so e.g. not only do we want to end up testing [good key, bad
    # password] but we also want to test [bad key, good password] AND [good
    # password, bad key] AND [bad password, good key], and so on. and of
    # course, more than just 2 deep. and not just all types x all types, but
    # multiple instances of a same type; and so on and so forth.
    # TODO: can Hypothesis help with this sort of thing?? Haven't looked at it

    def unsupported_password_auth_falls_back_to_interactive(self, trans):
        # Tests that Transport.password_auth automatically re-attempts with
        # 'interactive' type auth if password appears unsupported (via
        # BadAuthenticationType)
        trans.start_client()
        # 'commie' user:
        # - triggers allowed_auths of only [interactive]
        # - is not listed under check_auth_password, so would fail anyways
        # - is checked for in check_auth_interactive
        remains = trans.auth_password('commie', 'cat')
        assert remains == []


#
# True multi-factor auth, where more than one source is needed/required
#

class MultiFactor:
    def password_plus_publickey(self, trans):
        trans.connect()
        # NOTE: 'paranoid' user triggers explicit check within
        # get_allowed_auths that tracks password-submission state & updates
        # return value accordingly, thus mocking real-world two-factor auth.
        remains = trans.auth_password(
            username='paranoid',
            password='paranoid',
        )
        assert remains == ['publickey']
        key = DSSKey.from_private_key_file(_support('test_dss.key'))
        remains = trans.auth_publickey(username='paranoid', key=key)
        assert remains == []

    def publickey_plus_interactive(self):
        # TODO: this is now a common 2FA scenario, with the 2nd factor (TOTP)
        # often being served by a PAM module backing into an API like Duo
        # Security's.
        skip()

    # TODO: another possible good spot for parameterization / trying all combos
    # TODO: though especially here, where it requires statekeeping on the dummy
    # server, could be a lot of extra work...


#
# Unit-style tests for actual new auth APIs, insofar as they're not 100% tested
# in the above tests.
#

class Authenticator_:
    class init:
        def requires_a_Transport(self):
            skip()

        def transport_must_already_be_started(self):
            # TODO: or...not
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

        def returns_AuthenticationResult_on_success(self):
            skip()

        def raises_AuthenticationError_on_failure(self):
            # TODO: can this be backwards compat re: AuthenticationException,
            # BadAuthType, etc? Or is it worth calling this 3.0 and not bending
            # over backwards there?
            skip()


# TODO: name it AuthResult instead?
# NOTE: many nontrivial cases for this class are organically tested above.
class AuthenticationResult_:
    def single_auth_source_results_in_one_item_results_list(self):
        skip()

    def multiple_auth_sources_result_in_matching_results_list(self):
        # TODO: ensure order matches input
        skip()

    def each_auth_result_is_tagged_with_the_accepted_auth_types(self):
        # TODO: i.e. include the bits that transport.auth_blah return noting
        # which further types are acceptable. I.e. for a nontrivial multifactor
        # auth setup, it should be easy to see exactly what was tried, in what
        # order, and what the server claimed to allow at that step.
        skip()


class AuthenticationError_:
    def subclasses_SSHException_for_compatibility(self):
        skip()

    def attribute_access_for_inner_AuthenticationResult(self):
        skip()

    # TODO: more conveniences necessary?
