import re

from django.conf.urls import url
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import base36_to_int

from tastypie.authentication import BasicAuthentication
from tastypie.authorization import Authorization
from tastypie.resources import ModelResource, Resource
from tastypie.models import ApiKey
from tastypie.validation import FormValidation
from tastypie.exceptions import ImmediateHttpResponse, BadRequest

from registration.forms import RegistrationFormUniqueEmail
from registration.models import RegistrationProfile
from registration.backends.default.views import RegistrationView, ActivationView


class LoginResource (ModelResource):
    """ Login resource must be used to get api_key.
    ``BasicAuthentication`` is used to get it. """
    class Meta:
        queryset = ApiKey.objects.all()
        authentication = BasicAuthentication()
        allowed_methods = ['get']
        fields = ['key']
        include_resource_uri = False

    def get_object_list(self, request):
        return super(LoginResource, self).get_object_list(request).filter(user=request.user)

    def prepend_urls(self):
        return [
            url(r"^(?P<resource_name>%s)/$" % self._meta.resource_name, self.wrap_view('dispatch_detail'), name="api_dispatch_detail"),
        ]


class RegistrationResource (Resource):
    """ Registration resource.

    Uses ``registration_view`` to perform registration.
    The registration form must be set as ``form_class`` for
    ``validation``. Read about it here:
    https://django-registration.readthedocs.org/en/latest/forms.html
    and here:
    http://django-tastypie.readthedocs.org/en/latest/validation.html
    """
    registration_view = RegistrationView()

    class Meta:
        object_class = RegistrationProfile
        authorization = Authorization()
        allowed_methods = ['post']
        validation = FormValidation(form_class=RegistrationFormUniqueEmail)

    def obj_create(self, bundle, **kwargs):
        self.is_valid(bundle)
        if bundle.errors:
            raise ImmediateHttpResponse(response=self.error_response(bundle.request, bundle.errors))
        self.registration_view.register(bundle.request, **bundle.data)
        return bundle

    def detail_uri_kwargs(self, bundle_or_obj):
        return {}


class ActivationResource (ModelResource):
    """ Activation Resource.

    Uses ``activation_view``, which must be an intance of class from ``registration``
    package. Of course you also can write your own activation-view class,
    see https://django-registration.readthedocs.org/en/latest/views.html

    The resource expects a data POST with ``activation_key`` key.
    """
    activation_view = ActivationView()

    class Meta:
        queryset = RegistrationProfile.objects.all()
        authorization = Authorization()
        allowed_methods = ['post']

    def obj_create(self, bundle, **kwargs):
        if 'activation_key' not in bundle.data:
            raise BadRequest('You must pass activation_key')

        activated_user = self.activation_view.activate(bundle.request, bundle.data['activation_key'])
        if activated_user:
            return bundle
        raise BadRequest('Wrong activation_key')


class PasswordResetResource (Resource):
    """ Initialtes password reset.

    Here you can change ``email_template_name``, ``subject_template_name``,
    ``password_reset_form``, ``token_generator``. By default all values are set
    to django defaults.
    """
    email_template_name = 'registration/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
    password_reset_form = PasswordResetForm
    token_generator = default_token_generator

    class Meta:
        object_class = User
        authorization = Authorization()
        allowed_methods = ['post']

    def obj_create(self, bundle, **kwargs):
        request = bundle.request
        request.POST = bundle.data # TODO: find a better way to fix POST?
        form = self.password_reset_form(request.POST)

        if form.is_valid():
            opts = {
                'use_https': request.is_secure(),
                'token_generator': self.token_generator,
                'email_template_name': self.email_template_name,
                'subject_template_name': self.subject_template_name,
                'request': request,
            }
            form.save(**opts)
        else:
            raise ImmediateHttpResponse(response=self.error_response(bundle.request, form.errors))

        return bundle

    def detail_uri_kwargs(self, bundle_or_obj):
        return {}


class PasswordResetConfirmResource (Resource):
    """ Confirms password reset. E.g. allows to set new
    password using token got in email.

    You can set ``token_generator`` and ``set_password_form`` if you
    are not happy with django default setings.
    """
    token_generator = default_token_generator
    set_password_form = SetPasswordForm

    class Meta:
        object_class = User
        authorization = Authorization()
        allowed_methods = ['post']

    def obj_create(self, bundle, **kwargs):
        request = bundle.request
        request.POST = bundle.data # TODO: find a better way to fix POST?

        user = None
        token = None

        try:
            m = re.search('([0-9A-Za-z]+)-(.+)', bundle.data['reset_key'])
            uidb36 = m.group(1)
            token = m.group(2)
            uid_int = base36_to_int(uidb36)
            UserModel = get_user_model()
            user = UserModel._default_manager.get(pk=uid_int)
        except:
            raise BadRequest('User does not exist')

        if not self.token_generator.check_token(user, token):
            raise BadRequest('Bad token')

        form = self.set_password_form(user, request.POST)
        if not form.is_valid():
            raise ImmediateHttpResponse(response=self.error_response(bundle.request, form.errors))

        form.save()

        return bundle

    def detail_uri_kwargs(self, bundle_or_obj):
        return {}
