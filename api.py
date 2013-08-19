from django.conf.urls import url
from tastypie.authentication import BasicAuthentication
from tastypie.authorization import Authorization
from tastypie.resources import ModelResource, Resource
from tastypie.models import ApiKey
from tastypie.validation import FormValidation
from tastypie.exceptions import ImmediateHttpResponse
from registration.forms import RegistrationFormUniqueEmail
from registration.models import RegistrationProfile
from registration.backends.default.views import RegistrationView


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
    """ Registration resource """
    class Meta:
        object_class = RegistrationProfile
        authorization = Authorization()
        allowed_methods = ['post']
        validation = FormValidation(form_class=RegistrationFormUniqueEmail)
        registration_view = RegistrationView()

    def obj_create(self, bundle, **kwargs):
        self.is_valid(bundle)
        if bundle.errors:
            raise ImmediateHttpResponse(response=self.error_response(bundle.request, bundle.errors))
        self._meta.registration_view.register(bundle.request, **bundle.data)
        return bundle

    def detail_uri_kwargs(self, bundle_or_obj):
        return {}
