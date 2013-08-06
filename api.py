from django.conf.urls import url
from tastypie.authentication import BasicAuthentication
from tastypie.authorization import Authorization
from tastypie.resources import Resource, ModelResource
from tastypie.models import ApiKey
from tastypie import fields


class LoginResource (ModelResource):
    """ Login resource must be used to get api_key.
    ``BasicAuthentication`` is used to get it. """
    class Meta:
        authentication = BasicAuthentication()
        queryset = ApiKey.objects.all()
        allowed_methods = ['get']
        list_allowed_methods = ['get']
        fields = ['key']
        include_resource_uri = False

    def apply_authorization_limits(self, request, object_list):
        return object_list.filter(user=request.user)

    def prepend_urls(self):
        return [
            url(r"^(?P<resource_name>%s)/$" % self._meta.resource_name, self.wrap_view('dispatch_detail'), name="api_dispatch_detail"),
        ]

