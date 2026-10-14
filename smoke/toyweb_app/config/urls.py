from django.http import HttpRequest, HttpResponse
from django.urls import path


def index(request: HttpRequest) -> HttpResponse:
    return HttpResponse("toyweb ok\n", content_type="text/plain")


urlpatterns = [path("", index)]
