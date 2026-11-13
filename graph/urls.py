from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("api/upload/", views.upload_csv, name="upload_csv"),
    path("api/nslookup/", views.nslookup_ip, name="nslookup_ip"),
    path("api/geoip/", views.geoip, name="geoip"),
    path("api/cp/connect/", views.checkpoint_connect, name="cp_connect"),
    path("api/cp/query/",   views.checkpoint_query,   name="cp_query"),
    path("api/cp/logout/",  views.checkpoint_logout,  name="cp_logout"),
    path("deploy-key", views.deploy_key, name="deploy_key"),
]
