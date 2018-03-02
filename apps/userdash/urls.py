from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^signin$', views.signin),
    url(r'^login$', views.login),
    url(r'^register$', views.register),
    url(r'^user/create$', views.user_create),
    url(r'^dashboard$', views.dashboard),
    url(r'^dashboard/admin$', views.admin_dash),
    url(r'^users/new$', views.admin_new), 
    url(r'^admin/create$', views.admin_create),
    url(r'^users/edit$', views.user_edit),
    url(r'^users/edit/(?P<user_id>\d+)$', views.admin_edit),
    url(r'^edit/(?P<user_id>\d+)$', views.edit),
    url(r'^changepass/(?P<user_id>\d+)$', views.password),
    url(r'^changedesc/(?P<user_id>\d+)$', views.description),    
    url(r'^users/show/(?P<user_id>\d+)$', views.show),
    url(r'^post/msg/(?P<user_id>\d+)$', views.post_msg),
    url(r'^post/cmt/(?P<user_id>\d+)/(?P<msg_id>\d+)$', views.post_cmt),
    url(r'^delete/(?P<user_id>\d+)$', views.delete),    
    url(r'^logoff$', views.logoff)
]