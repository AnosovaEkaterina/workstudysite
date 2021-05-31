from django.conf.urls import url

from mainpage import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^filtr$', views.filtr, name='filtr'),
    url(r'^edit/(?P<program_id>[0-9]+)/$', views.showedit, name='editshow'),
    url(r'^showfav/(?P<user_id>[0-9]+)/', views.showfav, name='showfav'),
    url(r'^edit/(?P<program_id>[0-9]+)/edit$', views.edit, name='edit'),
    url(r'^detail/(?P<program_id>[0-9]+)/', views.detail, name='detail'),
    url(r'^delete/(?P<program_id>[0-9]+)/', views.delete, name='delete'),
    url(r'^addfav/(?P<program_id>[0-9]+)/(?P<user_id>[0-9]+)/', views.addfav, name='addfav'),
    url(r'^deletefav/(?P<program_id>[0-9]+)/(?P<user_id>[0-9]+)/', views.deletefav, name='deletefav'),
    url(r'^login$', views.login, name='login'),
    url(r'^report$', views.report, name='report'),
    url(r'^logout$', views.logout, name='logout'),
    url(r'^registr$', views.registr, name='registr'),
    url(r'^add$', views.add, name='add')
]
app_name = 'mains'
