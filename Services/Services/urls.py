"""beyondcorp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls import url
# from rest_framework_simplejwt import views as jwt_views
# from rest_framework.authtoken.views import obtain_auth_token
from service import views

urlpatterns = [
	#url(r'^$', views.home, name='home'),
    path('admin/', admin.site.urls),
    path('dash/<str:uid>',views.dashboard, name='dashboard'),
    path('cutOff/',views.cutOffUser, name='cutOffUser'),
    path('updateperm/',views.updatePerm, name='updatePerm'),
    path('req/<str:req>',views.requestResolver, name='requestResolver'),
    path('badP/',views.badP),
    path('logoutUser/<str:uid>',views.logUserOut, name='logUserOut'),
   # path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
   # path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
   # path('hello/', views.HelloView.as_view(), name='hello'),
   # path('api-token-auth/', obtain_auth_token, name='api-token-auth'),
   	url(r'^status', views.status, name='status'),
   	url(r'^$', views.dashboard, name='dashboard'),
    url(r'^revoked',views.revoked,name='revoked')
    # url(r'^$', views.check_jwt, name='check_jwt'),
]
