from django.urls import path
from django.contrib.auth import views as auth_views  # Ensure this import is present
from django.conf import settings
from django.conf.urls.static import static  
from . import views
urlpatterns = [
    path('', views.index, name='index'),
    path('login/',  views.login_view,   name='login'),
    path('signup/', views.signup_view,  name='signup'),
    path('home/',   views.home_view,    name='home'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    # information
    path('nmap/', views.nmap, name='nmap'),
    path('run_nmap/', views.run_nmap, name='run_nmap'),
    path('dimitry/', views.dimitry, name='dimitry'),
    path('run_dimitry/', views.run_dimitry, name='run_dimitry'),
    path('whois/', views.whois, name='whois'),
    path('run_whois/', views.run_whois, name='run_whois'),
    path('theharvester/', views.theharvester, name='theharvester'),
    path('run_theharvester/', views.run_theharvester, name='run_theharvester'),
    # vulnerability
    path('sqlmap/', views.sqlmap, name='sqlmap'),
    path('run_sqlmap/', views.run_sqlmap, name='run_sqlmap'),
    path('view_whatweb/', views.view_whatweb, name='view_whatweb'),
    path('scan_with_whatweb/', views.scan_with_whatweb, name='scan_with_whatweb'),
    path('wpscan/', views.wpscan, name='wpscan'),
    path('run_wpscan/', views.run_wpscan, name='run_wpscan'),
    path('nikto/',views.nikto, name='nikto'),
    path('run_nikto/', views.run_nikto, name='run_nikto'),
    path('joomscan/',views.joomscan, name='joomscan'),
    path('run_joomscan/',views.run_joomscan, name='run_joomscan'),
    # Password:
    path('john/',views.john, name='john'),
    path('run_john/',views.run_john, name='run_john'),
    path('zip2john/',views.zip2john, name='zip2john'),
    path('hydra/',views.hydra, name='hydra'),
    path('crunch/', views.crunch, name='crunch'),
    path('zip2john/', views.zip2john, name='zip2john'),
    path('crunch/', views.crunch, name='crunch'),
    path('run_crunch_view/', views.run_crunch_view, name='run_crunch_view'),
    path('delete_file/<str:file_name>/<str:type>/', views.delete_hash_file, name='delete_file'),
    path('tgpt/', views.tgpt, name='tgpt'),
    path('chat/', views.chat, name='chat'),
    path('mdk3/', views.mdk3, name='mdk3'),
    path('execute_mdk3', views.execute_mdk3, name='execute_mdk3'),
    path('manage-service/', views.manage_service, name='manage_service'),
    path('get_mobile_details/', views.get_mobile_details, name='get_mobile_details'),
    path('infoga/', views.infoga, name='infoga'),
    path('save_phone_detail/', views.save_phone_detail, name='save_phone_detail'),
    path('geolocation/', views.geolocation_tool, name='geolocation_tool'),


    
    
    
    path('cewl/', views.cewl, name='cewl'),
    path('run_cewl/', views.run_cewl , name='run_cewl'),
    path('dirsearch/',views.dirsearch, name='dirsearch'),
    path('cmsmap/',views.cmsmap, name='cmsmap'),
    path('run_dirsearch/', views.run_dirsearch,name='run_dirsearch'),
    path('run_cmsmap/', views.run_cmsmap,name='run_cmsmap'),
    path('dirb/', views.dirb,name='dirb'),
    path('run_dirb/', views.run_dirb,name='run_dirb'),
    path('nmap/', views.nmap,name='nmap'),
    path('network-info/', views.get_network_info, name='get_network_info'),
    path('netdiscover/', views.netdiscover, name='netdiscover'),
    path('nuclei/', views.nuclei, name='nuclei'),  # Add this URL pattern
    path('run_nuclei/', views.run_nuclei, name='run_nuclei'), 
    path('macof/', views.macof, name='macof'),
    path('macof-controller/', views.macof_controller, name='macof_controller'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)



