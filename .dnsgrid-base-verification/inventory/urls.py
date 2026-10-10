from django.urls import path

from . import views

urlpatterns = [
    path("", views.grid, name="grid"),
    path("hosts/new/", views.host_edit, name="host-create"),
    path("hosts/<int:host_id>/", views.host_edit, name="host-edit"),
    path("hosts/<int:host_id>/move/", views.host_move, name="host-move"),
    path("hosts/<int:host_id>/delete/", views.host_delete, name="host-delete"),
    path("confirm/", views.confirm, name="confirm"),
    path("confirm/cancel/", views.cancel, name="cancel"),
    path("settings/", views.configuration, name="configuration"),
    path("exports/", views.exports, name="exports"),
    path("exports/publish-dns/", views.dns_publish, name="dns-publish"),
    path("exports/deliver-dns/", views.dns_deliver, name="dns-deliver"),
    path("exports/retry-dns-delivery/", views.dns_retry, name="dns-retry-delivery"),
    path("exports/check-dns-result/", views.dns_result, name="dns-result"),
    path("archive/download/", views.archive_download, name="archive-download"),
    path("archive/upload/", views.archive_upload, name="archive-upload"),
    path("exports/download/<str:filename>/", views.download, name="download"),
    path("vpn/report/", views.vpn_report, name="vpn-report"),
    path("gandi/preview/", views.gandi_preview, name="gandi-preview"),
]
