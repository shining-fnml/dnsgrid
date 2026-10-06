from django.urls import path

from . import views

urlpatterns = [
    path("", views.grid, name="grid"),
    path("hosts/new/", views.host_edit, name="host-create"),
    path("hosts/<int:host_id>/", views.host_edit, name="host-edit"),
    path("hosts/<int:host_id>/move/", views.host_move, name="host-move"),
    path("hosts/<int:host_id>/delete/", views.host_delete, name="host-delete"),
    path("confirm/", views.confirm, name="confirm"),
    path("settings/", views.configuration, name="configuration"),
    path("exports/", views.exports, name="exports"),
    path("exports/download/<str:filename>/", views.download, name="download"),
    path("gandi/preview/", views.gandi_preview, name="gandi-preview"),
]
