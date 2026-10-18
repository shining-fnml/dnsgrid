from .gandi_credentials import credential_summary
from .models import Configuration


def gandi_status(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return {}
    config = Configuration.objects.filter(pk=1).first()
    return {"gandi_credential": credential_summary(config)} if config else {}
