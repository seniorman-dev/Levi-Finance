# tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model
from .models import User, BankDetail, Wallet, Transaction
import logging






#User = get_user_model()
logger = logging.getLogger(__name__)

@shared_task
def delete_user_in_5_days(user_id):
    try:
        user = User.objects.select_related().get(id=user_id, is_deleted=True)  #"select_related()" optimizes the query
        
        BankDetail.objects.filter(user=user).delete()
        Wallet.objects.filter(user=user).delete()
        Transaction.objects.filter(user=user).delete()
        if timezone.now() >= user.deleted_at + timedelta(days=5):
            user.delete()
            logger.info(f"Deleted user {user.email} and related data.")
    except User.DoesNotExist:
        pass
