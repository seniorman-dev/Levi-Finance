# myapp/models.py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings


#from django.utils.translation import gettext_lazy as _  #translation of strings
import requests
from django.conf import settings
from django.db import transaction
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
import random
#import datetime







# We'll create a custom user model that uses email instead of username for authentication.
class UserManager(BaseUserManager):
    """Custom user manager that uses email as the unique identifier instead of username"""
    
    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValidationError({'error': 'Users must have an email address'})
        
        # Normalize the email address (lowercase the domain part)
        email = self.normalize_email(email)
        
        # Create the user object
        user = self.model(email=email, **extra_fields)
        
        # Set the password (this handles hashing)
        user.set_password(password)
        
        # Save the user to the database
        user.save(using=self._db)
        
        # print user
        print(f'user -> {user}')
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValidationError({'error': 'Superuser must have is_staff=True.'})
        if extra_fields.get('is_superuser') is not True:
            raise ValidationError({"error": 'Superuser must have is_superuser=True.'})
         
        return self.create_user(email, password, **extra_fields)
    
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)




class User(AbstractBaseUser, PermissionsMixin):
    
    """Custom user model that uses email as the username field"""
    
    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
        ordering = ['-created_at'] 
    
    # Manager for the model
    objects = UserManager()

    # Use email as the username field
    USERNAME_FIELD = 'email' 
    REQUIRED_FIELDS = []
    
    #Fields
    email = models.EmailField(verbose_name='email address', unique=True)
    user_name = models.CharField(verbose_name='user name', max_length=150, blank=True)
    first_name = models.CharField(verbose_name='first name', max_length=150, blank=True)
    last_name = models.CharField(verbose_name='last name', max_length=150, blank=True)
    
    # Django user model required fields
    is_staff = models.BooleanField(
        verbose_name='staff status',
        default=False,
        help_text='Designates whether the user can log into this admin site.',
    )
    is_active = models.BooleanField(
        verbose_name='active',
        default=True,
        help_text='Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.',
    )
    date_joined = models.DateTimeField('date joined', default=timezone.now)

    # Custom fields for our wallet system
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    kyc_verified = models.BooleanField(default=False)
    kyc_document = models.FileField(upload_to='kyc_documents/', null=True, blank=True)
    
    # Transfer pin
    transfer_pin = models.IntegerField(null=True, blank=True)
    panic_transfer_pin = models.IntegerField(null=True, blank=True)
    
    # Add all profile fields directly to User
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    government_id = models.CharField(max_length=50, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Soft Delete
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    


    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, to_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [to_email], **kwargs)
        
    def soft_delete(self):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()

    def is_marked_for_deletion(self):
        return self.is_deleted and self.deleted_at is not None
        
    def __str__(self):
        return f"Profile of {self.email}"
        







#Let's create the remaining models for our system: (Create Profile, Bank, Wallet, and Transaction Models)
# myapp/models.py (continued)

class BankDetail(models.Model):
    """Bank account details for users"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bank_details',)
    bank_name = models.CharField(max_length=100)
    account_name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=50)
    bank_code = models.CharField(max_length=50, blank=True, null=True)
    recipient_code = models.CharField(max_length=50, blank=True, null=True)
    nuban = models.CharField(max_length=50, blank=True, null=True)
    is_primary = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"{self.bank_name} - {self.account_number} ({self.user.email})"
    
    class Meta:
        #unique_together = ('user', 'account_number', 'account_name', 'bank_name', 'nuban')
        models.UniqueConstraint(
            fields=['user', 'account_number', 'account_name', 'bank_name', 'nuban'],
            name='unique_bank_detail_per_user'
        )
        ordering = ['-created_at'] 





class Wallet(models.Model):
    """Digital wallet for users to hold funds"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=3, default='NGN')
    is_frozen = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #ADDED THIS TO SEE WHAT'S UP
    class Meta:
        models.UniqueConstraint(
            fields=['user', 'balance', 'currency', 'is_frozen', 'created_at'],
            name='unique_one_and_only_wallet_for_user'
        )
        ordering = ['-created_at'] 
    
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"Wallet of {self.user.email} - Balance: {self.balance}{self.currency} - IS_FROZEN {self.is_frozen}"
    
    
    
    
    #BANK to WALLET Deposit (MONEY GOTTEN FROM PAYSTACK PAYMENT POPUP)
    def deposit(self, amount: int):
        """Deposit money from bank into the wallet"""
        if amount <= 0:
            raise ValidationError("Deposit amount must be positive")
        # Add balance and log transaction
        self.balance += amount
            
    
    
    #FETCH TRANSFER RECIPIENT OF BANK DETAIL BY PAYSTACK
    def fetch_transfer_recipient(
        self,
        bank_code: str,  #more like declaring data type of an argument in dart (required String bla)
        account_number: str,
        account_name: str,
    ) -> dict:
        
        #If you want runtime validation (like Dart’s strict typing)
        #You’d need to manually check types inside the function, for example:
        
        if not all(isinstance(arg, str) for arg in [bank_code, account_number, account_name]):
           raise TypeError({"message":"All arguments must be strings"})
       
        """Fetch transfer recipient from a bank detail"""
        with transaction.atomic():
            # Call Paystack Bank Withdrawal API to withdraw from user bank
            url = "https://api.paystack.co/transferrecipient"
            headers = {
                "Authorization": f"Bearer {settings.PAYSTACK_TEST_SECRET_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
               "name": account_name,
               "account_number": account_number,
               "bank_code": bank_code,
               "currency": "NGN",
               "type": "nuban",
            }
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") is True: 
                    print(data["data"])
                    return data["data"]
                else:
                    raise Exception({"error": f"Paystack error: {data.get('message')}"})
            else:
                raise Exception({"error": f"Failed to connect to Paystack: {response.text}"})
    
    
    def finalize_transfer(
        self, 
        code: str, 
        otp: str, 
    ) -> dict:
        """Deduct money from the merchant wallet and credit actual bank account of the customer"""
        if code is None:
            raise ValidationError({"error": "Transfer code can't be empty"})
        elif otp is None:
            raise ValidationError({"error": "Transfer otp or status can't be empty"})
        else:
            with transaction.atomic():
                # Call Paystack Bank Withdrawal API to withdraw from user bank
                url = "https://api.paystack.co/transfer/finalize_transfer"
                headers = {
                    "Authorization": f"Bearer {settings.PAYSTACK_TEST_SECRET_KEY}",
                    "Content-Type": "application/json"
                }
                payload = { 
                   "transfer_code": code, 
                   "status": otp
                }
                response = requests.post(url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") is True:
                        print(data)
                        return data
                    else:
                        raise Exception({"error": f"Paystack error: {data.get('message')}"})
                else:
                    raise Exception({"error": f"Failed to connect to Paystack: {response.text}"})
    
    
    #WALLET to BANK TRANSFER
    def bank_transfer(
        self, 
        amount: int, 
        recipient_code: str, 
        transfer_pin: int, 
        reason: str
    )-> dict:
        """Deduct money from the wallet and credit actual bank account"""
        if amount <= 0:
            raise ValidationError({"error": "Deposit amount must be positive or greater than 0"})
        elif transfer_pin is None:
            raise ValidationError({"error": "Transfer PIN required"})
        elif transfer_pin != self.user.transfer_pin:
            raise ValidationError({"error": "Transfer PIN is invalid"})
        elif transfer_pin == self.user.transfer_pin:
            with transaction.atomic():
                # Call Paystack Bank Withdrawal API to withdraw from user bank
                url = "https://api.paystack.co/transfer"
                headers = {
                    "Authorization": f"Bearer {settings.PAYSTACK_TEST_SECRET_KEY}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "source": "balance",
                    "amount": int(amount * 100),  # Paystack expects amount in kobo
                    "recipient": recipient_code,
                    "reason": reason,
                }
                response = requests.post(url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") is True:
                        
                        #call the finalize transfer api
                        self.finalize_transfer(
                            code=data['transfer_code'],
                            otp=data['status']
                        )
                        
                        
                        # Deduct balance and log transaction
                        self.balance -= amount
                        self.save()
                        
                        #date time of the trx
                        trx_ref = f"GO-LEVI-{timezone.now()}-{random.randint(1000, 9999)}"
                        # Record transactions for sender
                        Transaction.objects.create(
                            user=self.user,
                            transaction_id=trx_ref,
                            transaction_type="WITHDRAWAL",
                            amount=amount,
                            currency=self.currency,
                            status="COMPLETED",
                            description=reason,
                            recipient=self.user
                        )
                        
                        # Send emails (can be pushed to a background task)
                        subject = "Transaction Notification"
                        self.user.email_user(
                            subject=subject,
                            message=f"You've successfully withdrawn ₦{amount} from you wallet.",
                            from_email='noreply@go-levi.com',
                            to_email=self.user.email
                        )
                        print(data)
                        return data
                    else:
                        raise Exception({"error": f"Paystack error: {data.get('message')}"})
                else:
                    raise Exception({"error": f"Failed to connect to Paystack: {response.text}"})
    
    
            
    #WALLET to WALLET TRANSFER
    def transfer(self, amount: int, recipient_user_id: str, transfer_pin: str, description: str):
        """Transfer money to another user's wallet using their user ID"""

        from .models import Wallet, Transaction


        User = get_user_model()

        if amount <= 0:
            raise ValidationError({"error": "Transfer amount must be positive"})

        elif self.balance < amount:
            raise ValidationError({"error": "Insufficient funds"})

        elif self.user.pk == recipient_user_id:
            raise ValidationError({"error": "You cannot transfer money to yourself"})

        elif transfer_pin is None:
            raise ValidationError({"error": "Transfer PIN is required"})

        try: 
            with transaction.atomic():
                recipient_user = User.objects.select_for_update().get(id=recipient_user_id)

                recipient_wallet, _ = Wallet.objects.select_for_update().get_or_create(
                    user=recipient_user,
                    defaults={'balance': 0.0, 'currency': self.currency}
                )

                if transfer_pin == self.user.panic_transfer_pin:
                    recipient_wallet.is_frozen = True
                    recipient_wallet.save()
                    #CREATE NOTIFICATION AFTER SUCCESSFUL TRANSACTION REPORT
                    Notification.objects.create(
                      user=self.user,
                      title=f"Transaction Reported",
                      content=f"we have marked the transaction with the receipient - f'Name: {recipient_user.get_full_name()}\nEmail: {recipient_user.email}' for immediate investigation and a follow up email will be sent to you.",
                      type="alert"  #alert, normal, promotion
                    )
                
                if transfer_pin == self.user.transfer_pin or transfer_pin == self.user.panic_transfer_pin:

                    # Adjust balances
                    self.balance -= amount
                    recipient_wallet.balance += amount
                    self.save()
                    recipient_wallet.save()
                    
                    #date time of the trx
                    trx_ref = f"GO-LEVI-{timezone.now()}-{random.randint(1000, 9999)}"

                    # Record transactions for sender
                    Transaction.objects.create(
                        user=self.user,
                        transaction_id=trx_ref,
                        transaction_type="WITHDRAWAL",
                        amount=amount,
                        currency=self.currency,
                        status="COMPLETED",
                        description=description,
                        recipient=recipient_user
                    )
            
                    # Record transactions for receipient
                    Transaction.objects.create(
                       user=recipient_user,
                       transaction_id=trx_ref,
                       transaction_type="TRANSFER",
                       amount=amount,
                       currency=self.currency,
                       status="COMPLETED",
                       description=description,  #f"Received ₦{amount} from {self.user.get_full_name()}.",
                       recipient=recipient_user
                    )

                    # Send emails (can be pushed to a background task)
                    subject = "Transaction Notification"
                    self.user.email_user(
                       subject=subject,
                       message=f"You've successfully sent ₦{amount} to {recipient_user.get_full_name()}.",
                       from_email='noreply@go-levi.com',
                       to_email=self.user.email
                    )
                    recipient_user.email_user(
                       subject=subject,
                       message=f"{self.user.get_full_name()} just sent you ₦{amount}.",
                       from_email='noreply@go-levi.com',
                       to_email=recipient_user.email
                    )

        except User.DoesNotExist:
            raise ValidationError({"error": "Recipient user does not exist"})

        
                
                

class Transaction(models.Model):
    """Record of financial transactions"""
    TRANSACTION_TYPES = (
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('TRANSFER', 'Transfer'),
        ('REFUND', 'Refund'),
    )
    
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        #('FROZEN', 'Frozen'),
        ('REVERSED', 'Reversed'),
    )
    
    transaction_id = models.CharField(max_length=50, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')
    # For transfers
    recipient = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='received_transactions')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='NGN')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=150, blank=True, null=True)
    
    # For withdrawals
    bank_detail = models.ForeignKey(BankDetail, on_delete=models.SET_NULL, null=True, blank=True)
    
    is_reported = models.BooleanField(default=False)
    report_reason = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.transaction_id} - {self.transaction_type} - {self.amount}{self.currency}"
    
    def freeze(self, reason: str):
        """Freeze a transaction due to a report"""
        self.status = 'FROZEN'
        self.is_reported = True
        self.report_reason = reason
        self.save()
    
    def complete(self):
        """Mark a transaction as completed"""
        self.status = 'COMPLETED'
        self.save()
    
    def fail(self, reason=None):
        """Mark a transaction as failed"""
        self.status = 'FAILED'
        if reason:
            self.description = reason
        self.save()
    
    class Meta:
        #field = ('user', 'transaction_id', 'transaction_type', 'currency', 'status', 'description')
        ordering = ['-created_at'] 


#NOTIFICATIONS MODEL
class Notification(models.Model):
    """Notifications for users for users"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user')
    title = models.CharField(max_length=150)
    type = models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"{self.title} - {self.content} - {self.type} ({self.user})"
    
    class Meta:
        #unique_together = ('user', 'title', 'type', 'content',)
        #field=['user', 'title', 'type', 'content',]
        models.UniqueConstraint(
            fields=['user', 'title', 'type', 'content',],
            name='unique_notification_per_user'
        )
        ordering = ['-created_at'] 
        
        
#MESSAGES MODEL
class Message(models.Model):
    """Messages for users"""

    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_msgs", )
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_msgs",)
    type = models.CharField(max_length=100)
    content = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"{self.content} - {self.type} ({self.created_at})"
    
    class Meta:
        ordering = ['created_at'] 
        
        
#