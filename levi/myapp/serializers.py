#Now let's create serializers for our models to convert between Python objects and JSON: (Create Serializers)
# myapp/serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework.authtoken.models import Token
from .models import Notification, User, BankDetail, Wallet, Transaction







class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""

    class Meta:
        model = User
        fields = ("id", 'email', 'password', 'first_name', 'last_name', 'user_name')
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data: dict):
        """Create and return a new user with a hashed password"""
        first_name = validated_data['first_name']
        last_name = validated_data['last_name']
        email = validated_data['email']
         
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)  # 🔐 Hash the password
        
        #SORT GMAIL SMTP STUFF IN THE SETTINGS, then call this
        '''user.email_user(
            subject= "Welcome to Go-Levi!", 
            message= f"Hey {first_name} {last_name}!\nWe're delighted to have you onboard and we say cheers to seamless banking with us.", 
            from_email= "noreply@levifinance.com", 
            to_email= email
        )'''
        
        #CREATE NOTIFICATION OBJECT FOR THE USER
        Notification.objects.create(
            user=user,
            title=f"Welcome to Go-Levi {first_name}!",
            content=f"Gear up as we take you on a journey to seamless banking.",
            type="normal"  #alert, normal, promotion
        )
        
        #FINALLY SAVED THE USER OBJECT TO DATABASE (SQLite)
        user.save()
        return user
    
    
    





class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    
    def validate(self, data: dict):
        """Validate user credentials"""
        email = data.get('email',)
        password = data.get('password',)
        request = self.context.get('request')
        
        print(f"Authenticating user: {email}")
        
        if email is None or password is None:
            raise serializers.ValidationError({"error": 'Email and password are required'})
        
        user = authenticate(
            request=request,
            email=email,
            password=password
        )
        
        if user is None:
            raise serializers.ValidationError({"error": "Invalid login credentials."})

        if not user.is_active:
            raise serializers.ValidationError({"error": "This account is inactive."})
        # Update last login time
        update_last_login(None, user)
        return user
    




class BasicUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", 'email', 'first_name', 'last_name', 'user_name', 'avatar', 'is_active', 'date_joined', 'kyc_verified')




class KycUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('government_id', 'kyc_document')
        extra_kwargs = {
            'kyc_document': {'required': True},
            'government_id': {'required': True}
        }



class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'phone_number', 
                 'address', 'city', 'country', 'postal_code', 
                 'date_of_birth')


    

class BankDetailSerializer(serializers.ModelSerializer):
    """Serializer for bank details"""

    class Meta:
        model = BankDetail
        fields = (
            'id', 'bank_name', 'account_name', 'account_number', 
            'bank_code', 'recipient_code', 'nuban', 'is_primary', 'created_at'
        )
        read_only_fields = ('id',)

    def validate(self, data: dict):
        """Validate bank details"""
        user = self.context['request'].user

        # Check for duplicate bank detail
        bank_detail = BankDetail.objects.filter(
            user=user,
            account_number=data.get('account_number'),
            account_name=data.get('account_name'),
            bank_name=data.get('bank_name'),
            nuban=data.get('nuban')
        )
        
        if bank_detail.exists():
            raise serializers.ValidationError({ 
               "error": "This bank detail already exists for this user."
              },
              code=400
            )

        # Ensure only one primary account per user
        if data.get('is_primary', False):
            BankDetail.objects.filter(user=user, is_primary=True).update(is_primary=False)

        return data



class WalletSerializer(serializers.ModelSerializer):
    """Serializer for wallet"""
    class Meta:
        model = Wallet
        fields = ("id", 'balance', 'currency')
        read_only_fields = fields #('balance', 'currency')



class TransactionSerializer(serializers.ModelSerializer):
    """Serializer for transactions"""
    #recipient_email = serializers.EmailField(source='recipient.email', read_only=True)
    #bank_detail = BankDetailSerializer(read_only=True)
     
    class Meta:
        model = Transaction
        fields = ("id", 'transaction_id', 'transaction_type', 'amount', 'currency', 
                 'status', 'description', 'recipient', 'bank_detail', 
                 'created_at', 'is_reported', 'report_reason')
        read_only_fields = fields


class TransferPinSerializer(serializers.Serializer):
    """Serializer for updating transfer pin"""
    #current_password = serializers.CharField(write_only=True, required=True)
    new_pin = serializers.CharField(max_length=6, min_length=4, write_only=True, required=True)
    
    def validate_current_pin(self, value):
        """Validate the transfer pin"""
        user = self.context['request'].user
        if user.transfer_pin != value:
            raise serializers.ValidationError({"error": 'Incorrect current transfer pin'})
        return value



class PanicPinSerializer(serializers.Serializer):
    """Serializer for updating panic pin"""
    #current_pin = serializers.CharField(max_length=6, min_length=4, write_only=True, required=False)
    new_pin = serializers.CharField(max_length=6, min_length=4, write_only=True, required=True)
    
    def validate_current_pin(self, value):
        """Validate the current panic pin"""
        user = self.context['request'].user
        if user.panic_transfer_pin != value:
            raise serializers.ValidationError({"error": 'Incorrect current panic pin'})
        return value



#DEPOSIT FROM BANK TO WALLET
class DepositSerializer(serializers.ModelSerializer):
    """Serializer for deposit operations"""
    amount = serializers.DecimalField(max_digits=12, decimal_places=2,)
    description = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = Transaction
        fields = (
            "id", 
            'amount', 
            "transaction_id" 
            'transaction_type', 
            'amount', 
            'currency', 
            'status', 
            'description', 
            'recipient_',  
            'is_reported', 
            'report_reason'
            'created_at',
        )
    
    def validate_amount(self, value: int):
        """Validate the deposit amount"""
        if value <= 0:
            raise serializers.ValidationError({"error":'Amount must be greter than 0'})
        return value



#FETCH RECIPIENT CODE SERIALIZER
class RecipientCodeSerializer(serializers.Serializer):
    """Serializer for fetching transfer receipient code by Paystack"""
    bank_code = serializers.CharField(max_length=5, required=True,)
    account_number = serializers.CharField(max_length=10, write_only=True, required=True,)
    account_name = serializers.CharField(max_length=300, required=True)
    
    '''class Meta:
        model = Wallet
        fields = (
            'currency', 
            'balance', 
            'user', 
        )'''

    '''def validate(self, attrs):
        user = self.context['request'].user
        if not hasattr(user, 'wallet'):
            raise serializers.ValidationError({"error": "User does not have a wallet."})
        return attrs'''

    def save(self, **kwargs):
        user = self.context['request'].user
        wallet = user.wallet
        wallet.fetch_transfer_recipient(
            bank_code=self.validated_data['recipient_code'],
            account_number=self.validated_data['transfer_pin'],
            account_name=self.validated_data['transfer_pin'],
        )
        #return {"status": "success"}





#WALLET TO WALLET TRANSFER
class TransferSerializer(serializers.ModelSerializer):
    """Serializer for transfer operations"""
    amount = serializers.DecimalField(max_digits=12, decimal_places=2,)
    recipient_user_id = serializers.CharField(max_length=50, required=True,)
    transfer_pin = serializers.CharField(max_length=4,write_only=True, required=True,)
    description = serializers.CharField(allow_blank=True, required=False)
    
    class Meta:
        model = Transaction
        fields = (
            "id", 
            'amount', 
            "transaction_id" 
            'transaction_type', 
            'amount', 
            'currency', 
            'status', 
            'description', 
            'recipient_',  
            'is_reported', 
            'report_reason'
            'created_at',
        )

    def validate(self, data: dict):
        user = self.context['request'].user
        if not hasattr(user, 'wallet'):
            raise serializers.ValidationError({"error": "User does not have a wallet."})
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        wallet = user.wallet
        wallet.transfer(
            amount=self.validated_data['amount'],
            recipient_user_id=self.validated_data['recipient_user_id'],
            transfer_pin=self.validated_data['transfer_pin'],
            description=self.validated_data.get('description', "")
        )
        return {"status": "success"}
    



#WALLET TO BANK TRANSFER
class BankTransferSerializer(serializers.ModelSerializer):
    """Serializer for transfer operations"""
    amount = serializers.DecimalField(max_digits=12, decimal_places=2,)
    recipient_code = serializers.CharField(max_length=50, required=True,)
    transfer_pin = serializers.CharField(max_length=4,write_only=True, required=True,)
    reason = serializers.CharField(allow_blank=True, required=False)
    
    class Meta:
        model = Transaction
        fields = (
            "id", 
            'amount', 
            "transaction_id" 
            'transaction_type', 
            'amount', 
            'currency', 
            'status', 
            'description', 
            'recipient_',  
            'is_reported', 
            'report_reason'
            'created_at',
        )

    def validate(self, data: dict):
        user = self.context['request'].user
        if not hasattr(user, 'wallet'):
            raise serializers.ValidationError({"error": "User does not have a wallet."})
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        wallet = user.wallet
        wallet.bank_transfer(
            amount=self.validated_data['amount'],
            recipient_code=self.validated_data['recipient_code'],
            transfer_pin=self.validated_data['transfer_pin'],
            reason=self.validated_data.get('reason', "")
        )
        return {"status": "success"}



class ReportTransactionSerializer(serializers.Serializer):
    """Serializer for reporting a transaction"""
    reason = serializers.CharField()
    
    def validate_reason(self, value: str) -> str:
        """Validate the report reason"""
        if not value.strip():
            raise serializers.ValidationError({"error": 'Reason cannot be empty'})
        return value


#FOR SENDING EMAILS
class EmailSerializer(serializers.Serializer):
    """Serializer for sending emails"""
    from_email = serializers.EmailField()
    to_email = serializers.EmailField()
    subject = serializers.CharField()
    message = serializers.CharField()
    
    '''def validate_to_email(self, value: str) -> str:
        """Ensure the receiver email is valid"""
        if value == self.initial_data.get("from_email"):
            raise serializers.ValidationError("Sender and receiver email cannot be the same.")
        return value'''
    
    def validate_subject(self, value: str) -> str:
        """Validate the email subject"""
        if not value.strip():
            raise serializers.ValidationError({"error": 'Subject cannot be empty'})
        return value
    
    def validate_message(self, value: str) -> str:
        """Validate the email message"""
        if not value.strip():
            raise serializers.ValidationError({"error": 'Message cannot be empty'})
        return value
    
    

#FOR NOTIFICATION  
class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notifications"""

    class Meta:
        model = Notification
        fields = (
            'id', 'title', 'content', 'type', 
            'created_at', 'updated_at',
        )
        read_only_fields = ('id',)

    def validate(self, data: dict):
        """Validate notification details"""
        user = self.context['request'].user

        # Check for duplicate bank detail
        notification_detail = Notification.objects.filter(
            user=user,
            title=data.get('title'),
            content=data.get('content'),
            type=data.get('type'),
        )
        
        if notification_detail.exists():
            raise serializers.ValidationError({ 
               "error": "This notification object already exists for this user."
              },
              code=400
            )

        return data