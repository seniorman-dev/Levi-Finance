
import random

from django.core.cache import cache
from django.utils import timezone

from rest_framework import status, generics, permissions
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, BlacklistedToken
from rest_framework.response import Response
from rest_framework.request import Request
#from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser

#from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth import logout, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.core.cache import cache

from .tasks import delete_user_in_5_days

from .models import Notification, User, BankDetail, Wallet, Transaction

from .serializers import (
    NotificationSerializer, UserRegistrationSerializer, UserLoginSerializer, BasicUserSerializer, KycUpdateSerializer, ProfileUpdateSerializer,
    BankDetailSerializer, WalletSerializer, TransactionSerializer,
    TransferPinSerializer, PanicPinSerializer,  RecipientCodeSerializer, DepositSerializer, TransferSerializer, BankTransferSerializer, ReportTransactionSerializer,
    EmailSerializer
)

# Create your views here.
# myapp/views.py






class UserRegistrationView(generics.GenericAPIView):
    """
    View to handle user registration.
    """
    permission_classes = [permissions.AllowAny]
    
    
    def post(self, request: Request) -> Response:
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            # Save the user from the serializer
            user = serializer.save()
            # Create wallet for the user
            Wallet.objects.create(user=user, balance=0.00, currency='NGN')
            # ✅ Generate JWT token pair
            refresh = RefreshToken.for_user(user=user)
            
            return Response({
                "refresh": str(refresh),  #remove token
                "access": str(refresh.access_token),
                "message": "User registered successfully"
            }, status=status.HTTP_201_CREATED)

        # Debugging block (optional)
        print("Registration failed with errors:", serializer.errors)

        return Response({
           "message": "Registration failed",
           "errors": serializer.errors
           }, 
           status=status.HTTP_400_BAD_REQUEST
        )
    
    
    

class UserLoginView(generics.GenericAPIView):
    """View for user login"""
    permission_classes = [permissions.AllowAny]
    serializer_class = UserLoginSerializer
    

        
    
    def post(self, request: Request) -> Response:
        serializer = UserLoginSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
           user = serializer.validated_data   # ✅ use this, not self.get_object()
           refresh = RefreshToken.for_user(user)

           return Response({
               "refresh": str(refresh),
               "access": str(refresh.access_token),
               "message": "User logged in successfully"
           }, status=status.HTTP_200_OK)

        return Response(
           {
            "message": "Login failed",
            "errors": serializer.errors,
        },
        status=status.HTTP_400_BAD_REQUEST,
        )





class UserLogoutView(generics.GenericAPIView):
    """View for user logout"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request):
        """Handle user logout"""
        # Delete the token
        request.auth.delete()
        
        # Django session logout (if using session authentication)
        logout(request)
        
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)


User = get_user_model()

class SoftDeleteUserView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def perform_destroy(self, instance):
        
        #user = self.get_object()
        # 1. Soft delete
        instance.is_deleted = True
        instance.deleted_at = timezone.now()
        instance.save()

        # 2. Invalidate all tokens (SimpleJWT-based)
        try:
            tokens = OutstandingToken.objects.filter(user=instance)  #instance
            for token in tokens:
                BlacklistedToken.objects.get_or_create(token=token)
        except:
            pass  # silently fail if not using token blacklisting

        # 3. Optionally, also log them out by deleting session
        if hasattr(instance, 'auth_token'):
            instance.auth_token.delete()

        # (Optional) 4. Send a Celery task or log a cron timestamp for hard-deletion
        #delete_user_in_5_days.delay(user_id=instance.id)
        # Schedule Celery task to run in 5 days 
        delete_user_in_5_days.apply_async((instance.id,), countdown=5*24*60*60)

    def delete(self, request: Request, *args, **kwargs):
        user = self.get_object()
        self.perform_destroy(instance=user)
        return Response({
            "message": "Account marked for deletion. Your data will be removed in 5 days."},
            status=status.HTTP_204_NO_CONTENT
        )



class PasswordResetView(generics.GenericAPIView):

    """View for sending OTP to user's email"""
    permission_classes = [permissions.AllowAny]
    

    def post(self, request: Request) -> Response:
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

        # Generate a random 4-digit OTP
        otp = str(random.randint(1000, 9999))

        # Cache it with a timeout of 3 minutes (180  seconds)
        cache.set(f'password_reset_otp_{email}', otp, timeout=180)
        
        # Log the otp
        print(f"your otp is: {otp}")

        # Send OTP to user's email
        send_mail(
            'Your Password Reset OTP',
            f'Your OTP for password reset is: {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            settings.EMAIL_HOST_USER,
            settings.EMAIL_HOST_PASSWORD,
            False,
        )

        return Response({'message': 'OTP has been sent to your email'}, status=status.HTTP_200_OK)





class ConfirmPasswordView(generics.GenericAPIView):
    """View for verifying OTP and setting new password"""
    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not all([email, otp, new_password]):
            return Response({'error': 'Email, OTP, and new password are required'}, status=status.HTTP_400_BAD_REQUEST)

        cached_otp = cache.get(f'password_reset_otp_{email}')
        if not cached_otp:
            return Response({'error': 'OTP expired or not found'}, status=status.HTTP_400_BAD_REQUEST)

        if otp != cached_otp:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        # Delete OTP after successful reset
        cache.delete(f'password_reset_otp_{email}')

        return Response({'message': 'Password reset successful. You can now log in with your new password.'}, status=status.HTTP_200_OK)
    
   
    

class CurrentUserView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = BasicUserSerializer
    
    
    def get_object(self):
        user = self.request.user
        if not user or not user.is_authenticated:
           raise Response({"message":"Authentication required."})
        return user




class UpdateProfileView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileUpdateSerializer
    
    def get_object(self):
        return self.request.user



class UpdateKycView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = KycUpdateSerializer
    parser_classes = [MultiPartParser, FormParser]  # For file uploads
    
    def get_object(self):
        return self.request.user
    
    def perform_update(self, serializer):
        user = self.get_object()
        serializer.save(kyc_verified=False)
        
        #CREATE NOTIFICATION AFTER SUCCESSFUL KYC UPDATE
        Notification.objects.create(
            user=user,
            title=f"KYC Documents Submitted Successfully",
            content=f"verification has commenced and you will be updated in due time.",
            type="normal"  #alert, normal, promotion
        )
    
    '''def update(self, serializer):
        instance.kyc_verified = False  # Reset verification on update
        # Here you would typically add logic to send for verification
        return super().update(instance, validated_data)'''
        
    '''def perform_update(self, serializer):
        # Set kyc_verified to False whenever KYC docs are updated until Admin Verifies it
        instance = serializer.save(kyc_verified=False)
        # Here you would typically add logic to send for verification'''

 


class BankDetailListView(generics.ListCreateAPIView):
    """View for listing and creating bank details"""
    serializer_class = BankDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get bank details for the current user"""
        return BankDetail.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        """Create a new bank detail for the current user"""
        serializer.save(user=self.request.user)




class BankDetailDetailView(generics.RetrieveUpdateDestroyAPIView):
    """View for retrieving, updating and deleting bank details"""
    serializer_class = BankDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get bank details for the current user"""
        return BankDetail.objects.filter(user=self.request.user)
    
    #DRF handles all these internally though
    def perform_update(self, serializer):
        serializer.save()
    
    #DRF handles all these internally though
    def perform_destroy(self, instance):
        # Example: prevent deletion of a primary bank detail
        '''if instance.is_primary:
            raise Response(
                data={ 
                    "error": "Cannot delete your primary bank account."
                },
                status=status.HTTP_400_BAD_REQUEST
            )'''
        instance.delete()






class WalletView(generics.RetrieveDestroyAPIView):
    """View for wallet operations"""
    serializer_class = WalletSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        """Get or create wallet for the current user"""
        wallet, created = Wallet.objects.get_or_create(user=self.request.user)
        return wallet
    
    #DRF handles all these internally though
    def perform_destroy(self, instance):
        instance.delete()

    




class TransferPinView(generics.GenericAPIView):
    """View for setting/updating transfer pin"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """Set or update transfer pin"""
        serializer = TransferPinSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            user = request.user
            new_pin = serializer.validated_data['new_pin']
            
            # Update the transfer pin
            user.transfer_pin = new_pin
            user.save()
            
            return Response({'message': 'Transfer pin updated successfully'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class PanicPinView(generics.GenericAPIView):
    """View for setting/updating panic pin"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """Set or update panic pin"""
        serializer = PanicPinSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            user = request.user
            new_pin = serializer.validated_data['new_pin']
            
            # Update the panic pin
            user.panic_transfer_pin = new_pin
            user.save()
            
            return Response({'message': 'Panic pin updated successfully'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




#FETCH AND CREATE TRANSFER RECIPIENT VIEW
class RecipientView(generics.GenericAPIView):
    serializer_class = RecipientCodeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = RecipientCodeSerializer(data=request.data, context={'request': request}) #self.get_serializer(data=request.data, context={"request": request}) 
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response(result, status=status.HTTP_201_CREATED)



#DEPOSIT TO WALLET VIEW
class DepositView(generics.GenericAPIView):
    """View for depositing funds into wallet"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """Handle deposit request"""
        serializer = DepositSerializer(data=request.data)
        
        if serializer.is_valid():
            user = request.user
            amount = serializer.validated_data['amount']
            description = serializer.validated_data.get('description', '')
            
            # Get the user's wallet
            wallet = request.user.wallet
    
            #date time of the trx
            trx_ref = f"LEVI-{timezone.now()}-{random.randint(1000, 9999)}"

            # Create a transaction record  for sender
            transaction =  Transaction.objects.create(
                user=request.user,
                transaction_id=trx_ref,
                transaction_type="DEPOSIT",
                amount=amount,
                currency="NGN",
                status="COMPLETED",
                description=description,
                recipient=request.user,
            )
            
            # Send email to the user (configure google smtp password to activate)
            '''subject = "Transaction Notification"
            request.user.email_user(
                subject=subject,
                message=f"You've successfully deposited ₦{amount} in your wallet.",
                from_email='support@levifinance.com',
                to_email=user.email
            )'''
            
            # Deposit the amount
            wallet.deposit(amount)
            
            # Return the updated wallet and transaction info (More like JSON.Decode())
            wallet_serializer = WalletSerializer(wallet)
            transaction_serializer = TransactionSerializer(transaction)
            
            #CREATE NOTIFICATION AFTER SUCCESSFUL DEPOSIT
            Notification.objects.create(
              user=user,
              title=f"Transaction Succesful",
              content=f"NGN {amount} has been deposited into your wallet.",
              type="normal"  #alert, normal, promotion
            )
            
            return Response({
                'wallet': wallet_serializer.data,
                'transaction': transaction_serializer.data,
                'message': 'Deposit successful'
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



#WALLET TRANSFER VIEW
class TransferView(generics.GenericAPIView):
    serializer_class = TransferSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args, **kwargs) -> Response:
        user = request.user
        serializer = TransferSerializer(data=request.data, context={'request': request}) #self.get_serializer(data=request.data, context={"request": request}) 
        amount = serializer.validated_data['amount']
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        #CREATE NOTIFICATION AFTER SUCCESSFUL TRANSFER
        Notification.objects.create(
            user=user,
            title=f"Transaction Succesful",
            content=f"NGN {amount} has been deducted from your wallet.",
            type="normal"  #alert, normal, promotion
        )
        return Response(result, status=status.HTTP_201_CREATED)



#BANK TRANSFER VIEW
class BankTransferView(generics.GenericAPIView):
    serializer_class = BankTransferSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args, **kwargs) -> Response:
        user = request.user
        serializer = BankTransferSerializer(data=request.data, context={'request': request}) #self.get_serializer(data=request.data, context={"request": request}) 
        amount = serializer.validated_data['amount']
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        #CREATE NOTIFICATION AFTER SUCCESSFUL TRANSFER
        Notification.objects.create(
            user=user,
            title=f"Transaction Succesful",
            content=f"NGN {amount} has been deducted from your wallet.",
            type="normal"  #alert, normal, promotion
        )
        return Response(result, status=status.HTTP_201_CREATED)



#TRANSACTION LIST VIEW (USER)
class TransactionListView(generics.ListAPIView):
    """View for listing transactions"""
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get transactions for the current user"""
        return Transaction.objects.filter(user=self.request.user).order_by('-created_at')
    
    def get(self, request: Request, *args, **kwargs) -> Response:
        """Get one transaction object by id for the current user"""
        try:
            transaction_id = kwargs.get("id")  # assuming it's passed in the URL as /transactions/<id>/
            transaction = Transaction.objects.get(id=transaction_id, user=request.user)
            return transaction
        except Transaction.DoesNotExist:
            return Response({"error": "Transaction not found"}, status=status.HTTP_404_NOT_FOUND)
        




class ReportTransactionView(generics.GenericAPIView):
    """View for reporting a transaction"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request, transaction_id: str) -> Response:
        """Handle transaction report"""
        transaction = get_object_or_404(Transaction, transaction_id=transaction_id, user=request.user)
        
        serializer = ReportTransactionSerializer(data=request.data)
        
        if serializer.is_valid():
            user = request.user
            reason = serializer.validated_data['reason']
            # Freeze the transaction
            transaction.freeze(reason)
            
            #CREATE NOTIFICATION AFTER SUCCESSFUL TRANASACTION REPORT
            Notification.objects.create(
                user=user,
                title=f"Transaction Reported",
                content=f"we have marked the transaction with the corresponding ID - '{transaction_id}' for immediate investigation and a follow up email will be sent to you.",
                type="alert"  #alert, normal, promotion
            )
            
            return Response({
                'message': 'Transaction reported and frozen',
                'transaction': TransactionSerializer(transaction).data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class SendEmailView(generics.GenericAPIView):
    """View for sending emails to users"""
    permission_classes = [permissions.AllowAny]
    
    #to get user object if authenticated
    def get_object(self):
        return self.request.user
    
    def post(self, request: Request,) -> Response:
        """Send email to a user"""
        
        serializer = EmailSerializer(data=request.data)
        
        if serializer.is_valid(raise_exception=True):
            from_email = serializer.validated_data['from_email']
            to_email = serializer.validated_data['to_email']
            subject = serializer.validated_data['subject']
            message = serializer.validated_data['message']
            
            # Send the email
            send_mail(subject=subject, message=message, from_email=from_email, recipient_list=[to_email])
            
            return Response({'message': 'Email sent successfully'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    
#GET POST
class NotificationListCreateView(generics.ListCreateAPIView):
    """View for listing and creating notifications"""
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get all notification objects belonging to the current user"""
        return Notification.objects.filter(user=self.request.user)
    
    #DRF handles all these internally though
    def perform_create(self, serializer):
        """Create a new notification object for the current user"""
        serializer.save(user=self.request.user)


#UPDATE DELETE
class NotificationUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """View for retrieving, updating and deleting notification details"""
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get all notification objects belonging to the current user"""
        return Notification.objects.filter(user=self.request.user)
    
    #DRF handles all these internally though
    def perform_update(self, serializer):
        serializer.save()
    
    #DRF handles all these internally though
    def perform_destroy(self, instance):
        instance.delete()