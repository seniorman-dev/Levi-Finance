"""
URL configuration for levi project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
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

# myapp/urls.py
from django.urls import path
from rest_framework.authtoken import views as jay
from myapp import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)








urlpatterns = [
    
    # Token authentication (for DRF browsable API)
    path('api/token-auth/', jay.obtain_auth_token),
    
    # for obtaining jwt (for DRF jwt )
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  #GET
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  #GET
    
    # Authentication
    path('api/auth/register/', views.UserRegistrationView.as_view(), name='register'),
    path('api/auth/login/', views.UserLoginView.as_view(), name='login'),
    path('api/auth/logout/', views.UserLogoutView.as_view(), name='logout'),
    path('api/auth/password-reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('api/auth/password-reset/confirm/', views.ConfirmPasswordView.as_view(), name='confirm-password-reset'),
    path('api/auth/users/delete/', views.SoftDeleteUserView.as_view(), name='soft-delete-user'),
    
    # User Profile
    path('api/user/', views.CurrentUserView.as_view(), name='current-user'),  #fetch current user
    path('api/profile/update/', views.UpdateProfileView.as_view(), name='update-profile-details'), #PATCH
    path('api/kyc/update/', views.UpdateKycView.as_view(), name='update-kyc'), #PATCH
    
    # Bank Details
    path('api/bank-details/', views.BankDetailListView.as_view(), name='bank-detail-list'), #GET #POST
    path('api/bank-details/<int:pk>/', views.BankDetailDetailView.as_view(), name='bank-detail-detail'), #GET BY ID, #PATCH #DELETE
    
    # Wallet
    path('api/wallet/', views.WalletView.as_view(), name='wallet'), #GET
    
    # Transfer Pins
    path('api/wallet/transfer-pin/', views.TransferPinView.as_view(), name='transfer-pin'),
    path('api/wallet/panic-pin/', views.PanicPinView.as_view(), name='panic-pin'),
    # Transactions
    path('api/wallet/fetch-transfer-recipient/', views.RecipientView.as_view(), name='fetch-bank-transfer-recipient'),
    path('api/wallet/deposit/', views.DepositView.as_view(), name='wallet-deposit'),
    path('api/wallet/transfer/', views.TransferView.as_view(), name='wallet-transfer'),
    path('api/wallet/bank-transfer/', views.BankTransferView.as_view(), name='bank-transfer'),
    path('api/transactions/', views.TransactionListView.as_view(), name='transaction-list'),
    path('api/transactions/<int:pk>/', views.TransactionListView.as_view(), name='transaction-object'),
    path('api/transactions/<str:transaction_id>/report/', views.ReportTransactionView.as_view(), name='report-transaction'),

    # Email
    path('api/send-email/<int:user_id>/', views.SendEmailView.as_view(), name='send-email'),
    
    # User Notifications
    path('api/notifications/', views.NotificationListCreateView.as_view(), name='notifications-list-create'), #GET #POST
    path('api/notifications/<int:pk>/', views.NotificationUpdateDestroyView.as_view(), name='notifications-update-delete') #PUT #PATCH #DELETE
    
    
    
]