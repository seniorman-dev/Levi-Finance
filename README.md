Go-Levi Backend 🚀

Pioneering Safer, Smarter Digital Transactions

Go-Levi is a FinTech backend infrastructure built with Django + Django REST Framework (DRF) & SQLite to power safer, seamless, and smarter digital transactions for everyday users.

This project focuses on secure wallet management, reliable user authentication, dynamic profile system and efficient transaction processing — all designed to ensure that financial interactions remain trustworthy and smooth.


✨ Features
🔑 Authentication & Security

   User Signup, Login, Logout

   Password Reset (Forgot/Reset password flows)

   JWT-based authentication

   Secure handling of sensitive user data

👤 User Profile Management

   Fetch and update user profile details:

   First name, Last name, Username

   Avatar

   KYC information

   Login password

   Soft Delete

🏦 Bank Details

   CRUD operations for bank account information:

   Create

   Fetch

   Update

   Delete

💳 Wallet / Account System

   Create wallet for each user

   Check wallet balance

   Set & update transaction PIN

   Set & update panic PIN (emergency fraud alert system)

💸 Transactions

   View transaction history

   Deposit funds into wallet

   Withdraw funds to registered bank details

   Transfer funds between users (via unique user ID)

   Report suspicious transactions (marks them as frozen)

📧 Email Notifications

   Transactional emails for account and wallet activities

   Password reset email support

🛠 Tech Stack

   Backend Framework: Django, Django REST Framework (DRF)

   Database: SQLite3 (default)

   Authentication: JWT (JSON Web Tokens)

   Other Tools: 
   Celery (for async tasks and cron jobs for soft delete functionality), 
   Redis (caching mechanism, message broker for soft delete functionality), 
   SMTP (Gmail smtp server for sending emails)


Link to PostMan Collection:

(https://luround-apis.postman.co/workspace/My-Workspace~103f3353-b5b2-4540-874f-a45aa7ae2ea4/collection/30693493-0d96869e-2f54-4bb8-87ff-8b67240cebfe?action=share&creator=30693493)
