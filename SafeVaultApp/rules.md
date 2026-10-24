SafeVault needs robust access control mechanisms to prevent unauthorized access to sensitive data. The system should:

Verify user credentials during login (authentication).

Restrict access to certain features, such as administrative tools, based on user roles (authorization).

Write code for user login functionality, including verifying usernames and passwords.

Hash passwords securely using a library like bcrypt or Argon2.

Example: Implement a function to authenticate users by comparing hashed passwords.

Assigns roles to users (e.g., admin, user).

Restricts access to specific routes or features based on roles.

Example: Protect the Admin Dashboard so only users with the admin role can access it.

Write test cases to simulate scenarios like invalid login attempts and unauthorized access.

Test access control for users with different roles.

Tests verifying proper access control for different user roles.

Prevent SQL Injection

Prevent XSS Attacks