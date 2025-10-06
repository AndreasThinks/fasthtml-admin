"""
Authentication module for the fasthtml_admin library.
"""

import secrets
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, Union, Dict, Any, Tuple, List
from fasthtml.common import database, RedirectResponse, Beforeware

from .utils import hash_password, verify_password, generate_token
from .validation import validation_manager

@dataclass
class ConfirmToken:
    """
    Token for email confirmation.
    This class is designed to work with FastHTML's database system.
    """
    token: str  # Primary key
    email: str
    expiry: datetime
    is_used: bool = False

@dataclass
class UserCredential:
    """
    Basic user credential class for authentication.
    This class is designed to work with FastHTML's database system.
    
    This class can be extended by creating a subclass with additional fields
    before passing it to the UserManager constructor.
    """
    email: str  # Primary key
    id: str
    pwd: str  # Hashed password
    created_at: datetime
    is_confirmed: bool = False
    is_admin: bool = False
    last_login: Optional[datetime] = None

def auth_before(req, sess, user_manager, login_url='/login', public_paths=None, 
               admin_manager=None, maintenance_url='/maintenance'):
    """
    Authentication Beforeware function for FastHTML.
    If maintenance mode is enabled, redirects non-admin users to maintenance page.
    Checks if user is authenticated and redirects to login page if not.
    
    Args:
        req: The request object
        sess: The session object
        user_manager: An instance of UserManager
        login_url: URL to redirect to if not authenticated
        public_paths: List of paths that don't require authentication
        admin_manager: Optional AdminManager instance to check for maintenance mode
        maintenance_url: URL to redirect to if in maintenance mode
        
    Returns:
        RedirectResponse if not authenticated or in maintenance mode, None otherwise
    """
    if public_paths is None:
        public_paths = ['/', '/login', '/register', '/confirm-email']
    
    # Always allow access to maintenance page and login page
    if maintenance_url and maintenance_url not in public_paths:
        public_paths.append(maintenance_url)
    if login_url and login_url not in public_paths:
        public_paths.append(login_url)
    
    path = req.url.path
    
    # Check for maintenance mode first (before authentication)
    if admin_manager and admin_manager.is_maintenance_mode():
        # Always allow access to maintenance page and login page
        if path == maintenance_url or path == login_url:
            pass
        # Check if user is authenticated and is an admin
        elif 'user_id' in sess:
            user_id = sess.get('user_id')
            # Find user to check if they're an admin
            users = user_manager.users
            is_admin = False
            
            if user_manager.is_db:
                # Using FastHTML database
                for user in users():
                    if user.id == user_id:
                        is_admin = user.is_admin
                        break
            else:
                # Using dictionary store
                for user in users.values():
                    if user["id"] == user_id:
                        is_admin = user.get("is_admin", False)
                        break
            
            # If admin, allow access and store auth info
            if is_admin:
                req.scope['auth'] = user_id
            else:
                # Non-admin user, redirect to maintenance page
                return RedirectResponse(maintenance_url, status_code=303)
        else:
            # Not logged in, redirect to maintenance page
            return RedirectResponse(maintenance_url, status_code=303)
    
    # Skip authentication for public routes
    if (path in public_paths
            or any(path.startswith(p) for p in public_paths if p.endswith('/') and p != '/')):
        return
    
    # Check if user is authenticated
    if 'user_id' not in sess:
        return RedirectResponse(login_url, status_code=303)
    
    # Store auth info in request scope for easy access
    user_id = sess.get('user_id')
    req.scope['auth'] = user_id


def get_current_user(sess, user_manager):
    """
    Get the current user from the session.
    
    Args:
        sess: The session object
        user_manager: An instance of UserManager
        
    Returns:
        The user object or None if not logged in
    """
    user_id = sess.get('user_id')
    if not user_id:
        return None
    
    # Find user by ID
    users = user_manager.users
    if user_manager.is_db:
        # Using FastHTML database
        for user in users():
            if user.id == user_id:
                return user
    else:
        # Using dictionary store
        for user in users.values():
            if user["id"] == user_id:
                return user
    return None


class UserManager:
    """
    Manages user authentication, registration, and related operations.
    """
    def __init__(self, db_or_store, user_class=UserCredential, table_name="user_credentials", validation_mgr=None):
        """
        Initialize the UserManager with either a FastHTML database or a dictionary store.
        
        Args:
            db_or_store: Either a FastHTML database instance or a dictionary for storing users
            user_class: The user class to use (default: UserCredential)
                        This can be a subclass of UserCredential with additional fields
            table_name: Name of the table to use if db_or_store is a FastHTML database
            validation_mgr: Optional ValidationManager instance for custom validation
        """
        self.is_db = hasattr(db_or_store, 'create')
        self.user_class = user_class
        
        if self.is_db:
            # Using FastHTML database
            self.db = db_or_store
            self.users = self.db.create(user_class, pk="email", name=table_name)
        else:
            # Using dictionary store
            self.users = db_or_store
            
        # Use provided validation manager or the global instance
        self.validation_manager = validation_mgr or validation_manager
    
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Validate email format.
        
        Args:
            email: The email to validate
            
        Returns:
            A tuple containing a boolean indicating if the email is valid and a message
        """
        return self.validation_manager.validate("email_format", email)
    
    def validate_password(self, password: str, min_score: int = 50) -> Tuple[bool, List[str]]:
        """
        Validate password strength.
        
        Args:
            password: The password to validate
            min_score: Minimum acceptable score (0-100)
            
        Returns:
            A tuple containing a boolean indicating if the password is strong enough and a list of issues
        """
        score, issues = self.validation_manager.validate("password_strength", password)
        return score >= min_score, issues
    
    def validate_passwords_match(self, password: str, confirm_password: str) -> Tuple[bool, str]:
        """
        Validate that passwords match.
        
        Args:
            password: The first password
            confirm_password: The second password to compare
            
        Returns:
            A tuple containing a boolean indicating if the passwords match and a message
        """
        return self.validation_manager.validate("passwords_match", password, confirm_password)
    
    def create_user(self, email, password, min_password_score=50, validate=True, **additional_fields):
        """
        Create a new user with the given email and password.
        
        Args:
            email: User's email address
            password: Plain text password to be hashed
            min_password_score: Minimum acceptable password score (0-100)
            validate: Whether to validate email and password
            **additional_fields: Additional fields to include in the user object
                                These must match fields defined in the user_class
            
        Returns:
            The created user object
            
        Raises:
            ValueError: If validation fails or a user with the given email already exists
        """
        # Validate email and password if validation is enabled
        if validate:
            # Validate email format
            is_valid_email, email_message = self.validate_email(email)
            if not is_valid_email:
                raise ValueError(email_message)
            
            # Validate password strength
            is_strong_password, password_issues = self.validate_password(password, min_password_score)
            if not is_strong_password:
                raise ValueError(f"Password is not strong enough: {', '.join(password_issues)}")
        
        # Check if user already exists
        try:
            if self.is_db:
                existing_user = self.users[email]
            else:
                existing_user = self.users.get(email)
            
            if existing_user:
                raise ValueError(f"User with email {email} already exists")
        except (KeyError, IndexError, Exception) as e:
            # User doesn't exist, continue with creation
            # NotFoundError is raised by FastHTML database when a record is not found
            if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
                raise  # Re-raise if it's not a NotFoundError
            pass
        
        # Create new user
        user_id = secrets.token_hex(16)
        hashed_pwd = hash_password(password)
        
        user_data = {
            "id": user_id,
            "email": email,
            "pwd": hashed_pwd,
            "created_at": datetime.now(),
            "is_confirmed": False,
            "is_admin": False,
            "last_login": None
        }
        
        # Add any additional fields
        user_data.update(additional_fields)
        
        if self.is_db:
            # Insert into FastHTML database
            user = self.users.insert(user_data)
        else:
            # Insert into dictionary store
            self.users[email] = user_data
            user = user_data
            
        return user
    
    def authenticate_user(self, email, password):
        """
        Authenticate a user with the given email and password.
        
        Args:
            email: User's email address
            password: Plain text password to verify
            
        Returns:
            The user object if authentication succeeds, None otherwise
        """
        try:
            if self.is_db:
                user = self.users[email]
            else:
                user = self.users.get(email)
                
            if not user:
                return None
                
            # Verify password
            if verify_password(password, user.pwd if self.is_db else user["pwd"]):
                # Update last login time
                if self.is_db:
                    user.last_login = datetime.now()
                    self.users.update(user)
                else:
                    user["last_login"] = datetime.now()
                return user
            
            return None
        except (KeyError, IndexError, Exception) as e:
            # NotFoundError is raised by FastHTML database when a record is not found
            if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
                raise  # Re-raise if it's not a NotFoundError or KeyError/IndexError
            return None
    
    def confirm_user(self, email):
        """
        Mark a user as confirmed.
        
        Args:
            email: User's email address
            
        Returns:
            True if the user was confirmed, False otherwise
        """
        try:
            if self.is_db:
                user = self.users[email]
                user.is_confirmed = True
                self.users.update(user)
            else:
                user = self.users.get(email)
                if user:
                    user["is_confirmed"] = True
            return True
        except (KeyError, IndexError, Exception) as e:
            # NotFoundError is raised by FastHTML database when a record is not found
            if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
                raise  # Re-raise if it's not a NotFoundError or KeyError/IndexError
            return False
    
    def generate_confirmation_token(self, email, token_store=None, expiry_days=7):
        """
        Generate a confirmation token for the given email.
        
        Args:
            email: User's email address
            token_store: Optional store for tokens (FastHTML database or dict)
            expiry_days: Number of days until the token expires
            
        Returns:
            The generated token
        """
        token = generate_token()
        
        if token_store:
            from datetime import timedelta
            expiry = datetime.now() + timedelta(days=expiry_days)
            
            token_data = {
                "token": token,
                "email": email,
                "expiry": expiry,
                "is_used": False
            }
            
            if hasattr(token_store, 'insert'):
                # FastHTML database
                token_store.insert(token_data)
            else:
                # Dictionary store
                token_store[token] = token_data
                
        return token
